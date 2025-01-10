# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from dataclasses import dataclass
from enum import Enum
from functools import total_ordering
from re import fullmatch
from typing import Any, Callable, Optional, Sequence

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component


from cdxev.error import AppError

logger = logging.getLogger(__name__)


@dataclass(frozen=True, order=True)
class SpecVersion:
    """
    Object representation of a simple version string comprised of a major and minor version.

    Instances are immutable and totally orderable.
    """

    major: int
    minor: int

    @classmethod
    def parse(cls, s: str) -> Optional["SpecVersion"]:
        """
        Creates a `SpecVersion` from a string, e.g. a CycloneDX specVersion field.

        :param s: The string to parse.
        :return: The parsed `SpecVersion`.
        """
        match = fullmatch("([0-9]+)\\.([0-9]+)", s)
        if match is None:
            logger.warning(f'"{s}" is not a valid specVersion')
            return None

        (major, minor) = (int(x) for x in match.group(1, 2))
        return SpecVersion(major, minor)

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}"


@total_ordering
class CycloneDXVersion(Enum):
    """
    Enumeration of known CycloneDX spec versions.

    Enumeration members can be compared directly to `SpecVersion` instances.
    """

    V1_0 = SpecVersion(1, 0)
    V1_1 = SpecVersion(1, 1)
    V1_2 = SpecVersion(1, 2)
    V1_3 = SpecVersion(1, 3)
    V1_4 = SpecVersion(1, 4)
    V1_5 = SpecVersion(1, 5)
    V1_6 = SpecVersion(1, 6)

    def __eq__(self, value: object) -> bool:
        if isinstance(value, CycloneDXVersion):
            return super().__eq__(value)
        elif isinstance(value, SpecVersion):
            return self.value.__eq__(value)
        else:
            return NotImplemented

    def __lt__(self, value: object) -> bool:
        if isinstance(value, CycloneDXVersion):
            return self.value < value.value
        elif isinstance(value, SpecVersion):
            return self.value < value
        else:
            return NotImplemented


def compare_components(first_component: dict, second_component: dict) -> bool:
    """
    Function to compare two components based on the attributes
    purl
    cpe
    swid
    should none of those be contained in both sboms,
    name, version and if it exists,
    group will be used.
    If the checked attributes are identical,
    it will return true, else false

    Input:
    first_component: dict with components
    second_component: dict with components

    Output:
    is_equal: boolean
    """
    is_equal = False
    if first_component.get("purl", "") and second_component.get("purl", ""):
        if (
            first_component.get("purl", "1").lower()
            == second_component.get("purl", "2").lower()
        ):
            is_equal = True
        else:
            return False
    if first_component.get("cpe", "") and second_component.get("cpe", ""):
        if (
            first_component.get("cpe", "1").lower()
            == second_component.get("cpe", "2").lower()
        ):
            is_equal = True
        else:
            return False
    if first_component.get("swid", "") and second_component.get("swid", ""):
        if (
            first_component.get("swid", "1").lower()
            == second_component.get("swid", "2").lower()
        ):
            is_equal = True
        else:
            return False
    if (
        first_component.get("name", "notfound1").lower()
        == second_component.get("name", "notfound2").lower()
        and first_component.get("version", "notfound1").lower()
        == second_component.get("version", "notfound2").lower()
        and not is_equal
    ):
        is_equal = True
        if "group" in first_component.keys() or "group" in second_component.keys():
            if not (
                first_component.get("group", "").lower()
                == second_component.get("group", "not found").lower()
            ):  # use this instead of the first if?
                is_equal = False
    return is_equal


def get_component_by_ref(ref: str, list_of_components: Sequence[dict]) -> dict:
    """
    Function that returns a component from a list, based on the bom_ref

    Input:
    ref:                String, bom_ref of a component
    list_of_components: list with dicts of components

    Output:
    comp: component with the requested bom-ref
    """
    for component in list_of_components:
        if component.get("bom-ref", "bom-ref_notFound").lower() == ref.lower():
            return component
    return {}


def get_bom_refs_from_dependencies(dependencies: Sequence[dict]) -> list[str]:
    """
    Function that gets a list of dependencies and returns a list with their sboms

    Input:
    dependencies: List with dict of dependencies

    Output:
    bom_refs: List of Strings, containing the bom-refs of the dependencies
    """
    list_of_bom_refs = []
    for dependency in dependencies:
        list_of_bom_refs.append(dependency.get("ref", ""))
    return list_of_bom_refs


def get_ref_from_components(list_of_components: Sequence[dict]) -> list[str]:
    """
    Function that returns a list of bom-refs from a list of components.
    This also includes nested components.

    Input:
    list_of_components: list with dicts of components

    Output:
    list_of_bom_refs: List of bom-refs from the components in the submitted list
    """
    list_of_all_components = extract_components(list_of_components)
    list_of_bom_refs = []
    for component in list_of_all_components:
        bom_ref = component.get("bom-ref", "")
        list_of_bom_refs.append(bom_ref)
    return list_of_bom_refs


def extract_components(list_of_components: Sequence[dict]) -> Sequence[dict]:
    extracted_components = []
    for component in list_of_components:
        if component.get("components", []) == []:
            extracted_components.append(component)
        else:
            extracted_components.append(component)
            extracted_components += extract_components(component.get("components", []))
    return extracted_components


def get_dependency_by_ref(reference: str, list_of_dependencies: Sequence[dict]) -> dict:
    """
    Function that gets a bom-ref and a list of dependencies and returns the dependency with the to
    ref corresponding reference

    Input:
    ref: String, a bom-ref
        list_of_dependencies: List, a list of dependencies

    Output:
    found_dependency: a dictionary from the dependencies with the submitted reference as ref
    """
    found_dependency: dict = {}
    for dependency in list_of_dependencies:
        if dependency.get("ref", "") == reference:
            found_dependency = dependency
    return found_dependency


def walk_components(
    sbom: dict,
    func: Callable[..., None],
    *args: Any,
    skip_meta: bool = False,
    **kwargs: Any,
) -> None:
    """
    Invokes the given function once for each component in the SBOM.

    :param sbom: The SBOM.
    :param func: A callable to run once for each component in the SBOM. The component object will
                 be passed to this function as the first argument. *args* will be appended as
                 subsequent arguments.
    :param args: Further positional arguments will be passed to *func* after the component object.
    :param skip_meta: If *true*, does not invoke *func* on the metadata.component object.
    :param kwargs: Further keyword-arguments (except *skip_meta*) will be passed to *func* after
                   the component object.
    """

    def _recurse(
        components: list[dict], func: Callable[..., None], *args: Any, **kwargs: Any
    ) -> None:
        for component in components:
            func(component, *args, **kwargs)
            if "components" in component:
                _recurse(component["components"], func, *args)

    if not skip_meta:
        if component := sbom.get("metadata", {}).get("component", None):
            func(component, *args, **kwargs)

    if "components" not in sbom:
        return

    _recurse(sbom["components"], func, *args, **kwargs)


# Function for the usage of the python cyclonedx model


def deserialize(sbom: dict) -> Bom:
    if sbom.get("compositions", {}):
        sbom.pop(
            "compositions"
        )  # compositions need to be removed till the model supports those
    deserialized_bom = Bom.from_json(data=sbom)  # type:ignore[attr-defined]
    if isinstance(deserialized_bom, Bom):
        return deserialized_bom
    else:
        raise AppError(
            "Failed deserialization",
            ("Deserialization of the SBOM into the CycloneDX Python Library failed."),
        )


def extract_cyclonedx_components(
    list_of_components: Sequence[Component],
) -> Sequence[Component]:
    extracted_components = []
    for component in list_of_components:
        if component.components is None:
            extracted_components.append(component)
        else:
            extracted_components.append(component)
            extracted_components += extract_cyclonedx_components(component.components)
    return extracted_components
