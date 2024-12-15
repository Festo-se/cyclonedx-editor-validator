# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from dataclasses import dataclass
from enum import Enum
from functools import total_ordering
from re import fullmatch
from typing import Any, Callable, Literal, Optional, Sequence, Union

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from dateutil.parser import parse

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


def compare_vulnerabilities(
    first_vulnerability: dict, second_vulnerability: dict
) -> bool:
    """
    Function that compares two vulnerability dictionaries

    Parameters
    ----------
    :first_vulnerability : dict
        A vulnerability dictionary
    :second_vulnerability : dict
        A vulnerability dictionary

    Returns
    -------
    bool
        Boolean that describes if the given vulnerabilities are identical
    """
    # two vulnerabilities are defined as identical, iff their id is the same
    if first_vulnerability.get("id", 1) == second_vulnerability.get("id", 2):
        return True
    return False


def vulnerability_is_in(
    first_vulnerability: dict, list_of_vulnerabilities: Sequence[dict]
) -> bool:
    """
    Checks if a specific vulnerability is in a given list of vulnerabilities

    Parameters
    ----------
    first_vulnerability : dict
        A vulnerability dictionary
    list_of_vulnerabilities: Sequence[dict]
        A list of vulnerability dictionaries

    Returns
    -------
    bool
        Boolean that describes if the given vulnerability is in the list of vulnerabilities
    """
    for vulnerability in list_of_vulnerabilities:
        if compare_vulnerabilities(first_vulnerability, vulnerability):
            return True
    return False


def copy_ratings(ratings: Sequence[dict]) -> list[dict]:
    """
    Creates a Copy of a list of rating dictionaries

    Parameters
    ----------
    ratings: list
        A list of ratings from a vulnerability

    Returns
    -------
    list[dict]:
        Copy of ratings
    """
    new_ratings = []
    for rating in ratings:
        new_dictionary = {}
        for key in rating.keys():
            new_dictionary[key] = rating[key]
        new_ratings.append(new_dictionary)
    return new_ratings


def compare_time_flag_from_vulnerabilities(
    first_vulnerability: dict, second_vulnerability: dict
) -> Union[Literal[0], Literal[1], Literal[2]]:
    """
    Compares two vulnerabilities based on the last time
    they were updated. If the first vulnerability got
    published/updated more recently, a 2 is returned.
    If they contain the same date, a 0 is returned
    and if the second one is newer, a 1 ist returned.

    Parameter
    ----------
    first_vulnerability: dict
        A dict with content of one vulnerability

    second_vulnerability: dict
        A dict with content of one vulnerability

    Returns
    -------
    int:
        0 If the vulnerabilities are of the same date
        1 If the second vulnerability is newer
        2 If the first vulnerability is newer
    """
    first_timestr: Optional[str] = first_vulnerability.get(
        "updated", first_vulnerability.get("published", None)
    )
    second_timestr: Optional[str] = second_vulnerability.get(
        "updated", second_vulnerability.get("published", None)
    )

    if first_timestr is not None and second_timestr is not None:
        first_timestamp = parse(first_timestr)
        second_timestamp = parse(second_timestr)
        if first_timestamp < second_timestamp:
            return 2
        if first_timestamp == second_timestamp:
            return 0

        return 1
    else:
        return 0


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


def get_corresponding_reference_to_component(
    component: dict, list_of_components: list
) -> tuple[bool, str]:
    """
    Function that checks if a given component is contained
    in a list of components and returns the bom-ref from
    the corresponding component in the list.

    Parameters
    ----------
    component: dict
        A component dict
    list_of_components: str
        A list of component dicts

    Returns
    -------
    is_in_list: bool
        A boolean describing if the component is in the list
    bomref_from_list:
        The bom-ref from the corresponding component in the list
    """
    is_in_list = False
    bomref_from_list = ""
    for component_from_list in list_of_components:
        if compare_components(component, component_from_list):
            is_in_list = True
            bomref_from_list = component_from_list.get("bom-ref", "")
            break
    return is_in_list, bomref_from_list


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
