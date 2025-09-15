# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from functools import total_ordering
from re import fullmatch
from typing import Any, Callable, Optional, Sequence

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from univers import nuget
from univers.version_range import VersionRange

from cdxev.auxiliary.identity import ComponentIdentity, VulnerabilityIdentity
from cdxev.error import AppError
from cdxev.log import LogMessage

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


def make_bom_refs_unique(list_of_sboms: Sequence[dict]) -> None:
    assigned_bom_refs: dict[ComponentIdentity, str] = {}

    if list_of_sboms:
        retained_components = get_ref_components_mapping(
            list_of_sboms[0].get("components", [])
            + [list_of_sboms[0].get("metadata", {}).get("component", {})]
        )

        for k in range(1, len(list_of_sboms)):
            subsequent_sbom = list_of_sboms[k]
            new_components = get_ref_components_mapping(
                subsequent_sbom.get("components", [])
                + [subsequent_sbom.get("metadata", {}).get("component", {})]
            )

            for reference in new_components.keys():
                if (
                    reference
                    in retained_components.keys()  # reference exists in primary SBOM
                    and retained_components[reference]
                    != new_components[
                        reference
                    ]  # component is not identical to the one in primary SBOM
                    and new_components[reference] not in assigned_bom_refs.keys()
                    # the component did not receive a new bom-ref already
                ):
                    new_bom_ref = str(new_components[reference])
                    index = 1
                    while (
                        new_bom_ref in retained_components.keys()
                        or new_bom_ref in new_components.keys()
                    ):
                        new_bom_ref = str(new_components[reference]) + "-" + str(index)
                        index += 1

                    replace_bom_ref_in_sbom(subsequent_sbom, reference, new_bom_ref)
                    retained_components[new_bom_ref] = new_components[reference]

                    assigned_bom_refs[new_components[reference]] = new_bom_ref

                elif new_components[reference] in assigned_bom_refs.keys():

                    replace_bom_ref_in_sbom(
                        subsequent_sbom,
                        reference,
                        assigned_bom_refs[new_components[reference]],
                    )
                    retained_components[new_bom_ref] = new_components[reference]

                else:
                    retained_components[reference] = new_components[reference]


def unify_bom_refs(list_of_sboms: Sequence[dict]) -> None:
    """
    Function to unify the bom-refs of several SBOMs,
    so that identical components in the different SBOMs
    have the same reference.

    :param list_of_sboms: list of SBOM dictionaries.
    """
    for n in range(len(list_of_sboms)):
        primary_sbom = list_of_sboms[n]
        primary_components = extract_components(
            primary_sbom.get("components", [])
            + [primary_sbom.get("metadata", {}).get("component", {})]
        )
        for k in range(n + 1, len(list_of_sboms)):
            secondary_sbom = list_of_sboms[k]
            new_components = extract_components(
                secondary_sbom.get("components", [])
                + [secondary_sbom.get("metadata", {}).get("component", {})]
            )
            for new_component in new_components:
                for primary_component in primary_components:
                    if ComponentIdentity.create(
                        new_component, allow_unsafe=True
                    ) == ComponentIdentity.create(
                        primary_component, allow_unsafe=True
                    ) and new_component.get(
                        "bom-ref", ""
                    ) != primary_component.get(
                        "bom-ref", ""
                    ):
                        reference = new_component.get("bom-ref", "")
                        new_reference = primary_component.get("bom-ref", "")

                        replace_bom_ref_in_sbom(
                            secondary_sbom, reference, new_reference
                        )


def replace_ref_in_components(
    components: list[dict], reference: str, new_reference: str
) -> None:
    for component in components:
        if component.get("bom-ref", "") == reference:
            component["bom-ref"] = new_reference


def replace_ref_in_dependencies(
    dependencies: list[dict], reference: str, new_reference: str
) -> None:
    for dependency in dependencies:
        if dependency.get("ref", "") == reference:
            dependency["ref"] = new_reference
        else:  # component should not depend on itself
            dependson = dependency.get("dependsOn", [])
            if reference in dependson:
                new_dependson = [
                    new_reference if entry == reference else entry
                    for entry in dependson
                ]
                dependency["dependsOn"] = new_dependson


def replace_ref_in_compositions(
    compositions: list[dict], reference: str, new_reference: str
) -> None:
    for composition in compositions:
        assemblies = composition.get("assemblies", [])
        if reference in assemblies:
            new_assemblies = [
                new_reference if entry == reference else entry for entry in assemblies
            ]
            composition["assemblies"] = new_assemblies


def replace_ref_in_vulnerabilities(
    vulnerabilities: list[dict], reference: str, new_reference: str
) -> None:
    for vulnerability in vulnerabilities:
        for affected in vulnerability.get("affects", []):
            if affected.get("ref", "") == reference:
                affected["ref"] = new_reference


def get_ref_components_mapping(
    components_list: list[dict],
) -> dict[str, ComponentIdentity]:
    component_dict: dict[str, ComponentIdentity] = {}
    for component in components_list:
        if component != {}:
            ref = component.get("bom-ref", "")
            identity = ComponentIdentity.create(component, allow_unsafe=True)
            if not ref:
                component["bom-ref"] = str(identity)
            component_dict[ref] = identity
    return component_dict


def replace_bom_ref_in_sbom(sbom: dict, reference: str, new_reference: str) -> None:
    replace_ref_in_components(
        sbom.get("components", []) + [sbom.get("metadata", {}).get("component", {})],
        reference,
        new_reference,
    )
    replace_ref_in_dependencies(sbom.get("dependencies", []), reference, new_reference)
    replace_ref_in_compositions(sbom.get("compositions", []), reference, new_reference)
    replace_ref_in_vulnerabilities(
        sbom.get("vulnerabilities", []),
        reference,
        new_reference,
    )


def collect_affects_of_vulnerabilities(
    list_of_original_vulnerabilities: list[dict],
    identities: dict[str, VulnerabilityIdentity],
) -> dict[str, list[dict]]:
    collected_affects: dict[str, list[dict]] = {}
    if list_of_original_vulnerabilities:
        for n in range(len(list_of_original_vulnerabilities)):
            # use json string of vulnerability in case the vulnerability does not contain any id
            id = identities[
                json.dumps(list_of_original_vulnerabilities[n], sort_keys=True)
            ]
            affects = deepcopy(list_of_original_vulnerabilities[n].get("affects", []))
            if id.string() not in collected_affects.keys():
                for k in range(n + 1, len(list_of_original_vulnerabilities)):
                    new_id = identities[
                        json.dumps(list_of_original_vulnerabilities[k], sort_keys=True)
                    ]

                    if id == new_id:
                        affects += list_of_original_vulnerabilities[k].get(
                            "affects", []
                        )

                collected_affects[id.string()] = affects
    return collected_affects


def compare_version_range(first_range: str, second_range: str) -> bool:
    # TODO extend to compare <= >= when supported

    # first compare the strings themselves
    # if the version scheme is unknown, but
    # the strings are identical a comparison can still be performed
    if first_range == second_range:
        return True

    try:
        first_range_object = VersionRange.from_string(second_range)  # type:ignore
        second_range_object = VersionRange.from_string(first_range)  # type:ignore
    except ValueError:
        return False

    if first_range_object == second_range_object:
        return True

    return False


def version_is_in_version_range(version: str, version_range: str) -> bool:

    range_object = VersionRange.from_string(version_range)  # type:ignore
    version_class = range_object.version_class
    try:
        if version_class.is_valid(version):
            return version_class(version) in range_object
        else:
            return False
    except nuget.InvalidNuGetVersion:
        return False


def compare_affects_versions_object(
    first_affects_object: dict, second_affects_object: dict
) -> int:
    """
    Function to compare two affects version objects.
    If version and range are present and both are not none, version will be considered.

    return:
        -1 first_affects_versions_object <= second_affects_versions_object
        0 first_affects_versions_object != second_affects_versions_object
        1 first_affects_versions_object == second_affects_versions_object
        2 first_affects_versions_object >= second_affects_versions_object
        3 inconclusive
    """
    if (
        first_affects_object.get("version", None) is not None
        and second_affects_object.get("version", None) is not None
    ):
        if first_affects_object.get("version", None) == second_affects_object.get(
            "version", None
        ):
            return 1
        else:
            return 0

    if (
        first_affects_object.get("range", None) is not None
        and second_affects_object.get("version", None) is not None
    ):

        if version_is_in_version_range(
            second_affects_object.get("version", ""),
            first_affects_object.get("range", ""),
        ):
            return 2
        else:
            return 0

    if (
        first_affects_object.get("version", None) is not None
        and second_affects_object.get("range", None) is not None
    ):

        if version_is_in_version_range(
            first_affects_object.get("version", ""),
            second_affects_object.get("range", ""),
        ):
            return -1
        else:
            return 0

    if (
        first_affects_object.get("range", None) is not None
        and second_affects_object.get("range", None) is not None
    ):  # TODO extend to support >= and <= for version ranges when supported
        if compare_version_range(
            first_affects_object.get("range", "1"),
            second_affects_object.get("range", "2"),
        ):
            return 1
        # If the version ranges are not identical, no further conclusions can be drawn
        else:
            return 3

    return 0


def get_new_affects_versions(
    original_versions_list: list[dict],
    new_versions_list: list[dict],
    vuln_id: str,
    ref: str,
    keep_version_overlap: bool = False,
    different_analysis: bool = False,
) -> list[dict]:
    kept_versions: list[dict] = []
    for new_version in new_versions_list:
        is_in = False
        new_version_copy = deepcopy(new_version)
        for original_version in original_versions_list:
            result = compare_affects_versions_object(original_version, new_version)
            if result == -1 and not keep_version_overlap:
                new_range = (
                    new_version_copy.get("range", "")
                    + "|!="
                    + original_version.get("version", "")
                )
                new_version_copy["range"] = new_range

            if result == 3:
                logger.warning(
                    LogMessage(
                        "Potential duplicate retained",
                        (
                            f"Inconclusive version comparison, "
                            f"keeping entry ({ref}) version {new_version} "
                            f"in vulnerability {vuln_id}."
                        ),
                    )
                )
            if result in [1, 2]:
                is_in = True
                if different_analysis:
                    logger.warning(
                        LogMessage(
                            "Dropped duplicate with different analysis",
                            (
                                f"Dropped entry ({ref}) version {new_version} "
                                f"in vulnerability {vuln_id}."
                            ),
                        )
                    )
        if not is_in:
            kept_versions.append(new_version_copy)
    return kept_versions


def extract_new_affects(
    original_affects_list: list[dict],
    new_affects_list: list[dict],
    vuln_id: str,
    keep_version_overlap: bool = False,
    different_analysis: bool = False,
) -> list[dict]:
    kept_affects: list[dict] = []
    collected_original_affects = join_affect_versions_with_same_references(
        original_affects_list
    )

    for new_affect in new_affects_list:
        new_versions = new_affect.get("versions", [])
        ref_is_in = False
        if new_affect.get("ref", "new_ref") in collected_original_affects.keys():
            ref_is_in = True
            original_versions = collected_original_affects.get(
                new_affect.get("ref", "new_ref"), []
            )
            kept_affect_versions = get_new_affects_versions(
                original_versions,
                new_versions,
                vuln_id,
                new_affect.get("ref", ""),
                keep_version_overlap,
                different_analysis,
            )

            if kept_affect_versions:
                new_affect_copy = deepcopy(new_affect)
                new_affect_copy["versions"] = kept_affect_versions
                kept_affects.append(new_affect_copy)

        if not ref_is_in:
            kept_affects.append(new_affect)

    return kept_affects


def compare_vulnerability_ids(
    first_vulnerability: dict, second_vulnerability: dict
) -> int:
    ids_first_vulnerability = VulnerabilityIdentity.get_ids_from_vulnerability(
        first_vulnerability
    )
    ids_second_vulnerability = VulnerabilityIdentity.get_ids_from_vulnerability(
        second_vulnerability
    )

    is_equal = False
    for id in ids_first_vulnerability:
        if id in ids_second_vulnerability:
            is_equal = True

    return is_equal


def join_affect_versions_with_same_references(
    affects_list: list[dict],
) -> dict[str, list[dict]]:
    # join all versions with the same ref in one object
    collected_versions: dict[str, list[dict]] = {}
    if affects_list:
        for n in range(len(affects_list)):
            id = affects_list[n].get("ref", "")
            affects = deepcopy(affects_list[n].get("versions", []))
            if id not in collected_versions.keys():
                for k in range(n + 1, len(affects_list)):
                    if affects_list[k].get("ref", "") == id:
                        affects += affects_list[k].get("versions", [])
                collected_versions[id] = affects
    return collected_versions


def get_identities_for_vulnerabilities(
    list_of_vulnerabilities: list[dict],
) -> dict[str, VulnerabilityIdentity]:
    identities: dict[str, VulnerabilityIdentity] = {}
    for vulnerability in list_of_vulnerabilities:
        vulnerability_string = json.dumps(vulnerability, sort_keys=True)
        if vulnerability_string not in list(identities.keys()):
            aliases = VulnerabilityIdentity.get_ids_from_vulnerability(vulnerability)

            # check if identity was already created
            is_present = False
            temp_dictionary: dict[str, VulnerabilityIdentity] = {}
            for identity_object in identities.values():
                if identity_object.one_of_ids_is_in(aliases):
                    temp_dictionary[vulnerability_string] = identity_object
                    is_present = True
                    continue
            identities.update(temp_dictionary)

            # create a identity for the vulnerability
            if not is_present:
                len_aliases = len(aliases)
                new_len_aliases = 0
                while len_aliases != new_len_aliases:
                    len_aliases = len(aliases)
                    for vulnerability_object in list_of_vulnerabilities:
                        vulnerability_aliases = (
                            VulnerabilityIdentity.get_ids_from_vulnerability(
                                vulnerability_object
                            )
                        )

                        # check if one of the vulnerability identifiers
                        # is in the current vulnerability
                        is_present = False
                        for vuln_id in vulnerability_aliases:
                            if vuln_id in aliases:
                                is_present = True
                                # add new identifiers to the list
                                #  of the aliases of the vulnerability
                        if is_present:
                            for vuln_id in vulnerability_aliases:
                                if vuln_id not in aliases:
                                    aliases.append(vuln_id)

                    new_len_aliases = len(aliases)

                identities[vulnerability_string] = VulnerabilityIdentity(
                    aliases[0], aliases
                )

    return identities


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


def merge_affects_versions(
    original_affects: list[dict], new_affects: list[dict]
) -> None:
    for affect in new_affects:
        ref_is_in = False
        for original_affect in original_affects:
            if original_affect.get("ref", "") == affect.get("ref", "_"):
                ref_is_in = True
                original_affect_versions = original_affect.get("versions", [])
                for version in affect.get("versions", []):
                    original_affect_versions.append(version)
        if not ref_is_in:
            original_affects.append(affect)
