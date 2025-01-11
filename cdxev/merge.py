# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import logging
import typing as t
from dataclasses import dataclass

from univers.version_range import VersionRange
from univers.versions import nuget

from cdxev.auxiliary.identity import ComponentIdentity
from cdxev.auxiliary.sbomFunctions import (
    get_bom_refs_from_dependencies,
    get_dependency_by_ref,
    extract_components,
)
from cdxev.log import LogMessage

logger = logging.getLogger(__name__)


@dataclass(frozen=True, init=True)
class VulnerabilityIdentity:
    id: str
    aliases: list[str]

    @classmethod
    def from_vulnerability(cls, vulnerability: dict) -> "VulnerabilityIdentity":
        id = vulnerability.get("id", "")
        aliases = get_ids_from_vulnerability(vulnerability)
        return cls(id, aliases)

    @classmethod
    def from_string(cls, id: str) -> "VulnerabilityIdentity":
        aliases = id.split("_|_")
        return cls(aliases[0], aliases)

    def id_is_in(self, other_id: str) -> bool:
        if other_id == self.id:
            return True

        if other_id in self.aliases:
            return True
        else:
            return False

    def one_of_ids_is_in(self, other_ids: list[str]) -> bool:
        for id in other_ids:
            if id == self.id:
                return True
            if id in self.aliases:
                return True
        return False

    def __eq__(self, other: object) -> bool:
        """
        Compares two vulnerability objects based on the described vulnerability.
        Fields like affects or analysis are not taken into account.
        """
        if not isinstance(other, VulnerabilityIdentity):
            raise TypeError(f"Can not compare {type(other)} with VulnerabilityIdentity")
        return self.one_of_ids_is_in(other.aliases)

    def __str__(self) -> str:
        if id not in self.aliases:
            string = self.id
        for ref in self.aliases:
            if ref not in string:
                string += "_|_" + ref
        return string

    def string(self) -> str:
        return self.__str__()


def merge_components(governing_sbom: dict, sbom_to_be_merged: dict) -> t.List[dict]:
    """
    Function that gets two lists of components and merges them unique into one.

    Warning: before use, it must be ensured, that the bom-refs are unique and unified
            across al SBOMs

    The bom-refs of the sbom_to_be_merged will be replaced by the ones from the
    one it will be merged into (governing_sbom), if they contain the same component.
    If a component gets merged but its bom-ref is already contained in the
    governing_sbom, the bom-ref will be changed and replaced in the sbom_to_be_merged.

    Input:
    governing_sbom: The sbom of the governing program, in which the other will be merged
    sbom_to_be_merged: The sbom to be merged

    Output:
    list_of_merged_components: List with the uniquely merged components of the submitted sboms
    """
    list_of_merged_components: t.List[dict] = governing_sbom.get("components", [])
    list_of_added_components = sbom_to_be_merged.get("components", [])
    for component in list_of_added_components:
        is_in_list, _ = get_corresponding_reference_to_component(
            component, list_of_merged_components
        )
        if is_in_list:
            component_id = ComponentIdentity.create(component, allow_unsafe=True)
            logger.warning(
                LogMessage(
                    "Potential loss of information",
                    f"Dropping a duplicate component ({component_id}) from the merge result.",
                )
            )
        else:
            if not (component.get("bom-ref", 1) in list_of_merged_bom_refs):
                list_of_merged_components.append(component)
                list_of_merged_bom_refs.append(component.get("bom-ref"))
            else:
                # if the bom-ref already exists in the components, add a incrementing number to
                # the bom-ref
                list_of_bom_refs_to_be_added = get_ref_from_components(
                    sbom_to_be_merged.get("components", [])
                )
                list_of_bom_refs_to_be_added.append(
                    sbom_to_be_merged.get("metadata", {})
                    .get("component", {})
                    .get("bom-ref", "")
                )
                bom_ref_is_not_unique = False
                new_bom_ref = component.get("bom-ref")
                n = 0
                while new_bom_ref in list_of_merged_bom_refs or bom_ref_is_not_unique:
                    n += 1
                    new_bom_ref = component.get("bom-ref") + "_" + str(n)
                    # The new bom-ref must not appear in either of the sboms
                    if new_bom_ref in list_of_bom_refs_to_be_added:
                        bom_ref_is_not_unique = True
                    else:
                        bom_ref_is_not_unique = False
                replace_ref_in_sbom(
                    new_bom_ref, component.get("bom-ref", ""), sbom_to_be_merged
                )
                list_of_merged_components.append(component)
                list_of_merged_bom_refs.append(new_bom_ref)
    return list_of_merged_components  # type:ignore [no-any-return]


def merge_dependency(
    depedency_original: dict, dependency_new: dict
) -> dict[str, t.Any]:
    """
    Function that merges the dependsOn lists of two dependencies uniquely into one.

    Input:
    depedencyOld:  dict of dependencies before merge
    dependencyNew: dict of dependencies before merge

    return: dict
        dict of the merged dependencies
    """
    dependson_new = depedency_original.get("dependsOn", [])
    for refs in dependency_new.get("dependsOn", []):
        if not (refs in dependson_new):
            dependson_new.append(refs)
    merged_dependency = {
        "ref": depedency_original.get("ref", ""),
        "dependsOn": dependson_new,
    }
    return merged_dependency


def merge_dependency_lists(
    original_list_of_dependencies: t.Sequence[dict],
    new_list_of_dependencies: t.Sequence[dict],
) -> t.List:
    """
    Function that merges two lists with dependencies. If a dependency appears in both lists, the
    dependsOn entries will be compared and uniquely merged.

    Input:
    original_list_of_dependencies: List with dependencies
    new_list_of_dependencies:   List with dependencies

    Output:
    list_of_merged_dependencies: List with the merged dict of dependencies
    """

    list_of_original_references = get_bom_refs_from_dependencies(
        original_list_of_dependencies
    )
    list_of_new_references = get_bom_refs_from_dependencies(new_list_of_dependencies)
    list_of_merged_dependencies = []
    for reference in list_of_new_references:
        if reference in list_of_original_references:
            original_dependency = get_dependency_by_ref(
                reference, original_list_of_dependencies
            )
            new_dependency = get_dependency_by_ref(reference, new_list_of_dependencies)
            merged_dependency = merge_dependency(original_dependency, new_dependency)
            list_of_merged_dependencies.append(merged_dependency)
        else:
            new_dependency = get_dependency_by_ref(reference, new_list_of_dependencies)
            list_of_merged_dependencies.append(new_dependency)
    list_of_new_references = get_bom_refs_from_dependencies(list_of_merged_dependencies)
    for reference in list_of_original_references:
        if not (reference in list_of_new_references):
            original_dependency = get_dependency_by_ref(
                reference, original_list_of_dependencies
            )
            list_of_merged_dependencies.append(original_dependency)
    return list_of_merged_dependencies


def merge_2_sboms(
    original_sbom: dict,
    sbom_to_be_merged: dict,
    vulnerability_identities: dict[str, VulnerabilityIdentity] = {},
) -> dict:
    """
    Function that merges two sboms.

    Input
    original_sbom: sbom
    sbom_to_be_merged: sbom

    Output
        merged_sbom: sbom, with sbom_to_be_merged merged in original_sbom

    """

    make_bom_refs_unique([original_sbom, sbom_to_be_merged])
    unify_bom_refs([original_sbom, sbom_to_be_merged])

    if (
        vulnerability_identities == {}
        and original_sbom.get("vulnerabilities", []) != []
        and sbom_to_be_merged.get("vulnerabilities", []) != []
    ):

        vulnerability_identities = get_identities_for_vulnerabilities(
            original_sbom["vulnerabilities"] + sbom_to_be_merged["vulnerabilities"]
        )

    merged_sbom = original_sbom
    component_from_metadata = sbom_to_be_merged.get("metadata", {}).get("component", {})
    components_of_sbom_to_be_merged = sbom_to_be_merged.get("components", [])
    components_of_sbom_to_be_merged.append(component_from_metadata)
    list_of_original_dependencies = original_sbom.get("dependencies", [])
    list_of_new_dependencies = sbom_to_be_merged.get("dependencies", [])
    list_of_original_vulnerabilities = original_sbom.get("vulnerabilities", [])
    list_of_new_vulnerabilities = sbom_to_be_merged.get("vulnerabilities", [])

    list_of_merged_components = merge_components(original_sbom, sbom_to_be_merged)

    merged_dependencies = merge_dependency_lists(
        list_of_original_dependencies,
        list_of_new_dependencies,
    )

    if list_of_original_vulnerabilities and list_of_new_vulnerabilities:
        list_of_merged_vulnerabilities = merge_vulnerabilities(
            list_of_original_vulnerabilities,
            list_of_new_vulnerabilities,
            vulnerability_identities,
        )
        merged_sbom["vulnerabilities"] = list_of_merged_vulnerabilities

    elif list_of_new_vulnerabilities:
        list_of_merged_vulnerabilities = merge_vulnerabilities(
            [], list_of_new_vulnerabilities, vulnerability_identities
        )
        merged_sbom["vulnerabilities"] = list_of_merged_vulnerabilities

    merged_sbom["components"] = list_of_merged_components
    merged_sbom["dependencies"] = merged_dependencies

    if merged_sbom.get("compositions", []) or sbom_to_be_merged.get("compositions", []):
        merge_compositions(
            merged_sbom.get("compositions", []),
            sbom_to_be_merged.get("compositions", []),
        )

    return merged_sbom


def merge(sboms: t.Sequence[dict], hierarchical: bool = False) -> dict:
    """
    Function that merges a list of sboms successively in to the first one and creates an JSON file.
    for the result

    Input:
    sboms: List of sboms

    Output:
    0

    """
    # make the bom-refs unique and synchronize them across all SBOMs
    make_bom_refs_unique(sboms)
    unify_bom_refs(sboms)

    # create identity object for all vulnerabilities
    concatenated_vulnerabilities: list[dict] = []
    for k in range(1, len(sboms)):
        concatenated_vulnerabilities += sboms[k].get("vulnerabilities", [])
    identities = get_identities_for_vulnerabilities(concatenated_vulnerabilities)

    merged_sbom = sboms[0]
    for k in range(1, len(sboms)):
        merged_sbom = merge_2_sboms(merged_sbom, sboms[k], identities)
    return merged_sbom


def get_ids_from_vulnerability(vulnerability: dict) -> list[str]:
    ids_vulnerability: list[str] = []

    primary_id = vulnerability.get("id", None)
    references = vulnerability.get("references", [])

    if primary_id is not None:
        ids_vulnerability.append(primary_id)

    for reference in references:
        id = reference.get("id", None)
        if id is not None and id not in ids_vulnerability:
            ids_vulnerability.append(id)

    return ids_vulnerability


def compare_version_range(first_range: str, second_range: str) -> bool:
    # TODO extend to compare <= >= when supported

    # first compare the strings themselves
    # if the version scheme is unknown, but
    # the strings are identical a comparison can still be performed
    if first_range == second_range:
        return True

    first_range_object = VersionRange.from_string(second_range)
    second_range_object = VersionRange.from_string(first_range)

    if first_range_object == second_range_object:
        return True

    return False


def version_is_in_version_range(version: str, version_range: str) -> bool:

    range_object = VersionRange.from_string(version_range)
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
            first_affects_object.get("range", None),
            second_affects_object.get("range", None),
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
) -> list[dict]:
    kept_versions: list[dict] = []
    for new_version in new_versions_list:
        is_in = False
        new_version_copy = copy.deepcopy(new_version)
        for original_version in original_versions_list:
            result = compare_affects_versions_object(original_version, new_version)

            if result == -1:
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
                            f"Inconclusive version comparison, keeping entry ({ref}) "
                            f"in vulnerability {vuln_id}."
                        ),
                    )
                )

            if result in [1, 2]:
                logger.warning(
                    LogMessage(
                        "Potential loss of information",
                        (
                            f"Dropping a duplicate affects entry ({ref}) "
                            f"in vulnerability {vuln_id}."
                        ),
                    )
                )
                is_in = True
        if not is_in:
            kept_versions.append(new_version_copy)
    return kept_versions


def extract_new_affects(
    original_affects_list: list[dict], new_affects_list: list[dict], vuln_id: str
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
            )

            if kept_affect_versions:
                new_affect_copy = copy.deepcopy(new_affect)
                new_affect_copy["versions"] = kept_affect_versions
                kept_affects.append(new_affect_copy)

        if not ref_is_in:
            kept_affects.append(new_affect)

    return kept_affects


def compare_vulnerability_ids(
    first_vulnerability: dict, second_vulnerability: dict
) -> int:
    ids_first_vulnerability = get_ids_from_vulnerability(first_vulnerability)
    ids_second_vulnerability = get_ids_from_vulnerability(second_vulnerability)

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
            affects = copy.deepcopy(affects_list[n].get("versions", []))
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
            aliases = get_ids_from_vulnerability(vulnerability)

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
                        vulnerability_aliases = get_ids_from_vulnerability(
                            vulnerability_object
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
            affects = copy.deepcopy(
                list_of_original_vulnerabilities[n].get("affects", [])
            )
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


def merge_vulnerabilities(
    list_of_original_vulnerabilities_input: list[dict],
    list_of_new_vulnerabilities_input: list[dict],
    vulnerability_identities: dict[str, VulnerabilityIdentity],
) -> list[dict]:
    """
    Merges the vulnerabilities of two SBOMs.

    The vulnerabilities in list_of_original_vulnerabilities are
    kept unchanged.
    If a vulnerability in list_of_new_vulnerabilities is not yet present,
    it will be added.
    If the vulnerability already exists, its "affects" field is compared entries
    already present in a Vulnerability in list_of_original_vulnerabilities will be removed.
    In case of version ranges, for an already present version a != constrained is appended.

    version ranged can not be compared with each other, here exists a risk of information loss.

    Parameters
    ----------
    list_of_original_vulnerabilities : Sequence[dict]
        The list of Vulnerabilities of the sbom in which should be merged
    list_of_new_vulnerabilities: Sequence[dict]
        The list of Vulnerabilities of the new sbom that will be merged in the other

    Returns
    -------
    Sequence[dict]
        List with the merged Vulnerabilities
    """
    # Create copies in case both inputs are the same object
    # what would cause a crash
    list_of_original_vulnerabilities = copy.deepcopy(
        list_of_original_vulnerabilities_input
    )
    list_of_new_vulnerabilities = copy.deepcopy(list_of_new_vulnerabilities_input)

    # replace old bom-refs with the bom refs of the merged sbom
    list_of_merged_vulnerabilities = copy.deepcopy(
        list_of_original_vulnerabilities_input
    )
    collected_affects = collect_affects_of_vulnerabilities(
        list_of_merged_vulnerabilities, vulnerability_identities
    )

    for new_vulnerability in list_of_new_vulnerabilities:
        is_in = False
        id_str_new_vulnerability = json.dumps(new_vulnerability, sort_keys=True)
        id_object_new_vulnerability = vulnerability_identities[id_str_new_vulnerability]

        # The loop is over the original vulnerabilities and not the merged ones to avoid
        # data losses in the case of duplicate entries in new_vulnerabilities
        # both of those will be kept since the comparison used dose not take fields like
        # "analysis" or the "status" of "affects" into consideration.
        # A cleanup of such duplicates might be performed in a dedicated function to be implemented
        # in the tool.
        for original_vulnerability in list_of_original_vulnerabilities:
            id_str_original_vulnerability = json.dumps(
                original_vulnerability, sort_keys=True
            )
            id_object_original_vulnerability = vulnerability_identities[
                id_str_original_vulnerability
            ]
            if id_object_new_vulnerability == id_object_original_vulnerability:
                is_in = True
                # Check affects: 3 cases
                # 1. complete disjunct => two different vulnerability objects, keep both
                # 2. new affects are a subset of the original vulnerabilities => drop with warning
                # 3. the affects have overlap => drop all already present affect objects and throw
                #    a warning
                #    keep the "cleaned" vulnerability object

                # TODO: This comparison takes only individual affect objects into account
                # a holistic approach might be worth future consideration
                # e.g. a vulnerability with the versions "<2.0.0" and "">=2.0.0|<=3.0.0"
                # is equal to one with the entry "<=3.0.0" but for this the ranges must be checked
                # as a whole

                new_affects = extract_new_affects(
                    collected_affects[id_object_original_vulnerability.string()],
                    new_vulnerability.get("affects", []),
                    original_vulnerability.get("id", ""),
                )

                if new_affects:
                    new_vulnerability["affects"] = new_affects
                    list_of_merged_vulnerabilities.append(new_vulnerability)
                    logger.warning(
                        LogMessage(
                            "Potential loss of information",
                            (
                                "Dropping a duplicate affects entries "
                                f'in vulnerability ({original_vulnerability.get("id", "")})'
                            ),
                        )
                    )
                break
        if not is_in:
            list_of_merged_vulnerabilities.append(new_vulnerability)

    return list_of_merged_vulnerabilities


def merge_compositions(
    list_to_be_merged_in: list,
    list_of_new_compositions: list,
) -> None:
    """
    The function get two lists with compositions
    and merges the content of the second list provided
    into the first list.

    Parameters
    ----------
    list_to_be_merged_in: list
        A list with compositions, the operation will be
        performed on this one
    list_of_new_compositions: list
        Compositions to be merged in

    Returns
    -------
    None:
    """
    if not list_to_be_merged_in:
        for composition in list_of_new_compositions:
            list_to_be_merged_in.append(composition)
    else:
        if not list_of_new_compositions:
            return
        else:
            for new_composition in list_of_new_compositions:
                found_matching_aggregate = False
                for original_composition in list_to_be_merged_in:
                    if original_composition.get(
                        "aggregate", "original"
                    ) == new_composition.get("aggregate", "new"):
                        found_matching_aggregate = True
                        merged_assemblies = original_composition.get("assemblies", [])
                        for reference in new_composition.get("assemblies", []):
                            if reference not in merged_assemblies:
                                merged_assemblies.append(reference)
                if not found_matching_aggregate:
                    list_to_be_merged_in.append(new_composition)
    return


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


def make_bom_refs_unique(list_of_sboms: t.Sequence[dict]) -> None:

    # TODO reintroduce the components mapped to refs to add refs of already existing components
    # Probably just do the unifying also in here.... its half of the job
    assigned_bom_refs: dict[ComponentIdentity, str] = {}

    if list_of_sboms:
        retained_components = get_ref_components_mapping(
            list_of_sboms[0].get("components", [])
            + [list_of_sboms[0].get("metadata", {}).get("component", {})]
        )

        for k in range(1, len(list_of_sboms)):
            secondary_sbom = list_of_sboms[k]
            new_components = get_ref_components_mapping(
                secondary_sbom.get("components", [])
                + [secondary_sbom.get("metadata", {}).get("component", {})]
            )

            for reference in new_components.keys():
                # reference exists in primary sbom
                # component is not identical to the one in primary sbom
                # the component did not receive a new bom-ref already

                if (
                    reference in retained_components.keys()
                    and retained_components[reference] != new_components[reference]
                    and new_components[reference] not in assigned_bom_refs.keys()
                ):
                    new_bom_ref = str(new_components[reference])
                    index = 1
                    while (
                        new_bom_ref in retained_components.keys()
                        or new_bom_ref in new_components.keys()
                    ):
                        new_bom_ref = str(new_components[reference]) + "-" + str(index)
                        index += 1

                    replace_bom_ref_in_sbom(secondary_sbom, reference, new_bom_ref)
                    retained_components[new_bom_ref] = new_components[reference]

                    assigned_bom_refs[new_components[reference]] = new_bom_ref

                elif new_components[reference] in assigned_bom_refs.keys():

                    replace_bom_ref_in_sbom(
                        secondary_sbom,
                        reference,
                        assigned_bom_refs[new_components[reference]],
                    )
                    retained_components[new_bom_ref] = new_components[reference]

                else:
                    retained_components[reference] = new_components[reference]


def unify_bom_refs(list_of_sboms: t.Sequence[dict]) -> None:
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
