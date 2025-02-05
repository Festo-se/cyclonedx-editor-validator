# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import logging
import typing as t

from cdxev.auxiliary.identity import ComponentIdentity, VulnerabilityIdentity
from cdxev.auxiliary.sbomFunctions import (
    collect_affects_of_vulnerabilities,
    extract_new_affects,
    extract_components,
    get_bom_refs_from_dependencies,
    get_dependency_by_ref,
    get_identities_for_vulnerabilities,
    make_bom_refs_unique,
    unify_bom_refs,
)
from cdxev.log import LogMessage

logger = logging.getLogger(__name__)


def filter_component(
    present_components: list[ComponentIdentity],
    components_to_add: list,
    add_to_existing: dict,
) -> list[dict]:
    """
    Function that goes through a list of components and their nested sub components
    and determine if they are present in a provided list with component identities.

    The function operates directly on the lists and dictionary provided and returns
    a list of filtered top level components that were not found in present_components.
    Filtered means, that the nested components are also not already present.

    param present_components: a list of component identities that are already present in the SBOM.
    param components_to_add: a list of components that shall be compared against the list of
                            already present components.
    param add_to_existing: list of nested components that have to be added to present_components.

    returns: filtered_components: list of top level components not present in present_components
    """
    filtered_components: list[dict] = []
    for component in components_to_add:
        component_id = ComponentIdentity.create(component, allow_unsafe=True)
        # component is new
        if component_id not in present_components:
            nested_components = filter_component(
                present_components,
                component.get("components", []),
                add_to_existing,
            )
            if component.get("components", []):
                component["components"] = nested_components
            filtered_components.append(component)

        # component already present
        # contained components get filtered and added to the component in the main sbom
        else:
            logger.warning(
                LogMessage(
                    "Potential loss of information",
                    f"Dropping a duplicate component ({component_id}) from the merge result.",
                )
            )
            nested_components = filter_component(
                present_components,
                component.get("components", []),
                add_to_existing,
            )
            if nested_components:
                add_to_existing[component_id] = (
                    add_to_existing.get(component_id, []) + nested_components
                )

    return filtered_components


def merge_components(
    governing_sbom: dict, sbom_to_be_merged: dict, hierarchical: bool = False
) -> t.List[dict]:
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

    present_component_identities: dict[ComponentIdentity, dict] = {}
    for component in extract_components(governing_sbom.get("components", [])):
        present_component_identities[
            ComponentIdentity.create(component, allow_unsafe=True)
        ] = component

    add_to_existing: dict[ComponentIdentity, dict] = {}
    list_present_component_identities = list(present_component_identities.keys())
    list_of_filtered_components = filter_component(
        list_present_component_identities,
        list_of_added_components,
        add_to_existing,
    )

    list_of_merged_components += list_of_filtered_components

    if hierarchical:
        for key in add_to_existing.keys():
            list_of_subcomponents = (
                present_component_identities[key].get("components", [])
                + add_to_existing[key]
            )
            present_component_identities[key]["components"] = list_of_subcomponents
    else:
        for key in add_to_existing.keys():
            for new_component in add_to_existing[key]:
                list_of_merged_components.append(new_component)

    return list_of_merged_components


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
    hierarchical: bool = False,
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
    # before used make_bom_refs_unique() and unify_bom_refs must be run on the input

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

    list_of_merged_components = merge_components(
        original_sbom, sbom_to_be_merged, hierarchical
    )

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

    if original_sbom.get("components", []) and sbom_to_be_merged.get("components", []):
        merged_sbom["components"] = list_of_merged_components

    if original_sbom.get("dependencies", []) and sbom_to_be_merged.get(
        "dependencies", []
    ):
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
    for bom in sboms:
        concatenated_vulnerabilities += bom.get("vulnerabilities", [])
    identities = get_identities_for_vulnerabilities(concatenated_vulnerabilities)

    merged_sbom = sboms[0]
    for k in range(1, len(sboms)):
        merged_sbom = merge_2_sboms(
            merged_sbom,
            sboms[k],
            vulnerability_identities=identities,
            hierarchical=hierarchical,
        )
    return merged_sbom


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
