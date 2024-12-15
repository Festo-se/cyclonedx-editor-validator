# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import typing as t

from cdxev.auxiliary.identity import ComponentIdentity
from cdxev.auxiliary.sbomFunctions import (
    compare_time_flag_from_vulnerabilities,
    compare_vulnerabilities,
    copy_ratings,
    get_bom_refs_from_dependencies,
    get_corresponding_reference_to_component,
    get_dependency_by_ref,
    get_ref_from_components,
)
from cdxev.log import LogMessage

logger = logging.getLogger(__name__)


def merge_components(governing_sbom: dict, sbom_to_be_merged: dict) -> t.List[dict]:
    """
    Function that gets two lists of components and merges them unique into one.

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
    list_of_merged_components = governing_sbom.get("components", [])
    list_of_added_components = sbom_to_be_merged.get("components", [])
    list_of_merged_bom_refs = get_ref_from_components(list_of_merged_components)
    for component in list_of_added_components:
        is_in_list, bom_ref_from_list = get_corresponding_reference_to_component(
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
            # if the component in the sbom_to_be_merged has a different
            # bom-ref than the governing_sbom, then the bom-ref will be
            # replaced through the one from the governing_sbom.
            # while doing so, the algorithm checks, that the sbom does not
            # already contain a different component with that ref, if so
            # that component's bom-ref will be renamed
            if bom_ref_from_list != component.get("bom-ref", 1):
                counter = 0
                new_reference = bom_ref_from_list
                while not replace_ref_in_sbom(
                    new_reference, component.get("bom-ref", ""), sbom_to_be_merged
                ):
                    counter += 1
                    new_reference = bom_ref_from_list + "_" + str(counter)
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


def merge_2_sboms(original_sbom: dict, sbom_to_be_merged: dict) -> dict:
    """
    Function that merges two sboms.

    Input
    original_sbom: sbom
    sbom_to_be_merged: sbom

    Output
        merged_sbom: sbom, with sbom_to_be_merged merged in original_sbom

    """
    merged_sbom = original_sbom
    component_from_metadata = sbom_to_be_merged.get("metadata", {}).get("component", {})
    components_of_sbom_to_be_merged = sbom_to_be_merged.get("components", [])
    components_of_sbom_to_be_merged.append(component_from_metadata)
    list_of_original_dependencies = original_sbom.get("dependencies", [])
    list_of_new_dependencies = sbom_to_be_merged.get("dependencies", [])
    list_of_merged_components = merge_components(original_sbom, sbom_to_be_merged)
    merged_dependencies = merge_dependency_lists(
        list_of_original_dependencies,
        list_of_new_dependencies,
    )
    list_of_original_vulnerabilities = original_sbom.get("vulnerabilities", [])
    list_of_new_vulnerabilities = sbom_to_be_merged.get("vulnerabilities", [])
    if list_of_original_vulnerabilities and list_of_new_vulnerabilities:
        list_of_merged_vulnerabilities = merge_vulnerabilities(
            list_of_original_vulnerabilities, list_of_new_vulnerabilities
        )
        merged_sbom["vulnerabilities"] = list_of_merged_vulnerabilities
    elif list_of_new_vulnerabilities:
        list_of_merged_vulnerabilities = merge_vulnerabilities(
            [], list_of_new_vulnerabilities
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


def merge(sboms: t.Sequence[dict]) -> dict:
    """
    Function that merges a list of sboms successively in to the first one and creates an JSON file.
    for the result

    Input:
    sboms: List of sboms

    Output:
    0

    """
    merged_sbom = sboms[0]
    for k in range(1, len(sboms)):
        merged_sbom = merge_2_sboms(merged_sbom, sboms[k])
    return merged_sbom


def merge_vulnerabilities(
    list_of_original_vulnerabilities: t.Sequence[dict],
    list_of_new_vulnerabilities: t.Sequence[dict],
) -> t.Sequence[dict]:
    """
    Merges the vulnerabilities of two sboms

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
    # replace old bom-refs with the bom refs of the merged sbom
    list_of_merged_vulnerabilities = []
    for vulnerability in list_of_new_vulnerabilities:
        affected = vulnerability.get("affects", [])
        is_in = False
        for original_vulnerability in list_of_original_vulnerabilities:
            if compare_vulnerabilities(vulnerability, original_vulnerability):
                time_flag = compare_time_flag_from_vulnerabilities(
                    original_vulnerability, vulnerability
                )
                if time_flag == 2:
                    entry_of_merged_vulnerability = vulnerability.copy()
                else:
                    entry_of_merged_vulnerability = original_vulnerability.copy()
                is_in = True
                merged_affects = original_vulnerability.get("affects", [])
                for references in affected:
                    if references not in merged_affects:
                        merged_affects.append(references)
                if original_vulnerability.get("ratings", []) and vulnerability.get(
                    "ratings", []
                ):
                    merged_ratings = merge_ratings(
                        original_vulnerability.get("ratings", []),
                        vulnerability.get("ratings", 2),
                        time_flag,
                    )
                    entry_of_merged_vulnerability["ratings"] = merged_ratings
                elif original_vulnerability.get("ratings", []):
                    entry_of_merged_vulnerability["ratings"] = (
                        original_vulnerability.get("ratings", 2)
                    )
                elif vulnerability.get("ratings", []):
                    entry_of_merged_vulnerability["ratings"] = vulnerability.get(
                        "ratings", 2
                    )
                list_of_merged_vulnerabilities.append(entry_of_merged_vulnerability)
        if not is_in:
            list_of_merged_vulnerabilities.append(vulnerability)
    return list_of_merged_vulnerabilities


def merge_ratings(
    original_ratings: t.Sequence[dict],
    ratings_to_be_merged: t.Sequence[dict],
    time_flag: int = 0,
) -> list:
    """
    Merges two lists of ratings from two vulnerabilities. If two ratings used the same methods,
    the rating with the higher risk is used
    if a flag is given, the entry from the designated input is used
    if time_flag == 1 the rating from the first input is used,
    for time_flag == 2 the second is used
    for time_flag == 0 (default) the higher rating is used

    Parameters
    ----------
    original_ratings: list
        A list of ratings from a vulnerability
    ratings_to_be_merged: list
        A list of ratings from a vulnerability
    time_flag: int
        Flag to determine which rating should be used

    Returns
    -------
    list:
        List with the merged ratings
    """
    merged_ratings = copy_ratings(original_ratings)
    list_of_merged_rating_methods = [
        rating.get("method", "")
        for rating in original_ratings
        if rating.get("method", "")
    ]
    for rating in ratings_to_be_merged:
        if not rating.get("method", "") in list_of_merged_rating_methods and rating.get(
            "method", ""
        ):
            list_of_merged_rating_methods.append(rating.get("method", 1))
            merged_ratings.append(rating)
        else:
            for entry_of_merged_ratings in merged_ratings:
                if not rating.get("method", 2) == entry_of_merged_ratings.get(
                    "method", 1
                ):
                    continue
                if time_flag == 2:
                    entry_of_merged_ratings["score"] = rating.get("score", "")
                elif time_flag == 0:
                    if rating.get("score", 2) > entry_of_merged_ratings.get("score", 2):
                        entry_of_merged_ratings["score"] = rating.get("score", 2)
    return merged_ratings


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


def replace_ref_in_sbom(
    new_reference: str, reference_to_be_replaced: str, sbom: dict
) -> bool:
    """
    Function to replace a bom-ref in a given sbom through a new one.
    The bom-ref will be replaced in
    metadata
    components
    dependencies
    compositions
    vex
    if those fields exists.
    The replacement is directly performed on the given sbom.

    Parameters
    ----------
    new_reference: str
        The new reference to be used
    reference_to_be_replaced: str
        The reference that shall be replaced with a new one
    sbom: dict
        The sbom on which the replacement of bom_refs is performed

    Returns
    -------
    bool:
        True if replacement succesfull, false, if the new_reference
        already exists in the sbom
    """
    list_of_bom_refs = get_ref_from_components(sbom.get("components", []))
    list_of_bom_refs.append(
        sbom.get("metadata", {}).get("component", {}).get("bom-ref", "")
    )
    if new_reference in list_of_bom_refs:
        return False

    if (
        sbom.get("metadata", {}).get("component", {}).get("bom-ref", "")
        == reference_to_be_replaced
    ):
        sbom["metadata"]["component"]["bom-ref"] = new_reference

    for component in sbom.get("components", []):
        if component.get("bom-ref", "") == reference_to_be_replaced:
            component["bom-ref"] = new_reference
            break  # a bom-ref should only appear in one component

    for dependency in sbom.get("dependencies", []):
        if dependency.get("ref", "") == reference_to_be_replaced:
            dependency["ref"] = new_reference
        else:  # component should not depend on itself
            dependson = dependency.get("dependsOn", [])
            if reference_to_be_replaced in dependson:
                dependson[dependson.index(reference_to_be_replaced)] = new_reference
            dependency["dependsOn"] = dependson

    for composition in sbom.get("compositions", []):
        assemblies = composition.get("assemblies", [])
        if reference_to_be_replaced in assemblies:
            assemblies[assemblies.index(reference_to_be_replaced)] = new_reference
        composition["assemblies"] = assemblies

    for vulnerability in sbom.get("vulnerabilities", []):
        for affected in vulnerability.get("affects", []):
            if affected.get("ref", "") == reference_to_be_replaced:
                affected["ref"] = new_reference
                break  # per vulnerability every ref should only appear once
    return True
