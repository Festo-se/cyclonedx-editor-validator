# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import logging
import typing as t

from cdxev.auxiliary.identity import ComponentIdentity, VulnerabilityIdentity
from cdxev.auxiliary.sbom_functions import (
    add_merged_metadata_component_to_dependencies,
    CycloneDXVersion,
    SpecVersion,
    collect_affects_of_vulnerabilities,
    extract_components,
    extract_new_affects,
    get_bom_refs_from_dependencies,
    get_dependency_by_ref,
    get_identities_for_vulnerabilities,
    make_bom_refs_unique,
    merge_affects_versions,
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
            if component not in filtered_components:
                filtered_components.append(component)
            else:
                logger.warning(
                    LogMessage(
                        "Potential loss of information",
                        "SBOM contained duplicate component, "
                        f"dropping one instance of ({component_id}) from the merge result.",
                    )
                )
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
    Before use, it must be ensured, that the bom-refs are unique and unified
    across all SBOMs.

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
    list_of_added_components = list(sbom_to_be_merged.get("components", []))

    component_from_metadata = sbom_to_be_merged.get("metadata", {}).get("component", {})
    if component_from_metadata:
        list_of_added_components.append(component_from_metadata)

    present_component_identities: dict[ComponentIdentity, dict] = {}
    for component in extract_components(governing_sbom.get("components", [])):
        present_component_identities[ComponentIdentity.create(component, allow_unsafe=True)] = (
            component
        )

    governing_sbom_metadata = governing_sbom.get("metadata", {})
    governing_sbom_metadata_component = governing_sbom_metadata.get("component", {})
    if governing_sbom_metadata_component:
        present_component_identities[
            ComponentIdentity.create(governing_sbom_metadata_component, allow_unsafe=True)
        ] = governing_sbom_metadata_component

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
                present_component_identities[key].get("components", []) + add_to_existing[key]
            )
            present_component_identities[key]["components"] = list_of_subcomponents
    else:
        for key in add_to_existing.keys():
            for new_component in add_to_existing[key]:
                list_of_merged_components.append(new_component)

    return list_of_merged_components


def _tools_are_equal(tool1: dict, tool2: dict) -> bool:
    """
    Compares two tool objects for equality with strict key matching.

    This intentionally does not use ComponentIdentity equality because that logic
    is overlap-based and can over-match (e.g. tools sharing only broad attributes
    like type), which would drop valid tools during merge.
    """

    def _norm(value: t.Any) -> str:
        if value is None:
            return ""
        return str(value).strip().lower()

    # Preserve important schema fields where present; missing fields normalize to empty strings.
    key1 = (
        _norm(tool1.get("type")),
        _norm(tool1.get("name")),
        _norm(tool1.get("version")),
        _norm(tool1.get("vendor", tool1.get("publisher", tool1.get("organization")))),
        _norm(tool1.get("bom-ref")),
    )
    key2 = (
        _norm(tool2.get("type")),
        _norm(tool2.get("name")),
        _norm(tool2.get("version")),
        _norm(tool2.get("vendor", tool2.get("publisher", tool2.get("organization")))),
        _norm(tool2.get("bom-ref")),
    )
    # If the coarse identity tuple matches, require deep object equality as
    # a guard against over-matching tools that differ in other schema fields.
    return key1 == key2 and tool1 == tool2


def _convert_tools_array_to_dict(tools_array: list) -> dict:
    """
    Converts tools from old format (array) to new format (dict with components/services).
    Array entries are converted to component objects.
    """
    components = []
    for tool in tools_array:
        # Convert old format tool to new format
        component = {
            "type": tool.get("type", "application"),
        }
        if "name" in tool:
            component["name"] = tool["name"]
        if "version" in tool:
            component["version"] = tool["version"]
        if "vendor" in tool:
            component["publisher"] = tool["vendor"]
        if "hashes" in tool:
            component["hashes"] = tool["hashes"]
        if "bom-ref" in tool:
            component["bom-ref"] = tool["bom-ref"]
        # Copy any other fields that might exist
        for key in tool:
            if key not in ("type", "name", "vendor", "version", "hashes", "bom-ref"):
                component[key] = tool[key]
        components.append(component)

    return {"components": components}


def _convert_tools_dict_to_array(tools_dict: dict) -> list:
    """
    Converts tools from new format (dict with components/services) to old format (array).
    """
    tools_array = []

    # Convert components
    for component in tools_dict.get("components", []):
        tool = {}
        if "name" in component:
            tool["name"] = component["name"]
        if "version" in component:
            tool["version"] = component["version"]
        if "publisher" in component:
            tool["vendor"] = component["publisher"]
        if "hashes" in component:
            tool["hashes"] = component["hashes"]
        if "bom-ref" in component:
            tool["bom-ref"] = component["bom-ref"]
        if component.get("type") and component["type"] != "application":
            logger.warning(
                LogMessage(
                    "Potential loss of information",
                    "Converting metadata.tools.components to pre-1.5 metadata.tools array "
                    "drops component type information.",
                )
            )
        tools_array.append(tool)

    # Convert services (if present, add them as tools as well)
    if tools_dict.get("services"):
        logger.warning(
            LogMessage(
                "Potential loss of information",
                "Converting metadata.tools.services to pre-1.5 metadata.tools array "
                "drops the service/component distinction.",
            )
        )
    for service in tools_dict.get("services", []):
        tool = {}
        if "name" in service:
            tool["name"] = service["name"]
        if "version" in service:
            tool["version"] = service["version"]
        if "organization" in service:
            tool["vendor"] = service["organization"]
        if "hashes" in service:
            tool["hashes"] = service["hashes"]
        if "bom-ref" in service:
            tool["bom-ref"] = service["bom-ref"]
        tools_array.append(tool)

    return tools_array


def _merge_tools_array(governing_tools: list, tools_to_merge: list) -> list:
    """
    Merges two tool arrays (old format), avoiding duplicates.
    """
    merged_tools = copy.deepcopy(governing_tools)

    for tool_to_merge in tools_to_merge:
        # Use explicit equality check - don't use sets
        is_duplicate = any(
            _tools_are_equal(tool_to_merge, existing_tool) for existing_tool in merged_tools
        )
        if not is_duplicate:
            merged_tools.append(copy.deepcopy(tool_to_merge))

    return merged_tools


def _merge_tools_dict(governing_tools: dict, tools_to_merge: dict) -> dict:
    """
    Merges two tool dicts (new format with components/services), avoiding duplicates.
    """
    merged_tools = copy.deepcopy(governing_tools)

    # Merge components
    governing_components = merged_tools.get("components")
    if governing_components is None:
        governing_components = []
    if "components" in merged_tools or tools_to_merge.get("components"):
        merged_tools["components"] = governing_components
    for component_to_merge in tools_to_merge.get("components", []):
        is_duplicate = any(
            _tools_are_equal(component_to_merge, existing_component)
            for existing_component in governing_components
        )
        if not is_duplicate:
            governing_components.append(copy.deepcopy(component_to_merge))

    # Merge services
    governing_services = merged_tools.get("services")
    if governing_services is None:
        governing_services = []
    if "services" in merged_tools or tools_to_merge.get("services"):
        merged_tools["services"] = governing_services
    for service_to_merge in tools_to_merge.get("services", []):
        is_duplicate = any(
            _tools_are_equal(service_to_merge, existing_service)
            for existing_service in governing_services
        )
        if not is_duplicate:
            governing_services.append(copy.deepcopy(service_to_merge))

    return merged_tools


def merge_tools(
    governing_tools: t.Union[list, dict, None],
    tools_to_be_merged: t.Union[list, dict, None],
) -> t.Union[list, dict, None]:
    """
    Merges tools from two SBOMs, adapting to the format of the governing SBOM.

    In CycloneDX < 1.5, tools is an array of objects with fields like name, vendor, version.
    In CycloneDX >= 1.5, tools is an object with 'components' and 'services' fields.

    This function:
    1. Determines the format from governing_tools
    2. Converts tools_to_be_merged to match that format
    3. Merges them, avoiding duplicates based on tool identity

    Args:
        governing_tools: Tools from the governing SBOM (array or dict or None)
        tools_to_be_merged: Tools from the SBOM to be merged (array or dict or None)

    Returns:
        Merged tools in the format of governing_tools, or None if both are None/empty
    """
    # Handle missing values. Empty dict/list are valid tool containers and must
    # not be treated like absent values.
    if governing_tools is None and tools_to_be_merged is None:
        return governing_tools

    if tools_to_be_merged is None:
        return governing_tools

    if governing_tools is None:
        return tools_to_be_merged

    # Determine format from governing_tools and narrow types
    if isinstance(governing_tools, dict):
        # Governing is dict format, convert tools_to_be_merged to dict if needed
        converted_tools_dict: dict
        if isinstance(tools_to_be_merged, list):
            converted_tools_dict = _convert_tools_array_to_dict(tools_to_be_merged)
        else:
            converted_tools_dict = copy.deepcopy(tools_to_be_merged)

        # Merge into governing_tools (dict format)
        return _merge_tools_dict(governing_tools, converted_tools_dict)

    # governing_tools is list here
    converted_tools_list: list
    if isinstance(tools_to_be_merged, dict):
        converted_tools_list = _convert_tools_dict_to_array(tools_to_be_merged)
    else:
        converted_tools_list = copy.deepcopy(tools_to_be_merged)

    # Merge into governing_tools (array format)
    return _merge_tools_array(governing_tools, converted_tools_list)


def merge_dependency(depedency_original: dict, dependency_new: dict) -> dict[str, t.Any]:
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
        if refs not in dependson_new:
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

    list_of_original_references = get_bom_refs_from_dependencies(original_list_of_dependencies)
    list_of_new_references = get_bom_refs_from_dependencies(new_list_of_dependencies)
    list_of_merged_dependencies = []
    for reference in list_of_new_references:
        if reference in list_of_original_references:
            original_dependency = get_dependency_by_ref(reference, original_list_of_dependencies)
            new_dependency = get_dependency_by_ref(reference, new_list_of_dependencies)
            merged_dependency = merge_dependency(original_dependency, new_dependency)
            list_of_merged_dependencies.append(merged_dependency)
        else:
            new_dependency = get_dependency_by_ref(reference, new_list_of_dependencies)
            list_of_merged_dependencies.append(new_dependency)
    list_of_new_references = get_bom_refs_from_dependencies(list_of_merged_dependencies)
    for reference in list_of_original_references:
        if reference not in list_of_new_references:
            original_dependency = get_dependency_by_ref(reference, original_list_of_dependencies)
            list_of_merged_dependencies.append(original_dependency)
    return list_of_merged_dependencies


def merge_2_sboms(
    original_sbom: dict,
    sbom_to_be_merged: dict,
    hierarchical: bool = False,
    vulnerability_identities: t.Optional[dict[str, VulnerabilityIdentity]] = None,
) -> dict:
    """
    Function that merges two SBOMs.

    Input
    original_sbom: sbom
    sbom_to_be_merged: sbom

    Output
        merged_sbom: sbom, with sbom_to_be_merged merged in original_sbom

    """
    # before used make_bom_refs_unique() and unify_bom_refs must be run on the input

    if vulnerability_identities is None:
        vulnerability_identities = {}
    if (
        vulnerability_identities == {}
        and original_sbom.get("vulnerabilities", []) != []
        and sbom_to_be_merged.get("vulnerabilities", []) != []
    ):
        vulnerability_identities = get_identities_for_vulnerabilities(
            original_sbom["vulnerabilities"] + sbom_to_be_merged["vulnerabilities"]
        )

    merged_sbom = original_sbom
    list_of_original_dependencies = original_sbom.get("dependencies", [])
    list_of_new_dependencies = sbom_to_be_merged.get("dependencies", [])
    list_of_original_vulnerabilities = original_sbom.get("vulnerabilities", [])
    list_of_new_vulnerabilities = sbom_to_be_merged.get("vulnerabilities", [])

    list_of_merged_components = merge_components(
        original_sbom, sbom_to_be_merged, hierarchical=hierarchical
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

    if list_of_merged_components:
        merged_sbom["components"] = list_of_merged_components

    if original_sbom.get("dependencies", []) and sbom_to_be_merged.get("dependencies", []):
        merged_sbom["dependencies"] = merged_dependencies

    if merged_sbom.get("compositions", []) or sbom_to_be_merged.get("compositions", []):
        merge_compositions(
            merged_sbom.get("compositions", []),
            sbom_to_be_merged.get("compositions", []),
        )

    if merged_sbom.get("metadata", {}).get("component", {}) and merged_sbom.get("components", []):
        add_merged_metadata_component_to_dependencies(merged_sbom, sbom_to_be_merged)

    original_tools = original_sbom.get("metadata", {}).get("tools", None)
    tools_to_merge = sbom_to_be_merged.get("metadata", {}).get("tools", None)
    if tools_to_merge is not None:
        # If original SBOM has no tools yet, choose default tools format based on
        # the original SBOM's version to ensure backward/forward compatibility.
        governing_tools: t.Union[list, dict, None] = original_tools
        if governing_tools is None and tools_to_merge is not None:
            spec_version = SpecVersion.parse(str(original_sbom.get("specVersion", "")))
            if spec_version is not None and spec_version >= CycloneDXVersion.V1_5:
                governing_tools = {}
            else:
                governing_tools = []

        merged_tools = merge_tools(
            governing_tools,
            tools_to_merge,
        )
        if merged_tools is not None:
            merged_sbom.setdefault("metadata", {})["tools"] = merged_tools
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
                    if original_composition.get("aggregate", "original") == new_composition.get(
                        "aggregate", "new"
                    ):
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
    If the vulnerability already exists, its "affects" field is compared.
    Entries already present in a vulnerability in list_of_original_vulnerabilities will be removed.
    In case of version ranges, for an already present version a != constrained is appended.

    version ranges can not be compared with each other, here exists a risk of information loss.

    Parameters
    ----------
    list_of_original_vulnerabilities : Sequence[dict]
        The list of vulnerabilities of the SBOM in which should be merged
    list_of_new_vulnerabilities: Sequence[dict]
        The list of vulnerabilities of the new SBOM that will be merged in the other

    Returns
    -------
    Sequence[dict]
        List with the merged vulnerabilities
    """
    # Create copies in case both inputs are the same object
    # what would cause a crash
    list_of_original_vulnerabilities = copy.deepcopy(list_of_original_vulnerabilities_input)
    list_of_new_vulnerabilities = copy.deepcopy(list_of_new_vulnerabilities_input)

    collected_affects = collect_affects_of_vulnerabilities(
        list_of_original_vulnerabilities, vulnerability_identities
    )

    # add all original vulnerabilities without "merge conflict" to merged vulnerabilities
    # this could be avoided by iterating over merged vulnerabilities,
    # but since those are changed during
    # the loop it would be necessary to recalculate
    # the vulnerability identities after every change.
    list_of_merged_vulnerabilities = []
    for original_vulnerability in list_of_original_vulnerabilities:
        is_in = False
        same_affects_state = False
        id_str_original_vulnerability = json.dumps(original_vulnerability, sort_keys=True)
        id_object_original_vulnerability = vulnerability_identities[id_str_original_vulnerability]
        for new_vulnerability in list_of_new_vulnerabilities:
            id_str_new_vulnerability = json.dumps(new_vulnerability, sort_keys=True)
            id_object_new_vulnerability = vulnerability_identities[id_str_new_vulnerability]
            if id_object_new_vulnerability == id_object_original_vulnerability:
                is_in = True
                if original_vulnerability.get("analysis", {}).get(
                    "state", ""
                ) == new_vulnerability.get("analysis", {}).get("state", "_"):
                    same_affects_state = True

        if not is_in or not same_affects_state:
            list_of_merged_vulnerabilities.append(original_vulnerability)

        # go over new vulnerabilities to resolve "merge conflicts"
    for new_vulnerability in list_of_new_vulnerabilities:
        is_in = False
        same_affects_state = False

        # since vulnerabilities can be assigned different identifier (cve, snyk ...)
        # all provided vulnerabilities are analysed during intitialization and a registry with
        # the respective references is created, the vulnerabilities are then mapped according to
        # this registry
        id_str_new_vulnerability = json.dumps(new_vulnerability, sort_keys=True)
        id_object_new_vulnerability = vulnerability_identities[id_str_new_vulnerability]

        # The loop is over the original vulnerabilities and not the merged ones to avoid
        # data losses in the case of duplicate entries in new_vulnerabilities
        for original_vulnerability in list_of_original_vulnerabilities:
            id_str_original_vulnerability = json.dumps(original_vulnerability, sort_keys=True)
            id_object_original_vulnerability = vulnerability_identities[
                id_str_original_vulnerability
            ]
            # objects describe the same vulnerability
            if id_object_new_vulnerability == id_object_original_vulnerability:
                is_in = True
                # compare the analysis.state
                if original_vulnerability.get("analysis", {}).get(
                    "state", ""
                ) == new_vulnerability.get("analysis", {}).get("state", "_"):
                    same_affects_state = True

                    # Check affects: 3 cases
                    # 1. complete disjunct => two different vulnerability objects, merge
                    # 2. new affects are a subset of the original vulnerabilities => ignore
                    # 3. the affects have overlap => keep both

                    # TODO: This comparison takes only individual affect objects into account
                    # a holistic approach might be worth future consideration
                    # e.g. a vulnerability with the versions "<2.0.0" and "">=2.0.0|<=3.0.0"
                    # is equal to one with the entry "<=3.0.0" but for this the
                    # ranges must be checked as a whole

                    new_affects = extract_new_affects(
                        collected_affects[id_object_original_vulnerability.string()],
                        new_vulnerability.get("affects", []),
                        original_vulnerability.get("id", ""),
                        keep_version_overlap=True,
                    )
                    merged_vulnerability = copy.deepcopy(original_vulnerability)
                    merged_affects = merged_vulnerability.get("affects", [])
                    merge_affects_versions(merged_affects, new_affects)
                    # if vulnerability did not contain affects object

                    merged_vulnerability["affects"] = merged_affects

                    merge_responses(merged_vulnerability, new_vulnerability)
                    list_of_merged_vulnerabilities.append(merged_vulnerability)

        # if no vulnerability object for the vulnerability with the same analysis state exists
        # create a new one
        if is_in and not same_affects_state:
            # Check affects: 3 cases
            # 1. complete disjunct => two different vulnerability objects, add new vuln object
            # 2. new affects are a subset of the original vulnerabilities => drop
            # 3. the affects have overlap => remove all already present affected versions and throw
            #    a warning keep the "cleaned" vulnerability object

            # TODO: This comparison takes only individual affect objects into account
            # a holistic approach might be worth future consideration
            # e.g. a vulnerability with the versions "<2.0.0" and "">=2.0.0|<=3.0.0"
            # is equal to one with the entry "<=3.0.0" but for this the ranges must be checked
            # as a whole
            new_affects = extract_new_affects(
                collected_affects[id_object_original_vulnerability.string()],
                new_vulnerability.get("affects", []),
                original_vulnerability.get("id", ""),
                different_analysis=True,
            )
            # make no changes on the objects themselfs to avoid key errors +
            # when using their id strings
            merged_vulnerability = copy.deepcopy(new_vulnerability)
            if new_affects:
                merged_vulnerability["affects"] = new_affects
                list_of_merged_vulnerabilities.append(merged_vulnerability)

            # If vulnerability is not yet present
        if not is_in:
            list_of_merged_vulnerabilities.append(new_vulnerability)

    return list_of_merged_vulnerabilities


def merge_responses(original_vulnerability: dict, new_vulnerability: dict) -> None:
    original_response = original_vulnerability.get("analysis", {}).get("response", [])
    for response in new_vulnerability.get("analysis", {}).get("response", []):
        if response not in original_response:
            original_response.append(response)
