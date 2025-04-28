# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
import re
import typing as t
from pathlib import Path
from typing import Any, Sequence

from jsonschema import Draft7Validator, FormatChecker

from cdxev.auxiliary.sbomFunctions import extract_components
from cdxev.log import LogMessage

logger = logging.getLogger(__name__)


def remove_internal_information_from_properties(component: dict[str, Any]) -> None:
    """
    Removes information from properties, that are
    tagged as internal. See
    https://github.com/CycloneDX/cyclonedx-property-taxonomy#registered-top-level-namespaces
    for further details.
    The function operates directly on the given component.

    Parameters
    ----------
    component: dict
        A component dictionary

    Returns
    -------
    None
    """
    new_properties = [
        entry
        for entry in component.get("properties", [])
        if not re.search("^internal:", entry.get("name").lower())
    ]
    # if the component has public properties, replace old properties list with new one
    # otherwise delete empty key-value pair
    if new_properties != []:
        component["properties"] = new_properties
    else:
        component.pop("properties", None)


def validate_external_references(regex: t.Union[str, None], component: dict) -> None:
    """
    Checks the external references of a component and
    removes any that match the regex pattern.
    The function operates directly on the given component.

    Parameters
    ----------
    regex: str
        The regex pattern
    component: dict
        A component dictionary

    Returns
    -------
    None
    """
    references = component.get("externalReferences", [])
    if regex is not None:
        new_references = [ref for ref in references if not re.match(regex, ref["url"])]
        if new_references != []:
            component["externalReferences"] = new_references
        else:
            component.pop("externalReferences", None)
    else:
        if not references:
            component.pop("externalReferences", None)


def clear_component(
    component: dict[str, Any], ext_ref_regex: t.Union[str, None] = None
) -> None:
    """
    Removes all internal information of the component
    and applies the same process to all sub-components
    contained within the component.

    Parameters
    -----------
    component: dict[str, Any]
        A dictionary representing the component,
        which may contain sub-components

    Returns
    -------
    None
    """
    remove_internal_information_from_properties(component)
    validate_external_references(ext_ref_regex, component)
    # The 'extract_components' function processes any nested components recursively,
    # ensuring that all levels of sub-components are handled.
    sub_components = extract_components(component.get("components", []))
    for sub_component in sub_components:
        remove_internal_information_from_properties(sub_component)
        validate_external_references(ext_ref_regex, sub_component)


def remove_component_tagged_internal(
    component: dict, validator: Draft7Validator
) -> tuple[list[str], list[dict]]:
    """
    Removes the top-level component if it is marked as internal (internal, if valid
    according to the schema). The nested components then replace
    the removed component if present. If a top-level component is not marked as internal,
    the function recursively checks and removes its nested internal marked components.

    Parameters
    ----------
    components: dict
        A dictionary of the top-level component
    validator: Draft7Validator
        A validator to check if component is valid
        according to the schema

    Returns
    -------
    tuple[list[str], list[dict]]:
        A tuple where the first element is a list containing bom-refs of
        of all removed components. The second element is a list of the new top-level component(s).
        If the original component has not been removed, this list contains only one element:
        the original component with only its public nested components.
        Otherwise the nested top-level components are saved in the list
    """

    list_of_removed_bom_refs = []
    sub_components = component.get("components", [])
    list_of_public_component = []
    # create copy of component without nested components inside a list
    # must be a list because the component could be internal and
    # would then be replaced by one or multiple sub components
    list_of_public_component.append(component.copy())
    list_of_public_component[0]["components"] = []
    # loop trough nested components and remove recursively internal tagged components
    for sub_component in sub_components:
        list_of_removed_sub_bom_refs, list_of_public_sub_component = (
            remove_component_tagged_internal(sub_component, validator)
        )
        # add (not internal) sub components to parent component
        for new_sub_component in list_of_public_sub_component:
            list_of_public_component[0]["components"].append(new_sub_component)
        for removed_bom_ref in list_of_removed_sub_bom_refs:
            list_of_removed_bom_refs.append(removed_bom_ref)
    # remove key if there are no nested components
    if list_of_public_component[0].get("components", []) == []:
        list_of_public_component[0].pop("components")
    # check if component is tagged internal
    # if so, then replace list containing only the parent component
    # with a list of all (not internal) sub components
    if validator.is_valid(component):
        list_of_public_component = list_of_public_component[0].get("components", [])
        list_of_removed_bom_refs.append(component.get("bom-ref", ""))
    return list_of_removed_bom_refs, list_of_public_component


def merge_dependency_for_removed_component(
    bom_ref: str, dependencies: Sequence[dict]
) -> Sequence[dict]:
    """
    Resolves the dependencies after a component
    is removed

    Parameters
    ----------
    bom_ref: str
        A bom-ref string from a removed component
    dependencies: list[dict]
        A list with dependency dictionaries

    Returns
    -------
    list[dict]
        A list with the resolved dependencies
        components
    """
    dependencies_to_merge = []
    new_dependencies = []
    for entry in dependencies:
        if entry.get("ref", "") == bom_ref:
            dependencies_to_merge = entry.get("dependsOn", [])
        else:
            new_dependencies.append(entry)
    for entry in new_dependencies:
        depends_on = entry.get("dependsOn", [])
        if bom_ref in depends_on:
            new_depends_on = [deps for deps in depends_on if deps != bom_ref]
            if dependencies_to_merge:
                for dependency in dependencies_to_merge:
                    if dependency not in new_depends_on:
                        new_depends_on.append(dependency)
            entry["dependsOn"] = new_depends_on
    return new_dependencies


def build_public_bom(
    sbom: dict[str, Any],
    path_to_schema: t.Union[Path, None],
    ext_ref_regex: t.Union[str, None] = None,
) -> dict:
    """
    Removes the components with the property internal
    from an SBOM and resolves the dependencies

    Parameters
    ----------
    sbom: dict
        An SBOM dictionary
    path_to_schema:
        The path to json schema for defining internal components

    Returns
    -------
    sbom: dict
        An SBOM dictionary with internal components removed

    """
    metadata = sbom.get("metadata", {})
    components = sbom.get("components", [])
    dependencies = sbom.get("dependencies", [])
    cleared_components = []
    list_of_removed_component_bom_refs = []

    # if a schema is provided, the validator will verify the metadata.component as well
    # as each individual component to determine if it is marked as internal according to the schema
    if path_to_schema is not None:
        validator = create_internal_validator(path_to_schema)

        # check if the JSON schema applies to metadata.component. If so, print a warning
        list_of_removed_metadata_component, _ = remove_component_tagged_internal(
            metadata.get("component", {}), validator
        )
        if len(list_of_removed_metadata_component) > 0:
            logger.warning(
                LogMessage(
                    "metadata.component not removed",
                    "metadata.component was not removed even though the JSON schema applies to it."
                    " Maybe you try to create an external SBOM for an internal component "
                    "(the SBOM is not intended for public use)?",
                )
            )
        for component in components:
            removed_component_bom_refs, noninternal_components = (
                remove_component_tagged_internal(component, validator)
            )
            list_of_removed_component_bom_refs.extend(removed_component_bom_refs)
            # loop trough list of removed (internal) components
            # and remove internal properties from all (sub-)components
            for noninternal_component in noninternal_components:
                clear_component(noninternal_component, ext_ref_regex)
                cleared_components.append(noninternal_component)
    else:
        # remove internal properties from all (sub-)components
        for component in components:
            clear_component(component, ext_ref_regex)
            cleared_components.append(component)
    # replace components with cleared components, if it is not an empy list
    if cleared_components:
        sbom["components"] = cleared_components
    else:
        sbom.pop("components", None)
    for bom_ref in list_of_removed_component_bom_refs:
        dependencies = merge_dependency_for_removed_component(bom_ref, dependencies)
    # check metadata.component
    remove_internal_information_from_properties(
        sbom.get("metadata", {}).get("component", {})
    )
    validate_external_references(
        ext_ref_regex, sbom.get("metadata", {}).get("component", {})
    )
    # replace dependencies with new dependencies, if it is not an empy list
    if dependencies:
        sbom["dependencies"] = dependencies
    else:
        sbom.pop("dependencies", None)
    for composition in sbom.get("compositions", []):
        new_assemblies = composition.get("assemblies").copy()
        for bom_ref in composition.get("assemblies"):
            if bom_ref in list_of_removed_component_bom_refs:
                new_assemblies.remove(bom_ref)
        composition["assemblies"] = new_assemblies
    return sbom


def create_internal_validator(path_to_schema: Path) -> Draft7Validator:
    with path_to_schema.open() as schema_f:
        schema_internal = json.load(schema_f)
    validator_for_being_internal = Draft7Validator(
        schema_internal, format_checker=FormatChecker()
    )
    validator_for_being_internal.check_schema(schema_internal)
    return validator_for_being_internal
