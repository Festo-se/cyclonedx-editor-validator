# SPDX-License-Identifier: GPL-3.0-or-later

import json
import re
import typing as t
from pathlib import Path
from typing import Sequence

from jsonschema import Draft7Validator, FormatChecker

from cdxev.auxiliary.sbomFunctions import extract_components


def remove_internal_information_from_properties(component: dict) -> None:
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
    # check if the component had properties before, so that,
    # in this case, an empty properties field is left
    if component.get("properties", []):
        component["properties"] = new_properties


def remove_component_tagged_internal(
    components: Sequence[dict], path_to_schema: t.Union[Path, None]
) -> t.Tuple[t.List[str], t.List[dict]]:
    """
    Removes the components marked as internal,
    from a list of components.
    If the component contains a properties field
    that declares it as public, it will not be removed.
    Internal Information will also be removed from properties fields
    tagged with a name containing "^internal:".

    Parameters
    ----------
    components: list[dict]
        A list of components
    path_to_schema: Path
        The path to a json schema defining a
        internal component

    Returns
    -------
    list[str]
        A list with the bom-refs from the removed
        components
    list[dict]:
        A list of components without the property
        "internal"
    """
    # create validator, to check if a component is internal
    list_of_removed_component_bom_refs = []
    cleared_components = []

    if path_to_schema is not None:
        validator_for_being_internal = create_internal_validator(path_to_schema)
        for component in components:
            # if it is a internal component, the whole component will be removed,
            # if not, the property within namespace internal will be removed
            if validator_for_being_internal.is_valid(component):
                list_of_removed_component_bom_refs.append(component.get("bom-ref", ""))
                sub_components = extract_components(component.get("components", []))
                for comp in sub_components:
                    list_of_removed_component_bom_refs.append(comp.get("bom-ref", ""))
            else:
                remove_internal_information_from_properties(component)
                cleared_components.append(component)
    else:
        for component in components:
            remove_internal_information_from_properties(component)
            cleared_components.append(component)

    return list_of_removed_component_bom_refs, cleared_components


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


def build_public_bom(sbom: dict, path_to_schema: t.Union[Path, None]) -> dict:
    """
    Removes the components with the property internal
    from a sbom and resolves the dependencies

    Parameters
    ----------
    sbom: dict
        A sbom dictionary
    path_to_schema:
        The path to json schema for defining internal components

    Returns
    -------
    sbom: dict
        A sbom dictionary with internal components removed

    """
    components = sbom.get("components", [])
    dependencies = sbom.get("dependencies", [])
    (
        list_of_removed_components,
        cleared_components,
    ) = remove_component_tagged_internal(components, path_to_schema)
    for bom_ref in list_of_removed_components:
        dependencies = merge_dependency_for_removed_component(bom_ref, dependencies)
    remove_internal_information_from_properties(
        sbom.get("metadata", {}).get("component", {})
    )
    sbom["components"] = cleared_components
    sbom["dependencies"] = dependencies
    for composition in sbom.get("compositions", []):
        new_assemblies = composition.get("assemblies").copy()
        for bom_ref in composition.get("assemblies"):
            if bom_ref in list_of_removed_components:
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
