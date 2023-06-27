import logging
from typing import Union, Literal
from pathlib import Path

from cdxev.log import LogMessage as msg
from cdxev.auxiliary.sbomFunctions import (
    get_component_by_ref,
    get_bom_refs_from_components,
)
from cdxev.auxiliary.identity import ComponentIdentity
from cdxev.validator.warningsngreport import WarningsNgReporter

logger = logging.getLogger(__name__)


def plausibility_check(
    sbom: dict, file: Path, report_format: str, output: Path
) -> Union[Literal[0], Literal[1]]:
    """
    Check a sbom for plausability.
    The sbom is checked for orphaned bom-refs and
    components that depend on themself.


    :param dict sbom: the sbom.

    :return: 0 if no errors were found, 1 otherwise
    :rtype: int
    """
    orphaned_bom_refs_errors = check_for_orphaned_bom_refs(sbom)
    dependencies_bom_refs = check_logic_of_dependencies(sbom)
    united_errors = orphaned_bom_refs_errors + dependencies_bom_refs
    if united_errors:
        if report_format == "warnings-ng":
            warnings_ng_handler = WarningsNgReporter(file, output)
            logger.addHandler(warnings_ng_handler)
        for error_dict in united_errors:
            logger.error(
                msg(
                    message=error_dict.get("message", ""),
                    description=error_dict.get("description", ""),
                )
            )
        return 1
    else:
        return 0


def check_for_orphaned_bom_refs(sbom: dict) -> list[dict]:
    """
    Check a sbom for orphaned bom-refs, references that do
    not correspond to any component from the sbom.

    :param dict sbom: the sbom.

    :return: list with the notifications of found errors
    rtype: list[dict]
    """
    list_of_actual_bom_refs = get_bom_refs_from_components(sbom.get("components", []))
    list_of_actual_bom_refs.append(
        sbom.get("metadata", {}).get("component", {}).get("bom-ref")
    )
    # Check if bom_refs appear in the sbom, that do not
    # correspond to a component from the sbom

    # check dependencies
    errors = []
    list_of_all_components = sbom.get("components", []).copy()
    list_of_all_components.append(sbom.get("metadata", {}).get("component", {}))
    for dependency in sbom.get("dependencies", []):
        if dependency.get("ref", "") in list_of_actual_bom_refs:
            for bom_ref in dependency.get("dependsOn", []):
                if bom_ref not in list_of_actual_bom_refs:
                    component = get_component_by_ref(
                        dependency.get("ref", ""), list_of_all_components
                    )
                    id = ComponentIdentity.create(component, allow_unsafe=True)
                    errors.append(
                        create_error_orphaned_bom_ref(
                            bom_ref,
                            "dependencies-dependsOn of reference"
                            + dependency.get("ref", "")
                            + f" belonging to component ({id})",
                        )
                    )

        else:
            errors.append(
                create_error_orphaned_bom_ref(dependency.get("ref", ""), "dependencies")
            )

    # check compositions
    for composition in sbom.get("compositions", []):
        for reference in composition.get("assemblies", []):
            if reference not in list_of_actual_bom_refs:
                errors.append(create_error_orphaned_bom_ref(reference, "compositions"))
        for reference in composition.get("dependencies", []):
            if reference not in list_of_actual_bom_refs:
                errors.append(create_error_orphaned_bom_ref(reference, "compositions"))
    # check vulnearabilities
    for vulnerability in sbom.get("vulnerabilities", []):
        for affected in vulnerability.get("affects", []):
            if affected.get("ref", "") not in list_of_actual_bom_refs:
                errors.append(
                    create_error_orphaned_bom_ref(
                        affected.get("ref", ""),
                        "vulnerabilitie " + vulnerability.get("id", ""),
                    )
                )
    return errors


def check_logic_of_dependencies(sbom: dict) -> list[dict]:
    """
    The function checks if the sbom contains circular dependencies,
    e.g. components, that depend on themself.

    :param dict sbom: the sbom
    :return: list with the notifications of found errors
    :rtype: list[dict]
    """
    errors = []
    list_of_actual_bom_refs = get_bom_refs_from_components(sbom.get("components", []))
    list_of_actual_bom_refs.append(
        sbom.get("metadata", {}).get("component", {}).get("bom-ref")
    )
    # Check for circular references in dependencies
    for current_reference in list_of_actual_bom_refs:
        list_of_upstream_references = get_upstream_dependency_bom_refs(
            current_reference, sbom.get("dependencies", [])
        )
        if current_reference in list_of_upstream_references:
            errors.append(create_error_circular_reference(current_reference, sbom))
    return errors


def create_error_orphaned_bom_ref(reference: str, found_in: str) -> dict:
    """
    Function to create an error dict if orphaned bom_refs were found.

    :param str reference: the orphaned reference
    :param str found in: location of the orphaned sbom

    :return: dict with error message and error description
    """
    error = {
        "message": "Found orphaned bom-ref",
        "description": f"The reference ({reference}) in ({found_in}) does not"
        " correspond to any component in the sbom.",
    }
    return error


def create_error_circular_reference(reference: str, sbom: dict) -> dict:
    """
    Function that creates an error dict if a selfdependend reference was found.

    :param str reference: the reference that depends on itself
    :param dict sbom: the sbom

    :return: dict with error message and error description
    """
    list_of_all_components = sbom.get("components", []).copy()
    list_of_all_components.append(sbom.get("metadata", {}).get("component", {}))
    component = get_component_by_ref(reference, list_of_all_components)
    id = ComponentIdentity.create(component, allow_unsafe=True)
    error = {
        "message": "found circular reference (selfdependent component)",
        "description": f"The component ({id}) depends on itself",
    }
    return error


def get_upstream_dependency_bom_refs(
    start_reference: str, list_of_dependencies: list[dict], recursion_depth: int = 0
) -> list:
    """
    Function that returns the upstream dependencies of a component,
    also all the components this component depends on.

    :param str start_reference: reference from which to start the recursion
                                return every reference this component depends on.
    :param dict sbom: the sbom
    :recursion_depth: parameter for the internal recursion.

    :return: list with elements the component depends on.
    :rtype: list[str]
    """
    list_with_dependencies = []
    # prevent endless recursion, max recursion number is qual to the maximal debt
    # of the tree, also the number of dependencies given
    if recursion_depth < len(list_of_dependencies) + 1:
        recursion_depth += 1
        for dependency in list_of_dependencies:
            if dependency.get("ref", "") == start_reference:
                for reference in dependency.get("dependsOn", ""):
                    list_with_dependencies.append(reference)
                    new_deps = get_upstream_dependency_bom_refs(
                        reference, list_of_dependencies, recursion_depth
                    )
                    for ref in new_deps:
                        if ref not in list_with_dependencies:
                            list_with_dependencies.append(ref)
    return list_with_dependencies


def get_non_unique_bom_refs(sbom: dict) -> list:
    list_of_bomrefs = get_bom_refs_from_components(sbom.get("components", []))
    list_of_bomrefs.append(sbom.get("metadata", {}).get("component", {}).get("bom-ref", ""))
    non_unique_bom_refs = [
        bom_ref for bom_ref in list_of_bomrefs if list_of_bomrefs.count(bom_ref) > 1
    ]
    return list(set(non_unique_bom_refs))


def create_error_non_unique_bom_ref(reference: str, sbom: dict) -> str:
    """
    Function to create an error dict for not unique bom-refs.

    :param str reference: the not unique bom-ref
    :param sbom         : the sbom the bom-ref originates from

    :return: dict with error message and error description
    """
    list_of_all_components = sbom.get("components", []).copy()
    list_of_all_components.append(sbom.get("metadata", {}).get("component", {}))
    list_of_component_ids = []
    for component in list_of_all_components:
        if component.get("bom-ref", "") == reference:
            list_of_component_ids.append(
                ComponentIdentity.create(component, allow_unsafe=True)
            )
    component_description_string = ""
    for component_id in list_of_component_ids:
        component_description_string += f"({component_id})"
    error = {
        "message": "SBOM has the mistake: found non unique bom-ref",
        "description": f"The reference ({reference}) is used in several components. Those are" +
        component_description_string
    }
    return error


def get_errors_for_non_unique_bomrefs(sbom: dict) -> list:
    list_of_non_unique_bomrefs = get_non_unique_bom_refs(sbom)
    errors = []
    for reference in list_of_non_unique_bomrefs:
        errors.append(create_error_non_unique_bom_ref(reference, sbom))
    return errors
