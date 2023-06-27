import json
import re
from datetime import datetime
from importlib import resources
from pathlib import Path
from cdxev.auxiliary.sbomFunctions import (
    get_component_by_ref,
    get_bom_refs_from_components,
)
from cdxev.auxiliary.identity import ComponentIdentity

from cdxev.error import AppError


def open_schema(
    sbom: dict, file: Path, schema_type: str, schema_path: str
) -> tuple[dict, Path]:
    if schema_path:
        sbom_schema, used_schema_path = get_external_schema(Path(schema_path))
    else:
        path_to_embedded_schema = resources.files("cdxev.auxiliary") / "schema"
        with resources.as_file(path_to_embedded_schema) as path:
            used_schema_path = path
        # open json schema, default to 1.3 if specVersion not found
        if schema_type != "default":
            required_schema = (
                "bom-"
                + str(sbom.get("specVersion", 1.3))
                + "-"
                + schema_type
                + ".schema.json"
            )
        else:
            required_schema = (
                "bom-" + str(sbom.get("specVersion", 1.3)) + ".schema.json"
            )
        for scheme_path in resources.files("cdxev.auxiliary.schema").iterdir():
            if required_schema in scheme_path.name:
                with scheme_path.open() as sbom_schema_f:
                    sbom_schema = json.load(sbom_schema_f)
                break
    if "sbom_schema" not in locals():
        raise AppError(
            message="Schema not found",
            description="Unable to load schema for specVersion "
            + sbom.get("specVersion", "not specified"),
            module_name=file.name,
        )
    else:
        return sbom_schema, used_schema_path


def validate_filename(sbom: dict, file: Path, filename_regex: str) -> bool:
    if filename_regex:
        valid_filename = re.search(filename_regex, file.name)
    else:
        try:
            iso_timestamp = datetime.fromisoformat(
                sbom.get("metadata", {}).get("timestamp", "").replace("Z", "+00:00")
            ).strftime("%Y%m%dT%H%M%S")
        except ValueError:
            return False
        name_of_component = (
            sbom.get("metadata", {}).get("component", {}).get("name", "")
        )
        version_of_component = (
            sbom.get("metadata", {}).get("component", {}).get("version", "")
        )
        if not name_of_component or not version_of_component:
            return False
        valid_filename = re.search(
            "^"
            + re.escape(name_of_component)
            + "_"
            + re.escape(version_of_component)
            + "_((([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|"
            "[a-fA-F0-9]{96}|[a-fA-F0-9]{128})_"
            + iso_timestamp
            + ")|(([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|"
            "[a-fA-F0-9]{96}|[a-fA-F0-9]{128})|"
            + iso_timestamp
            + "))(.cdx.json)$|^bom.json$",
            file.name,
        )
    if valid_filename is not None:
        return True
    else:
        return False


def get_external_schema(schema_path: Path) -> tuple[dict, Path]:
    if schema_path.exists():
        try:
            if not schema_path.is_absolute():
                used_schema_path = Path.cwd() / schema_path
            else:
                used_schema_path = schema_path
            with used_schema_path.open() as sbom_schema_f:
                sbom_schema = json.load(sbom_schema_f)
            return sbom_schema, used_schema_path
        except:
            raise AppError(
                "Schema not a valid json",
                (
                    "The submitted schema is not a valid"
                    " JSON file and could not be loaded"
                ),
            )
    else:
        raise AppError(
            "Could not load schema",
            ("Path to the provided schema does not exist"),
        )


def get_non_unique_bom_refs(sbom: dict) -> list:
    list_of_bomrefs = get_bom_refs_from_components(sbom.get("components", []))
    list_of_bomrefs.append(sbom.get("metadata", {}).get("component", {}).get("bom-ref", ""))
    non_unique_bom_refs = [
        bom_ref for bom_ref in list_of_bomrefs if list_of_bomrefs.count(bom_ref) > 1
    ]
    return list(set(non_unique_bom_refs))


def create_error_non_unique_bom_ref(reference: str, sbom: dict) -> dict:
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
        "message": "Found non unique bom-ref",
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
