import json
import re
from datetime import datetime
from importlib import resources
from pathlib import Path

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


def load_spdx_schema() -> dict:
    path_to_embedded_schema = (
        resources.files("cdxev.auxiliary.schema") / "spdx.schema.json"
    )
    with path_to_embedded_schema.open() as f:
        return json.load(f)


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
        hashes_of_component = (
            sbom.get("metadata", {}).get("component", {}).get("hashes", [])
        )
        if not name_of_component or not version_of_component:
            return False

        component_hash = (
            "([a-fA-F0-9]{32}|"
            + "[a-fA-F0-9]{40}|"
            + "[a-fA-F0-9]{64}|"
            + "[a-fA-F0-9]{96}|"
            + "[a-fA-F0-9]{128}"
        )
        if len(hashes_of_component) > 0:
            filename_splitted = file.name.replace(".cdx.json", "").split("_")
            for hash in hashes_of_component:
                component_first_hash = [
                    filename_part
                    for filename_part in filename_splitted
                    if hash["content"].startswith(filename_part)
                ]
            if component_first_hash:
                component_hash = "(" + component_first_hash[0]
            # if hash in file name is not one of the hashes in metadata, file name can not be valid
            else:
                return False
        valid_filename = re.search(
            "^"
            + re.escape(name_of_component)
            + "_"
            + re.escape(version_of_component)
            + "_("
            + component_hash
            + ")_"
            + iso_timestamp
            + ")|"
            + component_hash
            + "|"
            + iso_timestamp
            + ")(.cdx.json)$|^bom.json$",
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
