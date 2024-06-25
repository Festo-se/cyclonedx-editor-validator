# SPDX-License-Identifier: GPL-3.0-or-later

import json
import re
import typing as t
from importlib import resources
from pathlib import Path

from cdxev.auxiliary.filename_gen import generate_validation_pattern
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


def validate_filename(
    filename: str,
    regex: str,
    sbom: dict,
    schema_type: str,
) -> t.Union[t.Literal[False], str]:
    if not regex:
        if schema_type == "default":
            regex = "^(bom\\.json|.+\\.cdx\\.json)$"
        else:
            regex = generate_validation_pattern(sbom)

    if re.fullmatch(regex, filename) is None:
        return "filename doesn't match regular expression " + regex
    else:
        return False
