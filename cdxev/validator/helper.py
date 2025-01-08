# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
import re
import typing as t
from importlib import resources
from pathlib import Path

from cdxev.auxiliary.filename_gen import generate_validation_pattern
from cdxev.error import AppError

logger = logging.getLogger(__name__)


def open_schema(
    spec_version: str,
    schema_type: t.Optional[str],
    schema_path: t.Optional[Path],
) -> dict:
    try:
        if schema_type:
            return _get_builtin_schema(schema_type, spec_version)
        else:
            # Convince mypy that schema_path isn't None, because the caller made sure of this
            schema_path = t.cast(Path, schema_path)

            if not schema_path.is_file():
                raise AppError(
                    "Schema not loaded",
                    "Path does not exist or is not a file: " + str(schema_path),
                )
            with schema_path.open() as fp:
                return json.load(fp)  # type:ignore [no-any-return]
    except OSError as e:
        raise AppError("Schema not loaded", str(e)) from e
    except json.JSONDecodeError as e:
        raise AppError(
            "Schema not loaded",
            "Invalid JSON in schema file " + str(schema_path),
        ) from e


def _get_builtin_schema(schema_type: str, spec_version: str) -> dict:
    schema_dir = resources.files("cdxev.auxiliary") / "schema"
    if schema_type == "default":
        schema_file = schema_dir / f"bom-{spec_version}.schema.json"
    else:
        schema_file = schema_dir / f"bom-{spec_version}-{schema_type}.schema.json"

    if not schema_file.is_file():
        raise AppError(
            "Schema not loaded",
            f"No built-in schema found for CycloneDX version {spec_version} and "
            f"schema type '{schema_type}'.",
        )
    schema_json = schema_file.read_text()
    schema = json.loads(schema_json)
    if isinstance(schema, dict):
        return schema
    else:
        raise AppError(
            "Schema error",
            ("Loaded builtin schema is not of type dict"),
        )


def load_spdx_schema() -> dict:
    path_to_embedded_schema = (
        resources.files("cdxev.auxiliary.schema") / "spdx.schema.json"
    )
    with path_to_embedded_schema.open() as f:
        schema = json.load(f)
        if isinstance(schema, dict):
            return schema
        else:
            raise AppError(
                "SPDX schema error",
                ("Loaded SPDX schema is not type dict"),
            )


def validate_filename(
    filename: str,
    regex: str,
    sbom: dict,
    schema_type: t.Optional[str],
) -> t.Union[t.Literal[False], str]:
    if not regex:
        if schema_type == "custom":
            regex = generate_validation_pattern(sbom)
        else:
            regex = "^(bom\\.json|.+\\.cdx\\.json)$"

    if re.fullmatch(regex, filename) is None:
        return "filename doesn't match regular expression " + regex
    else:
        return False
