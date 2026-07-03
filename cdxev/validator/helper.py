# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
import re
import typing as t
from importlib import resources
from pathlib import Path

from cdxev.auxiliary.filename_gen import (
    generate_allowed_filename_variants,
    generate_validation_pattern,
)
from cdxev.error import AppError

logger = logging.getLogger(__name__)


def _custom_filename_mismatch_hints(filename: str, sbom: dict) -> list[str]:
    hints: list[str] = []

    if not filename.endswith(".cdx.json"):
        return hints

    basename = filename[: -len(".cdx.json")]
    metadata_component = sbom.get("metadata", {}).get("component", {})

    expected_name = metadata_component.get("name", "unknown")
    expected_name = _sanitize_expected_filename_part(expected_name, default_if_empty="unknown")

    expected_version = metadata_component.get("version", "")
    expected_version = _sanitize_expected_filename_part(expected_version, default_if_empty="")

    expected_hashes = [
        h.get("content")
        for h in metadata_component.get("hashes", [])
        if isinstance(h, dict) and h.get("content")
    ]

    _, expected_timestamp_token = generate_allowed_filename_variants(sbom)
    expected_timestamp: t.Optional[str]
    if expected_timestamp_token == "[YYYYMMDDTHHMMSS]":
        expected_timestamp = None
    else:
        expected_timestamp = expected_timestamp_token

    name_prefix = f"{expected_name}_"
    if not basename.startswith(name_prefix):
        hints.append(f"name mismatch: expected '{expected_name}'")
        return hints

    remainder = basename[len(name_prefix) :]

    if expected_version:
        version_prefix = f"{expected_version}_"
        if not remainder.startswith(version_prefix):
            hints.append(f"version mismatch: expected '{expected_version}'")
            return hints
        remainder = remainder[len(version_prefix) :]

    if not remainder:
        return hints

    suffix = remainder.split("_")
    timestamp_regex = re.compile(r"^[0-9]{8}T[0-9]{6}$")

    def _is_timestamp_match(value: str) -> bool:
        if expected_timestamp is not None:
            return value == expected_timestamp
        return bool(timestamp_regex.fullmatch(value))

    if not expected_hashes:
        if len(suffix) != 1 or not _is_timestamp_match(suffix[0]):
            if len(suffix) >= 1 and not _is_timestamp_match(suffix[-1]):
                if expected_timestamp is not None:
                    hints.append(
                        "timestamp mismatch: "
                        f"expected '{expected_timestamp}' (derived from metadata.timestamp, UTC)"
                    )
                else:
                    hints.append("timestamp mismatch: expected format YYYYMMDDTHHMMSS")
        return hints

    if len(suffix) == 1:
        token = suffix[0]
        if _is_timestamp_match(token):
            return hints
        if token not in expected_hashes:
            hints.append(
                "hash mismatch: "
                f"expected one of {', '.join(expected_hashes)}"
            )
        return hints

    hash_token = suffix[0]
    timestamp_token = suffix[1]

    if hash_token not in expected_hashes:
        hints.append(
            "hash mismatch: "
            f"expected one of {', '.join(expected_hashes)}"
        )

    if not _is_timestamp_match(timestamp_token):
        if expected_timestamp is not None:
            hints.append(
                "timestamp mismatch: "
                f"expected '{expected_timestamp}' (derived from metadata.timestamp, UTC)"
            )
        else:
            hints.append("timestamp mismatch: expected format YYYYMMDDTHHMMSS")

    return hints


def _sanitize_expected_filename_part(value: str, default_if_empty: str) -> str:
    value = value or ""
    value = "".join(c for c in value if (c.isalnum() or c in r" .-_"))
    return value or default_if_empty


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
            with schema_path.open(encoding="utf_8_sig") as fp:
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
    schema_json = schema_file.read_text(encoding="utf_8_sig")
    schema = json.loads(schema_json)
    if isinstance(schema, dict):
        return schema
    else:
        raise AppError(
            "Schema error",
            ("Loaded builtin schema is not of type dict"),
        )


def load_spdx_schema() -> dict:
    path_to_embedded_schema = resources.files("cdxev.auxiliary.schema") / "spdx.schema.json"
    with path_to_embedded_schema.open(encoding="utf_8_sig") as f:
        schema = json.load(f)
        if isinstance(schema, dict):
            return schema
        else:
            raise AppError(
                "SPDX schema error",
                ("Loaded SPDX schema is not type dict"),
            )


def load_bundled_schema(filename: str) -> dict:
    """
    Loads a bundled helper schema (e.g. jsf-0.82.schema.json, cryptography-defs.schema.json)
    from the package's schema resource directory.

    :param filename: The filename of the schema to load (e.g. 'jsf-0.82.schema.json').
    :return: The parsed schema as a dictionary.
    """
    path = resources.files("cdxev.auxiliary.schema") / filename
    if not path.is_file():
        raise AppError(
            "Schema not loaded",
            f"Bundled helper schema not found: {filename}",
        )
    with path.open() as f:
        schema = json.load(f)
    if isinstance(schema, dict):
        return schema
    raise AppError(
        "Schema error",
        f"Bundled helper schema is not of type dict: {filename}",
    )


def validate_filename(
    filename: str,
    regex: str,
    sbom: dict,
    schema_type: t.Optional[str],
) -> t.Union[t.Literal[False], str]:
    using_default_custom_pattern = False
    if not regex:
        if schema_type == "custom":
            regex = generate_validation_pattern(sbom)
            using_default_custom_pattern = True
        else:
            regex = "^(bom\\.json|.+\\.cdx\\.json)$"

    try:
        matches = re.fullmatch(regex, filename) is not None
    except re.error as exc:
        raise AppError(
            "Invalid filename pattern",
            f"The provided filename pattern is not a valid regular expression: {exc}",
        ) from exc

    if not matches:
        if using_default_custom_pattern:
            variants, _ = generate_allowed_filename_variants(sbom)
            variants_msg = ", ".join(variants)
            hints = _custom_filename_mismatch_hints(filename, sbom)
            hints_msg = ""
            if hints:
                hints_msg = " Error: " + "; ".join(hints) + "."
            return (
                "filename doesn't match expected SBOM filenames. "
                f"Allowed filenames for this SBOM: {variants_msg}. "
                f"{hints_msg}"
            )
        return "filename doesn't match regular expression " + regex
    else:
        return False
