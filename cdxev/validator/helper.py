# SPDX-License-Identifier: GPL-3.0-or-later

import functools
import json
import logging
import re
import typing as t
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import jsonschema_rs
from license_expression import ExpressionError, get_spdx_licensing  # type: ignore[import-untyped]

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
    with path_to_embedded_schema.open(encoding="utf_8_sig") as schema_file:
        schema = json.load(schema_file)
        if isinstance(schema, dict):
            return schema
        raise AppError("SPDX schema error", "Loaded SPDX schema is not type dict")


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
) -> t.Union[t.Literal[False], str]:
    if not regex:
        regex = "^(bom\\.json|.+\\.cdx\\.json)$"

    try:
        matches = re.fullmatch(regex, filename) is not None
    except re.error as exc:
        raise AppError(
            "Invalid filename pattern",
            f"The provided filename pattern is not a valid regular expression: {exc}",
        ) from exc

    if not matches:
        return "filename doesn't match regular expression " + regex
    else:
        return False


PathSegment = str | int
EXTERNAL_COMPONENT_SENTINEL = "this_is_an_externally_described_component"
_HELPER_SCHEMAS = (
    "spdx.schema.json",
    "jsf-0.82.schema.json",
    "cryptography-defs.schema.json",
)
_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$-]*$")
_LICENSE_REF = re.compile(r"^(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+$")
_CONTEXT_LABELS = {
    "components": "component",
    "compositions": "composition",
    "dependencies": "dependency",
    "licenses": "license",
    "services": "service",
    "vulnerabilities": "vulnerability",
}
_ENTITY_COLLECTIONS = {"components", "dependencies", "services", "vulnerabilities"}
_LICENSE_EXPRESSION_PARSER = get_spdx_licensing()


@dataclass(frozen=True)
class ValidationIssue:
    path: tuple[PathSegment, ...]
    message: str
    keyword: str
    subject: str | None

    @property
    def location(self) -> str:
        return format_json_path(self.path)

    @property
    def description(self) -> str:
        if self.subject is not None:
            context = _human_field_context(self.path, self.message)
            return f"{context}: {self.message}" if context else self.message
        context = _human_context(self.path, self.message)
        return f"{context}: {self.message}" if context else self.message


@dataclass(frozen=True)
class ValidationResult:
    errors: tuple[ValidationIssue, ...]
    warnings: tuple[ValidationIssue, ...]


def validate_instance(
    instance: dict[str, t.Any],
    spec_version: str,
    schema_type: str | None,
    schema_path: Path | None,
) -> ValidationResult:
    validator = _get_validator(spec_version, schema_type, schema_path)
    errors: set[ValidationIssue] = set()
    warnings: set[ValidationIssue] = set()

    for error in validator.iter_errors(instance):
        path = tuple(error.instance_path)
        if path == ("$schema",):
            continue
        if _required_property(error) == EXTERNAL_COMPONENT_SENTINEL:
            warnings.add(_external_component_warning(instance, path))
            continue
        errors.update(_normalize_error(error, instance))
    errors.update(_validate_license_expressions(instance))

    def sort_key(issue: ValidationIssue) -> tuple[str, str, str]:
        return issue.location, issue.keyword, issue.message

    return ValidationResult(
        errors=tuple(sorted(errors, key=sort_key)),
        warnings=tuple(sorted(warnings, key=sort_key)),
    )


def _validate_license_expressions(instance: dict[str, t.Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for path in _license_expression_paths(instance):
        expression = t.cast(str, _value_at_path(instance, path))
        try:
            parsed = _LICENSE_EXPRESSION_PARSER.parse(expression)
            unknown_keys = _LICENSE_EXPRESSION_PARSER.unknown_license_keys(parsed)
            invalid_keys = [key for key in unknown_keys if not _LICENSE_REF.fullmatch(key)]
            if invalid_keys:
                raise ExpressionError(f"Unknown license key(s): {', '.join(invalid_keys)}")
        except ExpressionError as exc:
            issues.append(
                ValidationIssue(
                    path=path,
                    message=f"{expression!r} is not a valid license expression: {exc}",
                    keyword="licenseExpression",
                    subject=_subject_for_path(instance, path),
                )
            )
    return issues


def _license_expression_paths(
    value: t.Any,
    path: tuple[PathSegment, ...] = (),
) -> t.Iterator[tuple[PathSegment, ...]]:
    if isinstance(value, dict):
        if len(path) >= 2 and path[-2] == "licenses" and isinstance(value.get("expression"), str):
            yield path + ("expression",)
        for key, nested in value.items():
            yield from _license_expression_paths(nested, path + (key,))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _license_expression_paths(nested, path + (index,))


def format_json_path(path: t.Iterable[PathSegment]) -> str:
    result = "$"
    for segment in path:
        if isinstance(segment, int):
            result += f"[{segment}]"
        elif _IDENTIFIER.fullmatch(segment):
            result += f".{segment}"
        else:
            result += f"[{segment!r}]"
    return result


def _human_context(path: tuple[PathSegment, ...], message: str) -> str:
    segments = [segment for segment in path if isinstance(segment, str)]
    if segments and segments[-1].lower() in message.lower():
        segments.pop()
    words = [_humanize_segment(segment) for segment in segments]
    return " ".join(words).capitalize()


def _human_field_context(path: tuple[PathSegment, ...], message: str) -> str:
    fields = [segment for segment in path if isinstance(segment, str)]
    entity_positions = [
        index
        for index, field in enumerate(fields)
        if field in _ENTITY_COLLECTIONS or field == "component"
    ]
    if entity_positions:
        fields = fields[entity_positions[-1] + 1 :]
    if fields and fields[-1].lower() in message.lower():
        fields.pop()
    fields = [field for field in fields if field.rstrip("s").lower() not in message.lower()]
    if not fields:
        return ""
    words = list(dict.fromkeys(_humanize_segment(field) for field in fields))
    return " ".join(words).capitalize()


def _humanize_segment(segment: str) -> str:
    return _CONTEXT_LABELS.get(segment, re.sub(r"(?<!^)(?=[A-Z])", " ", segment).lower())


def _get_validator(
    spec_version: str,
    schema_type: str | None,
    schema_path: Path | None,
) -> jsonschema_rs.Validator:
    if schema_type is not None:
        return _get_builtin_validator(spec_version, schema_type)

    custom_path = t.cast(Path, schema_path)
    schema = open_schema(spec_version, None, custom_path)
    registry = _get_registry()
    try:
        jsonschema_rs.meta.validate(schema, registry=registry)
        return jsonschema_rs.validator_for(
            schema,
            registry=registry,
            validate_formats=True,
            base_uri=custom_path.resolve().as_uri(),
        )
    except jsonschema_rs.ValidationError as exc:
        raise AppError(
            "Schema not loaded",
            "Invalid JSON Schema in schema file " + str(custom_path),
        ) from exc


@functools.lru_cache(maxsize=None)
def _get_builtin_validator(spec_version: str, schema_type: str) -> jsonschema_rs.Validator:
    schema = open_schema(spec_version, schema_type, None)
    _prepare_builtin_schema(schema, spec_version, schema_type)
    try:
        return jsonschema_rs.validator_for(
            schema,
            registry=_get_registry(),
            validate_formats=True,
        )
    except jsonschema_rs.ValidationError as exc:
        raise AppError(
            "Schema not loaded",
            f"Bundled schema '{schema_type}' for CycloneDX {spec_version} is invalid: "
            f"{exc.message}",
        ) from exc


def _prepare_builtin_schema(schema: dict[str, t.Any], spec_version: str, schema_type: str) -> None:
    if spec_version != "1.7" or schema_type != "custom":
        return
    definitions = schema.get("definitions", {})
    if "licensing" not in definitions:
        definitions["licensing"] = definitions["license"]["properties"]["licensing"]


@functools.lru_cache(maxsize=1)
def _get_registry() -> jsonschema_rs.Registry:
    resources: list[tuple[str, jsonschema_rs.JSONType]] = [
        ("spdx.schema.json", t.cast(dict[str, t.Any], load_spdx_schema())),
        *[
            (name, t.cast(dict[str, t.Any], load_bundled_schema(name)))
            for name in _HELPER_SCHEMAS[1:]
        ],
    ]
    return jsonschema_rs.Registry(resources)


def _normalize_error(
    error: jsonschema_rs.ValidationError,
    instance: dict[str, t.Any],
) -> list[ValidationIssue]:
    if error.kind.name in {"oneOf", "anyOf"}:
        nested = _normalize_branch_error(error, instance)
        if nested:
            return nested

    path = tuple(error.instance_path)
    message = _format_error_message(error, path)
    return [
        ValidationIssue(
            path=path,
            message=message,
            keyword=error.kind.name,
            subject=_subject_for_path(instance, path),
        )
    ]


def _normalize_branch_error(
    error: jsonschema_rs.ValidationError,
    instance: dict[str, t.Any],
) -> list[ValidationIssue]:
    choices = error.instance if isinstance(error.instance, list) else [error.instance]
    conflicts = [
        (index, choice)
        for index, choice in enumerate(choices)
        if isinstance(choice, dict) and {"license", "expression"} <= choice.keys()
    ]
    if conflicts:
        base_path = tuple(error.instance_path)
        return [
            ValidationIssue(
                path=base_path + ((index,) if isinstance(error.instance, list) else ()),
                message="'license' and 'expression' are mutually exclusive; provide exactly one",
                keyword=error.kind.name,
                subject=_subject_for_path(instance, base_path),
            )
            for index, _choice in conflicts
        ]

    branches = _error_branches(error)
    if not branches:
        return []

    all_errors = [nested for branch in branches for nested in branch]
    spdx_error = next(
        (
            nested
            for nested in _walk_errors(all_errors)
            if nested.kind.name == "enum"
            and nested.instance_path
            and nested.instance_path[-1] == "id"
        ),
        None,
    )
    if spdx_error is not None:
        path = tuple(spdx_error.instance_path)
        return [
            ValidationIssue(
                path=path,
                message=(
                    f"{spdx_error.instance!r} is not a valid SPDX ID; "
                    "use a valid SPDX ID or provide a license name and text."
                ),
                keyword="enum",
                subject=_subject_for_path(instance, path),
            )
        ]

    if all(nested.kind.name == "additionalProperties" for nested in all_errors):
        unexpected = [
            property_name
            for nested in all_errors
            for property_name in nested.kind.as_dict().get("unexpected", [])
            if isinstance(property_name, str)
        ]
        path = tuple(error.instance_path)
        properties = ", ".join(f"'{name}'" for name in dict.fromkeys(unexpected))
        return [
            ValidationIssue(
                path=path,
                message=f"Additional properties are not allowed ({properties} were unexpected)",
                keyword="additionalProperties",
                subject=_subject_for_path(instance, path),
            )
        ]

    leaf_errors = list(_walk_errors(all_errors))
    required = [_required_property(nested) for nested in leaf_errors]
    if (
        error.instance_path
        and error.instance_path[-1] == "tools"
        and isinstance(error.instance, dict)
        and any(property_name is not None for property_name in required)
        and any(nested.kind.name == "type" for nested in leaf_errors)
    ):
        property_names = [
            *[name for name in required if name is not None],
            *error.instance.keys(),
        ]
        path = tuple(error.instance_path)
        alternatives = " or ".join(f"'{name}'" for name in dict.fromkeys(property_names))
        return [
            ValidationIssue(
                path=path,
                message=f"{alternatives} is a required property",
                keyword=error.kind.name,
                subject=_subject_for_path(instance, path),
            )
        ]
    if required and all(property_name is not None for property_name in required):
        property_names = t.cast(list[str], required)
        path = tuple(error.instance_path)
        alternatives = " or ".join(f"'{name}'" for name in dict.fromkeys(property_names))
        return [
            ValidationIssue(
                path=path,
                message=f"{alternatives} is a required property",
                keyword=error.kind.name,
                subject=_subject_for_path(instance, path),
            )
        ]

    closest_branch = min(branches, key=lambda branch: len(list(_walk_errors(branch))))
    normalized: list[ValidationIssue] = []
    for nested in closest_branch:
        normalized.extend(_normalize_error(nested, instance))
    return normalized


def _error_branches(
    error: jsonschema_rs.ValidationError,
) -> list[list[jsonschema_rs.ValidationError]]:
    context = error.kind.as_dict().get("context")
    if not isinstance(context, list):
        return []
    return [
        [nested for nested in branch if isinstance(nested, jsonschema_rs.ValidationError)]
        for branch in context
        if isinstance(branch, list)
    ]


def _walk_errors(
    errors: t.Iterable[jsonschema_rs.ValidationError],
) -> t.Iterator[jsonschema_rs.ValidationError]:
    for error in errors:
        branches = _error_branches(error)
        if branches:
            yield from _walk_errors(nested for branch in branches for nested in branch)
        else:
            yield error


def _required_property(error: jsonschema_rs.ValidationError) -> str | None:
    if error.kind.name != "required":
        return None
    property_name = error.kind.as_dict().get("property")
    return property_name if isinstance(property_name, str) else None


def _format_error_message(
    error: jsonschema_rs.ValidationError,
    path: tuple[PathSegment, ...],
) -> str:
    details = error.kind.as_dict()
    keyword = error.kind.name
    field = str(path[-1]) if path else "value"

    if keyword == "required":
        return f"'{_required_property(error)}' is a required property"
    if keyword == "enum" and path and path[-1] == "id":
        return (
            f"{error.instance!r} is not a valid SPDX ID; "
            "use a valid SPDX ID or provide a license name and text."
        )
    if keyword in {"minLength", "minItems", "minProperties"} and details.get("limit") == 1:
        return f"'{field}' should not be empty"
    if keyword == "type":
        types = details.get("types")
        if isinstance(types, list):
            expected = " or ".join(f"'{item}'" for item in types)
            return f"{error.instance!r} is not of type {expected}"
    if keyword == "format" and isinstance(details.get("format"), str):
        return f"{error.instance!r} is not a valid {details['format']}"
    if keyword == "uniqueItems" and path and path[-1] == "dependsOn":
        return "the dependencies in 'dependsOn' are non-unique"
    if keyword == "pattern":
        return error.message.replace("\\", "")
    return error.message


def _external_component_warning(
    instance: dict[str, t.Any],
    path: tuple[PathSegment, ...],
) -> ValidationIssue:
    subject = _subject_for_path(instance, path)
    component = _value_at_path(instance, path)
    if isinstance(component, dict) and isinstance(component.get("bom-ref"), str):
        label = f"bom-ref: {component['bom-ref']}"
    elif isinstance(component, dict) and isinstance(component.get("name"), str):
        label = f"name: {component['name']}"
    else:
        label = "unidentified component"
    return ValidationIssue(
        path=path,
        message=(
            f"Component [{label}] is described by an external BOM. "
            "The validity of the referenced BOM cannot be checked."
        ),
        keyword="externalBom",
        subject=subject,
    )


def _value_at_path(instance: dict[str, t.Any], path: tuple[PathSegment, ...]) -> t.Any:
    current: t.Any = instance
    for segment in path:
        try:
            current = current[segment]
        except (KeyError, IndexError, TypeError):
            return None
    return current


def _subject_for_path(
    instance: dict[str, t.Any],
    path: tuple[PathSegment, ...],
) -> str | None:
    subject: str | None = None
    for index, segment in enumerate(path):
        if segment == "component" or (
            segment in _ENTITY_COLLECTIONS
            and index + 1 < len(path)
            and isinstance(path[index + 1], int)
        ):
            entity_path = path[: index + 1]
            if segment in _ENTITY_COLLECTIONS:
                entity_path += (path[index + 1],)
            entity = _value_at_path(instance, entity_path)
            if not isinstance(entity, dict):
                continue
            identifier = entity.get("bom-ref") or entity.get("ref") or entity.get("name")
            if isinstance(identifier, str):
                subject = identifier
    return subject
