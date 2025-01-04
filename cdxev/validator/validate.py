# SPDX-License-Identifier: GPL-3.0-or-later

import contextlib
import logging
import re
import sys
import typing as t
from pathlib import Path

import jsonschema
import jsonschema.exceptions
import jsonschema.validators
from jsonschema import FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012, Schema

from cdxev.error import AppError
from cdxev.log import LogMessage
from cdxev.validator.customreports import GitLabCQReporter, WarningsNgReporter
from cdxev.validator.helper import load_spdx_schema, open_schema, validate_filename

logger = logging.getLogger(__name__)


def validate_sbom(
    sbom: dict,
    input_format: str,
    file: Path,
    report_format: t.Optional[str],
    report_path: t.Optional[Path],
    schema_type: t.Optional[str],
    filename_regex: t.Optional[str],
    schema_path: t.Optional[Path],
) -> int:
    errors: list[str] = []
    if (schema_path is not None) == bool(schema_type):
        raise AssertionError(  # pragma: no cover
            "Exactly one of schema_path or schema_type must be non-None"
        )

    # Redirect stderr logging handler to stdout. StopIteration is raised if no handler writing
    # to stderr is found (i.e. during testing)
    with contextlib.suppress(StopIteration):
        stderr_handler = next(
            hdlr
            for hdlr in logging.root.handlers
            if isinstance(hdlr, logging.StreamHandler) and hdlr.stream == sys.stderr
        )
        stderr_handler.setStream(sys.stdout)

    if input_format == "json":
        try:
            spec_version: str = sbom["specVersion"]
        except (KeyError, TypeError):
            raise AppError(
                "Invalid SBOM",
                "Failed to validate against built-in schema because 'specVersion' is missing. "
                "Add the field, then retry.",
            )
        sbom_schema = open_schema(spec_version, schema_type, schema_path)

        if filename_regex is not None:
            # Filename should be validated
            filename_error = validate_filename(
                file.name, filename_regex, sbom, schema_type
            )
            if filename_error:
                if filename_regex == "" and schema_type != "custom":
                    # Implicit validation against CycloneDX recommendations is only a warning
                    logger.warning(filename_error)
                else:
                    # Explicit filename pattern or custom schema produces validation errors
                    errors.append("SBOM has the mistake: " + filename_error)

        schema_spdx = Resource.from_contents(
            contents=load_spdx_schema(), default_specification=DRAFT202012
        )
        registry: Registry[Schema] = Registry().with_resource(
            uri="spdx.schema.json", resource=schema_spdx
        )

        validator_cls: type[jsonschema.Validator] = jsonschema.validators.validator_for(
            sbom_schema
        )
        if schema_path is not None:
            # Built-in schemas are assumed to be tested during development. A runtime check on
            # every run of the validate command would be excessive.
            try:
                validator_cls.check_schema(sbom_schema)
            except jsonschema.exceptions.SchemaError:
                raise AppError(
                    "Schema not loaded",
                    "Invalid JSON Schema in schema file " + str(schema_path),
                )
        v = validator_cls(
            schema=sbom_schema,
            # remove mypy exclusion, if https://github.com/python/typeshed/pull/12484 is merged
            registry=registry,  # type: ignore[call-arg]
            format_checker=FormatChecker(),
        )
        for error in sorted(v.iter_errors(sbom), key=str):
            try:
                if (
                    error.validator == "required"  # type: ignore[comparison-overlap]
                    and error.validator_value
                    == ["this_is_an_externally_described_component"]
                ):
                    # This requirement in the schema allows us to produce warnings.
                    comp = t.cast(dict, error.instance)
                    if "bom-ref" in comp:
                        comp_id = f"Component [bom-ref: {comp['bom-ref']}]"
                    elif "name" in comp:
                        comp_id = f"Component [name: {comp['name']}]"
                    else:
                        comp_id = f"Unidentified component at {error.json_path}"

                    logger.warning(
                        comp_id + " is described by an external BOM. "
                        "The validity of the referenced BOM cannot be checked."
                    )
                    continue
                elif len(error.absolute_path) > 3:
                    error_path = (
                        sbom[error.absolute_path[0]][error.absolute_path[1]].get(
                            "bom-ref",
                            sbom[error.absolute_path[0]][error.absolute_path[1]].get(
                                "name", error.json_path
                            ),
                        )
                        + " the field "
                        + error.absolute_path[2]
                        + "["
                        + str(error.absolute_path[3])
                        + "] has the mistake: "
                    )
                elif len(error.absolute_path) >= 2:
                    error_path = (
                        sbom[error.absolute_path[0]][error.absolute_path[1]].get(
                            "bom-ref",
                            sbom[error.absolute_path[0]][error.absolute_path[1]].get(
                                "name", error.json_path
                            ),
                        )
                        + " has the mistake: "
                    )
                elif len(error.absolute_path) == 1:
                    if "$schema" == error.absolute_path[0]:
                        # skip error that schema is wrong as probably another scheme is in use
                        continue
                    else:
                        error_path = f"{error.absolute_path[0]} has the mistake: "
                else:
                    error_path = "SBOM has the mistake: "
            except AttributeError:
                error_path = error.json_path + " has the mistake: "
            if error.context is not None and len(error.context) > 0:
                error_message = ""
                for i in range(len(error.context)):
                    error_field = re.search(
                        r"'\w+'|(is too short)", error.context[i].message
                    )
                    if (error_field is None) or (
                        error_field.group(0) == "is too short"
                    ):
                        validation_field = (
                            "'" + error.context[i].json_path.split(".")[-1] + "'"
                        )
                    else:
                        validation_field = error_field.group(0)
                    if i < (len(error.context) - 1):
                        if error_message == "":
                            error_message += validation_field
                        else:
                            error_message += ", " + validation_field
                    else:
                        error_message += " or " + validation_field
                error_message += " is a required property"
                errors.append(error_path + error_message)
            else:
                if ("license.id" in error.json_path) and (
                    "is not one of" in error.message
                ):
                    # if mistake is a wrong SPDX ID omit printing every single option
                    errors.append(
                        error_path + "used license ID is not a valid SPDX ID. "
                        "Please use either the field 'name' or provide a valid ID."
                    )
                elif ("dependsOn" in error.json_path) and (
                    "has non-unique elements" in error.message
                ):
                    dependencies = sbom.get("dependencies", {})
                    index_dependencies = re.search(r"\[\d\]", error_path)
                    if index_dependencies is not None:
                        index_ref = index_dependencies.group(0).strip("[]")
                        errors.append(
                            dependencies[int(index_ref)]["ref"]
                            + " has the mistake: the dependencies in dependsOn are non-unique"
                        )
                    else:
                        errors.append(
                            "SBOM has the mistake: Could not find reference for dependencies"
                        )
                elif "non-empty" in error.message:
                    errors.append(
                        f"{error_path}'{error.absolute_path[-1]}' should not be empty"
                    )
                elif error.validator == "pattern":  # type: ignore[comparison-overlap]
                    errors.append(error_path + error.message.replace("\\", ""))
                else:
                    errors.append(error_path + error.message)
    sorted_errors = sorted(set(errors))

    report_handler: t.Optional[logging.Handler] = None
    if report_format == "warnings-ng":
        # The following cast is safe because the caller of this function made sure that
        # report_path is not None when report_format is not None.
        report_handler = WarningsNgReporter(file, t.cast(Path, report_path))
        logger.addHandler(report_handler)
    elif report_format == "gitlab-code-quality":
        # See comment above
        report_handler = GitLabCQReporter(file, t.cast(Path, report_path))
        logger.addHandler(report_handler)
    if len(sorted_errors) == 0:
        logger.info("SBOM is compliant to the provided specification schema")
        return 0
    else:
        for error_msg in sorted_errors:
            logger.error(
                LogMessage(
                    message="Invalid SBOM",
                    description=error_msg.replace(
                        error_msg[0 : error_msg.find("has the mistake")], ""
                    ).replace("has the mistake: ", ""),
                    module_name=error_msg[0 : error_msg.find("has the mistake") - 1],
                )
            )
        if report_handler is not None:
            report_handler.close()
        return 1
