import logging
import re
from importlib import resources
from pathlib import Path

from jsonschema import Draft7Validator, FormatChecker, validators

from cdxev.log import LogMessage
from cdxev.validator.helper import open_schema, validate_filename
from cdxev.validator.warningsngreport import WarningsNgReporter

logger = logging.getLogger(__name__)

schema_path = resources.files("cdxev.auxiliary") / "schema"
with resources.as_file(schema_path) as path:
    # noinspection PyTypeChecker
    resolver = validators.RefResolver(
        base_uri=f"{path.as_uri()}/",
        # according to documentation referrer has to be True, therefore ignore error from mypy
        referrer=True,  # type: ignore
    )


def validate_sbom(
    sbom: dict,
    input_format: str,
    file: Path,
    report_format: str,
    output: Path,
    schema_type: str = "default",
    filename_regex: str = "",
    schema_path: str = "",
) -> int:
    errors = []
    if input_format == "json":
        sbom_schema, used_schema_path = open_schema(
            sbom, file, schema_type, schema_path
        )
        valid_filename = validate_filename(sbom, file, filename_regex)
        if not valid_filename:
            message = (
                "SBOM has the mistake: file name is not according to the given regex"
            )
            errors.append(message)
        resolver = validators.RefResolver(
            base_uri=f"{used_schema_path.as_uri()}/",
            # according to documentation referrer has to be True, therefore ignore error from mypy
            referrer=True,  # type: ignore
        )
        v = Draft7Validator(
            schema=sbom_schema, resolver=resolver, format_checker=FormatChecker()
        )
        for error in sorted(v.iter_errors(sbom), key=str):
            try:
                if len(error.absolute_path) > 3:
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
                    if "$schema" in error.absolute_path[0]:
                        # skip error that schema is wrong as probably another scheme is in use
                        continue
                    else:
                        error_path = error.absolute_path[0] + " has the mistake: "
                else:
                    error_path = "SBOM has the mistake: "
            except AttributeError:
                error_path = error.json_path + " has the mistake: "
            if len(error.context) > 0:
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
                elif "too short" in error.message:
                    errors.append(
                        error_path
                        + "'"
                        + error.absolute_path[-1]
                        + "' must not be empty"
                    )
                elif error.validator == "pattern":
                    errors.append(error_path + error.message.replace("\\", ""))
                else:
                    errors.append(error_path + error.message)
    sorted_errors = set(sorted(errors))
    if report_format == "warnings-ng":
        warnings_ng_handler = WarningsNgReporter(file, output)
        logger.addHandler(warnings_ng_handler)
    if len(sorted_errors) == 0:
        logger.info("SBOM is compliant to the provided specification schema")
        return 0
    else:
        for error in sorted_errors:
            logger.error(
                LogMessage(
                    message="Invalid SBOM",
                    description=error.replace(
                        error[0 : error.find("has the mistake")], ""
                    ).replace("has the mistake: ", ""),
                    module_name=error[0 : error.find("has the mistake") - 1],
                )
            )
        return 1
