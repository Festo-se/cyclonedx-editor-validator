# SPDX-License-Identifier: GPL-3.0-or-later

import contextlib
import logging
import sys
import typing as t
from pathlib import Path

from cdxev.error import AppError
from cdxev.log import LogMessage
from cdxev.validator.customreports import GitLabCQReporter, WarningsNgReporter
from cdxev.validator.engine import ValidationIssue, validate_instance
from cdxev.validator.helper import validate_filename

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

    if input_format != "json":
        raise AppError("Invalid SBOM", f"Unsupported input format for validation: {input_format}")

    try:
        spec_version = sbom["specVersion"]
    except (KeyError, TypeError) as exc:
        raise AppError(
            "Invalid SBOM",
            "Failed to validate because 'specVersion' is missing. Add the field, then retry.",
        ) from exc
    if not isinstance(spec_version, str):
        raise AppError("Invalid SBOM", "The 'specVersion' field must be a string.")

    errors: list[ValidationIssue] = []
    if filename_regex is not None:
        filename_error = validate_filename(file.name, filename_regex)
        if filename_error:
            if filename_regex == "" and schema_type != "custom":
                logger.warning(filename_error)
            else:
                errors.append(
                    ValidationIssue(
                        path=(),
                        message=filename_error,
                        keyword="filename",
                        subject=None,
                    )
                )

    result = validate_instance(sbom, spec_version, schema_type, schema_path)
    errors.extend(result.errors)
    for warning in result.warnings:
        logger.warning(warning.message)

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
    try:
        if not errors:
            logger.info("SBOM is compliant with the provided specification schema")
            return 0

        for issue in sorted(set(errors), key=lambda item: (item.location, item.message)):
            logger.error(
                LogMessage(
                    message="Invalid SBOM",
                    description=issue.description,
                    module_name=issue.subject,
                )
            )
        return 1
    finally:
        if report_handler is not None:
            logger.removeHandler(report_handler)
            report_handler.close()
