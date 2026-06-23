# SPDX-License-Identifier: GPL-3.0-or-later
"""Fuzz target for SBOM JSON ingestion and filename generation.

Parses arbitrary bytes as JSON and, when the result is an object, runs the
filename-generation helpers that operate on untrusted SBOM metadata. This
covers the JSON decode path plus the timestamp/name/version sanitization logic.
"""

import json
import sys

import atheris

with atheris.instrument_imports():
    from cdxev.auxiliary.filename_gen import (
        generate_filename,
        generate_validation_pattern,
    )


def TestOneInput(data: bytes) -> None:
    try:
        sbom = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        # Invalid JSON is expected and handled by callers via InputFileError.
        return

    # The production code only ever processes JSON objects as SBOMs.
    if not isinstance(sbom, dict):
        return

    try:
        generate_filename(sbom)
        generate_validation_pattern(sbom)
    except (ValueError, TypeError, AttributeError):
        # These can surface from grossly malformed metadata structures and are
        # acceptable; callers validate the SBOM schema before relying on output.
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
