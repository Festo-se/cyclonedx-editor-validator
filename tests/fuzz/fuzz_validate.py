# SPDX-License-Identifier: GPL-3.0-or-later
"""End-to-end fuzz target for the ``validate`` command.

Runs a plausible SBOM through ``validate_sbom`` against the built-in schema.
This exercises the full validation pipeline: jsonschema validation with the
SPDX/JSF/cryptography helper registries, the custom error post-processing, and
(optionally) filename-pattern validation -- all over untrusted SBOM input.
"""

import os
import sys
from pathlib import Path

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

with atheris.instrument_imports():
    from _sbom_builder import build_sbom

    from cdxev.error import AppError
    from cdxev.validator.validate import validate_sbom


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    sbom = build_sbom(fdp)

    # Optionally exercise the filename-validation branch with a fuzzed pattern.
    if fdp.ConsumeBool():
        filename_regex = fdp.ConsumeUnicodeNoSurrogates(32)
    else:
        filename_regex = None
    file_name = fdp.ConsumeUnicodeNoSurrogates(32) or "bom.json"

    try:
        validate_sbom(
            sbom=sbom,
            input_format="json",
            file=Path(file_name),
            report_format=None,
            report_path=None,
            schema_type="default",
            filename_regex=filename_regex,
            schema_path=None,
        )
    except AppError:
        # AppError is the tool's intended way of rejecting unprocessable SBOMs
        # (e.g. missing specVersion, unknown spec version).
        pass
    except (KeyError, ValueError, TypeError, RecursionError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
