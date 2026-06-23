# SPDX-License-Identifier: GPL-3.0-or-later
"""End-to-end fuzz target for the ``build-public-bom`` command.

Runs ``build_public_bom`` (without an internal-component schema, so no file I/O)
over a plausible SBOM. This exercises the recursive removal of internal
components and the dependency-graph fix-up that follows.
"""

import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

with atheris.instrument_imports():
    from _sbom_builder import build_sbom

    from cdxev.build_public_bom import build_public_bom
    from cdxev.error import AppError


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    sbom = build_sbom(fdp)

    # Optionally fuzz the external-reference regex (None disables that branch).
    if fdp.ConsumeBool():
        ext_ref_regex = fdp.ConsumeUnicodeNoSurrogates(32)
    else:
        ext_ref_regex = None

    try:
        build_public_bom(sbom, None, ext_ref_regex)
    except AppError:
        pass
    except (KeyError, ValueError, TypeError, RecursionError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
