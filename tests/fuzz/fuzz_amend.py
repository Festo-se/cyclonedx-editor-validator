# SPDX-License-Identifier: GPL-3.0-or-later
"""End-to-end fuzz target for the ``amend`` command.

Runs the default set of amend operations (AddBomRef, Compositions,
DefaultAuthor, InferSupplier, LicenseNameToId) over a plausible SBOM. These
operations do no network or arbitrary file I/O, so they're safe to fuzz. This
exercises the component-tree walker plus each operation's per-component logic.
The non-default HierarchicalBomRefs operation is run afterwards to exercise
recursive parent-path and cross-reference rewriting.
"""

import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

with atheris.instrument_imports():
    from _sbom_builder import build_sbom

    from cdxev.amend import command as amend_command
    from cdxev.amend.operations import HierarchicalBomRefs
    from cdxev.error import AppError


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    sbom = build_sbom(fdp)

    try:
        # No explicit operation selection -> default operations only.
        amend_command.run(sbom)
        amend_command.run(sbom, selected=[HierarchicalBomRefs])
    except AppError:
        pass
    except (KeyError, ValueError, TypeError, RecursionError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
