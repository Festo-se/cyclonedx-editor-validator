# SPDX-License-Identifier: GPL-3.0-or-later
"""End-to-end fuzz target for the ``merge`` command.

Builds several plausible SBOMs and runs the full ``merge`` pipeline over them.
This exercises bom-ref unification, component-tree merging, dependency merging
and vulnerability identity resolution -- the most complex command in the tool.
"""

import os
import sys

import atheris

# Make the sibling helper importable both when compiled (PYTHONPATH set in
# build.sh) and when run directly from a checkout.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

with atheris.instrument_imports():
    from _sbom_builder import build_sbom

    from cdxev.error import AppError
    from cdxev.merge import merge


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    # Merge needs at least one SBOM; build between 2 and 4 to exercise the loop.
    count = fdp.ConsumeIntInRange(2, 4)
    sboms = [build_sbom(fdp) for _ in range(count)]
    hierarchical = fdp.ConsumeBool()

    try:
        merge(sboms, hierarchical=hierarchical)
    except AppError:
        # AppError is the tool's own, intentional way of rejecting bad SBOMs.
        pass
    except (KeyError, ValueError, TypeError, RecursionError):
        # Malformed sub-structures can legitimately surface these; they're caught
        # by the CLI layer. Anything else is a genuine finding worth a crash.
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
