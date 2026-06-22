# SPDX-License-Identifier: GPL-3.0-or-later
"""End-to-end fuzz target for the ``vex`` command.

Runs all four vex sub-commands (list, trim, search, extract) over a plausible
SBOM. This exercises the CSV/string building in ``get_list_of_ids``, the
recursive ``search_key`` traversal used by ``trim``, and the id-matching logic
in ``search``.
"""

import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

with atheris.instrument_imports():
    from _sbom_builder import build_sbom

    from cdxev.error import AppError
    from cdxev.vex import vex


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    sbom = build_sbom(fdp)

    sub_command = fdp.PickValueInList(["list", "trim", "search", "extract"])
    schema = fdp.PickValueInList(["default", "lightweight", ""])
    key = fdp.ConsumeUnicodeNoSurrogates(16)
    value = fdp.ConsumeUnicodeNoSurrogates(16)
    vul_id = fdp.ConsumeUnicodeNoSurrogates(24)

    try:
        vex(sub_command, sbom, key=key, value=value, schema=schema, vul_id=vul_id)
    except AppError:
        pass
    except (KeyError, ValueError, TypeError, RecursionError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
