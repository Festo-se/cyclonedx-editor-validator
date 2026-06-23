# SPDX-License-Identifier: GPL-3.0-or-later
"""End-to-end fuzz target for the ``set`` command.

Builds a plausible SBOM plus a list of fuzzer-controlled update records and runs
``set.run``. This exercises the update-record validation (including untrusted
``version-range`` parsing via ``univers``), component mapping and the
property-merge/overwrite/delete logic.
"""

import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

with atheris.instrument_imports():
    from _sbom_builder import build_sbom

    from cdxev.error import AppError
    from cdxev.set import SetConfig, run


def _build_id(fdp: atheris.FuzzedDataProvider) -> dict:
    id_obj: dict = {}
    if fdp.ConsumeBool():
        id_obj["name"] = fdp.ConsumeUnicodeNoSurrogates(24)
    if fdp.ConsumeBool():
        id_obj["group"] = fdp.ConsumeUnicodeNoSurrogates(16)
    # Choose at most one of version / version-range (the validator rejects both).
    choice = fdp.ConsumeIntInRange(0, 2)
    if choice == 1:
        id_obj["version"] = fdp.ConsumeUnicodeNoSurrogates(16)
    elif choice == 2:
        if fdp.ConsumeBool():
            scheme = fdp.PickValueInList(
                ["generic", "npm", "pypi", "maven", "nuget", "deb", "gem"]
            )
            id_obj["version-range"] = f"vers:{scheme}/{fdp.ConsumeUnicodeNoSurrogates(24)}"
        else:
            id_obj["version-range"] = fdp.ConsumeUnicodeNoSurrogates(32)
    if fdp.ConsumeBool():
        id_obj["purl"] = fdp.ConsumeUnicodeNoSurrogates(48)
    if fdp.ConsumeBool():
        id_obj["cpe"] = fdp.ConsumeUnicodeNoSurrogates(48)
    return id_obj


def _build_update(fdp: atheris.FuzzedDataProvider) -> dict:
    update_set: dict = {}
    for _ in range(fdp.ConsumeIntInRange(0, 4)):
        key = fdp.ConsumeUnicodeNoSurrogates(16)
        kind = fdp.ConsumeIntInRange(0, 3)
        if kind == 0:
            update_set[key] = fdp.ConsumeUnicodeNoSurrogates(24)
        elif kind == 1:
            update_set[key] = None  # triggers delete path
        elif kind == 2:
            update_set[key] = [fdp.ConsumeUnicodeNoSurrogates(16)]
        else:
            update_set[key] = {"name": fdp.ConsumeUnicodeNoSurrogates(16)}
    return {"id": _build_id(fdp), "set": update_set}


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    sbom = build_sbom(fdp)
    updates = [_build_update(fdp) for _ in range(fdp.ConsumeIntInRange(0, 5))]

    cfg = SetConfig(
        force=fdp.ConsumeBool(),
        allow_protected=fdp.ConsumeBool(),
        sbom_paths=[],
        from_file=None,
        # ignore_missing/ignore_existing avoid the interactive prompt path and
        # the deterministic "not found" AppErrors, keeping signal high.
        ignore_missing=True,
        ignore_existing=True,
    )

    try:
        run(sbom, updates, cfg)
    except AppError:
        pass
    except (KeyError, ValueError, TypeError, RecursionError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
