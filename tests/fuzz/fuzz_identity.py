# SPDX-License-Identifier: GPL-3.0-or-later
"""Fuzz target for component identity handling.

Builds an arbitrary component dictionary from the fuzzer input and feeds it into
``ComponentIdentity.create``. This exercises the purl/cpe/swid/coordinates key
extraction logic with malformed and unexpected data.
"""

import sys

import atheris

with atheris.instrument_imports():
    from cdxev.auxiliary.identity import ComponentIdentity


def _build_component(fdp: atheris.FuzzedDataProvider) -> dict:
    """Assembles a component-like dict from fuzzer-controlled bytes."""
    component: dict = {}

    # Randomly populate a selection of identity-relevant fields.
    if fdp.ConsumeBool():
        component["cpe"] = fdp.ConsumeUnicodeNoSurrogates(64)
    if fdp.ConsumeBool():
        component["purl"] = fdp.ConsumeUnicodeNoSurrogates(128)
    if fdp.ConsumeBool():
        component["name"] = fdp.ConsumeUnicodeNoSurrogates(64)
    if fdp.ConsumeBool():
        component["group"] = fdp.ConsumeUnicodeNoSurrogates(64)
    if fdp.ConsumeBool():
        component["version"] = fdp.ConsumeUnicodeNoSurrogates(32)
    if fdp.ConsumeBool():
        # SWID may be a string (parsed as JSON) or a mapping.
        if fdp.ConsumeBool():
            component["swid"] = fdp.ConsumeUnicodeNoSurrogates(128)
        else:
            component["swid"] = {
                "tagId": fdp.ConsumeUnicodeNoSurrogates(32),
                "name": fdp.ConsumeUnicodeNoSurrogates(32),
            }

    return component


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    component = _build_component(fdp)
    allow_unsafe = fdp.ConsumeBool()

    try:
        identity = ComponentIdentity.create(component, allow_unsafe=allow_unsafe)
        # Exercise the dunder methods that downstream code relies on.
        str(identity)
        len(identity)
        hash(identity)
        for key in identity:
            str(key)
    except (ValueError, TypeError, KeyError):
        # SWID parsing (json.loads) and missing required SWID fields legitimately
        # raise these on malformed input; they are handled by callers.
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
