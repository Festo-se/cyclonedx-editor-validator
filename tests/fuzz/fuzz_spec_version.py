# SPDX-License-Identifier: GPL-3.0-or-later
"""Fuzz target for ``SpecVersion.parse``.

Exercises the CycloneDX specVersion string parser with arbitrary input to make
sure it never raises an unexpected exception on untrusted data.
"""

import sys

import atheris

with atheris.instrument_imports():
    from cdxev.auxiliary.sbom_functions import SpecVersion


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    version_string = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)
    # parse must always return either a SpecVersion or None, never raise.
    SpecVersion.parse(version_string)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
