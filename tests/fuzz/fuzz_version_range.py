# SPDX-License-Identifier: GPL-3.0-or-later
"""Fuzz target for CycloneDX version-range handling.

This is the highest-value parsing surface in ``cdxev``: untrusted
``version-range`` strings (from ``set`` update files and from vulnerability
``affects[].versions[].range`` during ``merge``) are handed to the third-party
``univers`` library. This target exercises both the range parser and the
``version_is_in_version_range`` matcher with arbitrary input.
"""

import sys

import atheris

with atheris.instrument_imports():
    import univers.version_range
    import univers.versions
    from univers import nuget

    from cdxev.auxiliary.sbom_functions import version_is_in_version_range

# Exceptions the production code already expects/handles from univers when it is
# fed a malformed range or version. Anything outside this set is a real finding.
_EXPECTED = (
    univers.version_range.InvalidVersionRange,
    univers.versions.InvalidVersion,
    nuget.InvalidNuGetVersion,
    ValueError,
    TypeError,
    KeyError,
    NotImplementedError,
)


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    version_range = fdp.ConsumeUnicodeNoSurrogates(256)
    version = fdp.ConsumeUnicodeNoSurrogates(128)

    try:
        version_is_in_version_range(version, version_range)
    except _EXPECTED:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
