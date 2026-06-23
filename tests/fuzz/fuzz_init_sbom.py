# SPDX-License-Identifier: GPL-3.0-or-later
"""Fuzz target for the ``init-sbom`` command.

Unlike the other commands, ``init-sbom`` does not consume an SBOM file; it builds
a new SBOM from CLI strings. The interesting untrusted-input surface is the
``email`` argument, which is parsed by the third-party ``email-validator``
library, plus the free-text fields that flow into the CycloneDX model and JSON
serialization.
"""

import sys

import atheris

with atheris.instrument_imports():
    from cdxev.error import AppError
    from cdxev.initialize_sbom import initialize_sbom


def _opt(fdp: atheris.FuzzedDataProvider, max_len: int) -> "str | None":
    # Each field may be omitted (None) so the default-value branches are covered.
    if fdp.ConsumeBool():
        return None
    return fdp.ConsumeUnicodeNoSurrogates(max_len)


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    software_name = _opt(fdp, 48)
    version = _opt(fdp, 24)
    supplier = _opt(fdp, 48)
    authors = _opt(fdp, 48)
    email = _opt(fdp, 64)

    try:
        initialize_sbom(software_name, version, supplier, authors, email)
    except ValueError:
        # Raised for an invalid email address; the CLI turns this into a usage
        # error, so it's expected and handled.
        pass
    except AppError:
        pass
    except (KeyError, TypeError, RecursionError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
