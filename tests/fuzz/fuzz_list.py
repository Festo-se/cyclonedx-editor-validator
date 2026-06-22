# SPDX-License-Identifier: GPL-3.0-or-later
"""End-to-end fuzz target for the ``list`` command.

The ``list`` command runs the untrusted SBOM dict through
``cyclonedx-python-lib``'s ``Bom.from_json`` deserializer before extracting
license/component information. That third-party deserializer is a high-value
parsing surface; this target exercises it plus the downstream string formatting.
"""

import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

with atheris.instrument_imports():
    from _sbom_builder import build_sbom
    from cyclonedx.exception import CycloneDxException

    from cdxev.error import AppError
    from cdxev.list_command import list_command


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    sbom = build_sbom(fdp)

    operation = fdp.PickValueInList(["licenses", "components"])
    output_format = fdp.PickValueInList(["txt", "csv"])

    try:
        list_command(sbom, operation, output_format)
    except AppError:
        pass
    except CycloneDxException:
        # The cyclonedx-python-lib deserializer raises this to reject malformed
        # SBOMs (e.g. invalid purl/UUID). That is its intended boundary behavior.
        pass
    except (KeyError, ValueError, TypeError, RecursionError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
