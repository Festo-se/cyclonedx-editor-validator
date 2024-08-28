# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from cdxev.initialize_sbom import initialize_sbom


class TestInitializeSbom(unittest.TestCase):
    def test_no_arguments_given(self) -> None:
        sbom = initialize_sbom(software_name=None, supplier_name=None, version=None)
        self.assertEqual(
            sbom["metadata"]["component"]["name"],
            "Name of the software described in the SBOM",
        )
        self.assertEqual(
            sbom["metadata"]["component"]["supplier"]["name"],
            "The name of the organization supplying the software",
        )
        self.assertEqual(
            sbom["metadata"]["component"]["version"], "Version of the software"
        )

    def test_name_argument_given(self) -> None:
        sbom = initialize_sbom(software_name="xyz", supplier_name=None, version=None)
        self.assertEqual(sbom["metadata"]["component"]["name"], "xyz")

    def test_supplier_arguments_given(self) -> None:
        sbom = initialize_sbom(supplier_name="yxz", software_name=None, version=None)
        self.assertEqual(sbom["metadata"]["component"]["supplier"]["name"], "yxz")

    def test_version_given(self) -> None:
        sbom = initialize_sbom(version="9.9.9", supplier_name=None, software_name=None)
        self.assertEqual(sbom["metadata"]["component"]["version"], "9.9.9")
