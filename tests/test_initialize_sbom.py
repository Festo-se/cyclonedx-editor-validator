# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from cdxev.initialize_sbom import initialize_sbom


class TestInitializeSbom(unittest.TestCase):
    def test_no_arguments_given(self) -> None:
        sbom = initialize_sbom(
            software_name=None, supplier_sbom=None, supplier_software=None, version=None
        )
        self.assertEqual(
            sbom["metadata"]["component"]["name"],
            "The name of the component."
        )
        self.assertEqual(
            sbom["metadata"]["component"]["supplier"]["name"],
            "The name of the organization that supplied the component."
        )
        self.assertEqual(
            sbom["metadata"]["component"]["version"], "The component version."
        )
        self.assertEqual(
            sbom["metadata"]["supplier"]["name"],
            "The organization that supplied the BOM."
        )

    def test_name_argument_given(self) -> None:
        sbom = initialize_sbom(
            software_name="xyz",
            supplier_sbom=None,
            supplier_software=None,
            version=None,
        )
        self.assertEqual(sbom["metadata"]["component"]["name"], "xyz")
        self.assertEqual(
            sbom["metadata"]["component"]["supplier"]["name"],
            "The name of the organization that supplied the component."
        )
        self.assertEqual(
            sbom["metadata"]["component"]["version"], "The component version."
        )
        self.assertEqual(
            sbom["metadata"]["supplier"]["name"],
            "The organization that supplied the BOM."
        )

    def test_supplier_sbom_arguments_given(self) -> None:
        sbom = initialize_sbom(
            software_name=None,
            supplier_sbom="xyz",
            supplier_software=None,
            version=None,
        )
        self.assertEqual(
            sbom["metadata"]["component"]["name"],
            "The name of the component."
        )
        self.assertEqual(
            sbom["metadata"]["component"]["supplier"]["name"],
            "The name of the organization that supplied the component."
        )
        self.assertEqual(
            sbom["metadata"]["component"]["version"], "The component version."
        )
        self.assertEqual(
            sbom["metadata"]["supplier"]["name"],
            "xyz"
        )

    def test_supplier_software_arguments_given(self) -> None:
        sbom = initialize_sbom(
            software_name=None,
            supplier_sbom=None,
            supplier_software="xyz",
            version=None,
        )
        self.assertEqual(
            sbom["metadata"]["component"]["name"],
            "The name of the component."
        )
        self.assertEqual(
            sbom["metadata"]["component"]["supplier"]["name"],
            "xyz"
        )
        self.assertEqual(
            sbom["metadata"]["component"]["version"], "The component version."
        )
        self.assertEqual(
            sbom["metadata"]["supplier"]["name"],
            "The organization that supplied the BOM."
        )

    def test_version_arguments_given(self) -> None:
        sbom = initialize_sbom(
            software_name=None,
            supplier_sbom=None,
            supplier_software=None,
            version="xyz"
        )
        self.assertEqual(
            sbom["metadata"]["component"]["name"],
            "The name of the component."
        )
        self.assertEqual(
            sbom["metadata"]["component"]["supplier"]["name"],
            "The name of the organization that supplied the component."
        )
        self.assertEqual(sbom["metadata"]["component"]["version"], "xyz")
        self.assertEqual(
            sbom["metadata"]["supplier"]["name"],
            "The organization that supplied the BOM."
        )
