# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from cdxev import pkg
from cdxev.initialize_sbom import initialize_sbom


class TestInitializeSbom(unittest.TestCase):
    def test_no_arguments_given(self) -> None:
        sbom = initialize_sbom(
            software_name=None, authors=None, supplier=None, version=None
        )
        self.assertEqual(
            sbom["metadata"]["component"]["name"],
            "The name of the component described by the SBOM.",
        )
        self.assertEqual(
            sbom["metadata"]["component"]["supplier"]["name"],
            "The name of the organization that supplied the component.",
        )
        self.assertEqual(
            sbom["metadata"]["component"]["version"], "The component version."
        )
        self.assertEqual(
            sbom["metadata"]["authors"][0]["name"], "The person who created the SBOM."
        )
        self.assertEqual(sbom["metadata"]["tools"][0]["version"], pkg.VERSION)

    def test_name_argument_given(self) -> None:
        sbom = initialize_sbom(
            software_name="xyz",
            authors=None,
            supplier=None,
            version=None,
        )
        self.assertEqual(sbom["metadata"]["component"]["name"], "xyz")
        self.assertEqual(
            sbom["metadata"]["component"]["supplier"]["name"],
            "The name of the organization that supplied the component.",
        )
        self.assertEqual(
            sbom["metadata"]["component"]["version"], "The component version."
        )
        self.assertEqual(
            sbom["metadata"]["authors"][0]["name"], "The person who created the SBOM."
        )

    def test_authors_arguments_given(self) -> None:
        sbom = initialize_sbom(
            software_name=None,
            authors="xyz",
            supplier=None,
            version=None,
        )
        self.assertEqual(
            sbom["metadata"]["component"]["name"],
            "The name of the component described by the SBOM.",
        )
        self.assertEqual(
            sbom["metadata"]["component"]["supplier"]["name"],
            "The name of the organization that supplied the component.",
        )
        self.assertEqual(
            sbom["metadata"]["component"]["version"], "The component version."
        )
        self.assertEqual(sbom["metadata"]["authors"][0]["name"], "xyz")

    def test_supplier_arguments_given(self) -> None:
        sbom = initialize_sbom(
            software_name=None,
            authors=None,
            supplier="xyz",
            version=None,
        )
        self.assertEqual(
            sbom["metadata"]["component"]["name"],
            "The name of the component described by the SBOM.",
        )
        self.assertEqual(sbom["metadata"]["component"]["supplier"]["name"], "xyz")
        self.assertEqual(
            sbom["metadata"]["component"]["version"], "The component version."
        )
        self.assertEqual(
            sbom["metadata"]["authors"][0]["name"], "The person who created the SBOM."
        )

    def test_version_arguments_given(self) -> None:
        sbom = initialize_sbom(
            software_name=None, authors=None, supplier=None, version="xyz"
        )
        self.assertEqual(
            sbom["metadata"]["component"]["name"],
            "The name of the component described by the SBOM.",
        )
        self.assertEqual(
            sbom["metadata"]["component"]["supplier"]["name"],
            "The name of the organization that supplied the component.",
        )
        self.assertEqual(sbom["metadata"]["component"]["version"], "xyz")
        self.assertEqual(
            sbom["metadata"]["authors"][0]["name"], "The person who created the SBOM."
        )

    def test_email_arguments_given(self) -> None:
        sbom = initialize_sbom(
            software_name=None,
            authors=None,
            supplier=None,
            version=None,
            email="test@test.com",
        )
        self.assertEqual(sbom["metadata"]["authors"][0]["email"], "test@test.com")

    def test_email_arguments_not_given(self) -> None:
        sbom = initialize_sbom(
            software_name=None, authors=None, supplier=None, version=None
        )
        self.assertEqual(sbom["metadata"]["authors"][0].get("email", None), None)

    def test_invalid_email(self) -> None:
        with self.assertRaises(ValueError):
            initialize_sbom(
                software_name=None,
                authors=None,
                supplier=None,
                version=None,
                email="notValidMail.com",
            )
