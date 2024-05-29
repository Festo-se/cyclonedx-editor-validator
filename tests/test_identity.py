# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

import univers.version_range  # type:ignore

from cdxev.auxiliary.identity import ComponentIdentity, Key, KeyType


class IdentityTestCase(unittest.TestCase):
    sample_cpe = "cpe:/a:example:mylibrary:1.0.0"
    sample_purl = "pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.14"
    sample_swid = {
        "tagId": "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1",
        "name": "Acme Application",
        "version": "9.1.1",
        "text": {
            "contentType": "text/xml",
            "encoding": "base64",
            "content": (
                "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiID8+"
                "CjxTb2Z0d2FyZUlkZW50aXR5IHhtbDpsYW5nPSJFTiIgbmFtZT0i"
                "QWNtZSBBcHBsaWNhdGlvbiIgdmVyc2lvbj0iOS4xLjEiIAogdmVy"
                "c2lvblNjaGVtZT0ibXVsdGlwYXJ0bnVtZXJpYyIgCiB0YWdJZD0i"
                "c3dpZGdlbi1iNTk1MWFjOS00MmMwLWYzODItM2YxZS1iYzdhMmE0"
                "NDk3Y2JfOS4xLjEiIAogeG1sbnM9Imh0dHA6Ly9zdGFuZGFyZHMu"
                "aXNvLm9yZy9pc28vMTk3NzAvLTIvMjAxNS9zY2hlbWEueHNkIj4g"
                "CiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1M"
                "U2NoZW1hLWluc3RhbmNlIiAKIHhzaTpzY2hlbWFMb2NhdGlvbj0i"
                "aHR0cDovL3N0YW5kYXJkcy5pc28ub3JnL2lzby8xOTc3MC8tMi8y"
                "MDE1LWN1cnJlbnQvc2NoZW1hLnhzZCBzY2hlbWEueHNkIiA+CiAg"
                "PE1ldGEgZ2VuZXJhdG9yPSJTV0lEIFRhZyBPbmxpbmUgR2VuZXJh"
                "dG9yIHYwLjEiIC8+IAogIDxFbnRpdHkgbmFtZT0iQWNtZSwgSW5j"
                "LiIgcmVnaWQ9ImV4YW1wbGUuY29tIiByb2xlPSJ0YWdDcmVhdG9y"
                "IiAvPiAKPC9Tb2Z0d2FyZUlkZW50aXR5Pg=="
            ),
        },
    }
    sample_coordinates = {"name": "mylibrary", "group": "acme", "version": "0.2.4"}

    def test_id_creation(self) -> None:
        component = {
            "type": "library",
            "bom-ref": "some bom-ref",
            "author": "Company Unit",
            "name": self.sample_coordinates["name"],
            "group": self.sample_coordinates["group"],
            "version": self.sample_coordinates["version"],
            "cpe": self.sample_cpe,
            "purl": self.sample_purl,
            "swid": self.sample_swid,
        }

        component_id = ComponentIdentity.create(component, True)

        # Expected a key of every type to be present
        expected_key_types = [e for e in KeyType]
        actual_key_types = [k.type for k in component_id]
        self.assertSequenceEqual(actual_key_types, expected_key_types)

    def test_partial_id_creation(self) -> None:
        component = {
            "type": "library",
            "bom-ref": "some bom-ref",
            "author": "Company Unit",
            "name": self.sample_coordinates["name"],
            "group": self.sample_coordinates["group"],
            "version": self.sample_coordinates["version"],
            "cpe": self.sample_cpe,
            "purl": self.sample_purl,
        }

        component_id = ComponentIdentity.create(component, True)

        # This id shouldn't have an SWID.
        expected_key_types = (KeyType.CPE, KeyType.PURL, KeyType.COORDINATES)
        actual_key_types = [k.type for k in component_id]
        self.assertSequenceEqual(actual_key_types, expected_key_types)

    def test_safe_id_creation(self) -> None:
        component = {
            "type": "library",
            "bom-ref": "some bom-ref",
            "author": "Company Unit",
            "name": self.sample_coordinates["name"],
            "group": self.sample_coordinates["group"],
            "version": self.sample_coordinates["version"],
            "cpe": self.sample_cpe,
            "purl": self.sample_purl,
        }

        component_id = ComponentIdentity.create(component, False)

        # This id shouldn't have an SWID.
        expected_key_types = (KeyType.CPE, KeyType.PURL)
        actual_key_types = [k.type for k in component_id]
        self.assertSequenceEqual(actual_key_types, expected_key_types)

    def test_swid_creation(self) -> None:
        key = Key.from_swid(self.sample_swid)

        self.assertEqual(key.type, KeyType.SWID)
        self.assertEqual(
            str(key),
            "SWID[tagId: %s]" % self.sample_swid["tagId"],
        )

    def test_cpe_creation(self) -> None:
        key = Key.from_cpe(self.sample_cpe)

        self.assertEqual(key.type, KeyType.CPE)
        self.assertEqual(
            str(key),
            "CPE[%s]" % self.sample_cpe,
        )

    def test_purl_creation(self) -> None:
        key = Key.from_purl(self.sample_purl)

        self.assertEqual(key.type, KeyType.PURL)
        self.assertEqual(
            str(key),
            "PURL[%s]" % self.sample_purl,
        )

    def test_coordinates_creation(self) -> None:
        key = Key.from_coordinates(
            name=self.sample_coordinates["name"],
            group=self.sample_coordinates["group"],
            version=self.sample_coordinates["version"],
        )

        self.assertEqual(key.type, KeyType.COORDINATES)
        self.assertEqual(
            str(key),
            "COORDINATES[%s/%s@%s]"
            % (
                self.sample_coordinates["group"],
                self.sample_coordinates["name"],
                self.sample_coordinates["version"],
            ),
        )

    def test_coordinates_with_version_range_creation(self) -> None:

        key = Key.from_coordinates(
            name=self.sample_coordinates["name"],
            group=self.sample_coordinates["group"],
            version="vers:pypi/>=1.2.4",
        )

        self.assertEqual(key.type, KeyType.COORDINATES)
        self.assertEqual(
            str(key),
            "COORDINATES[%s/%s@%s]"
            % (
                self.sample_coordinates["group"],
                self.sample_coordinates["name"],
                "vers:pypi/>=1.2.4",
            ),
        )
        self.assertEqual(key.key.version_type, univers.versions.PypiVersion)
        self.assertEqual(
            key.key.version_range,
            univers.version_range.VersionRange.from_string("vers:pypi/>=1.2.4"),
        )

    def test_id_equality(self) -> None:
        component_base = {
            "type": "library",
            "bom-ref": "first bom-ref",
            "author": "Company Unit",
            "name": self.sample_coordinates["name"],
            "group": self.sample_coordinates["group"],
            "version": self.sample_coordinates["version"],
            "cpe": self.sample_cpe,
            "purl": self.sample_purl,
            "swid": self.sample_swid,
        }

        component_with_cpe = dict(component_base)
        del component_with_cpe["name"]
        del component_with_cpe["purl"]
        del component_with_cpe["swid"]

        component_with_purl = dict(component_base)
        del component_with_purl["name"]
        del component_with_purl["cpe"]
        del component_with_purl["swid"]

        component_with_swid = dict(component_base)
        del component_with_swid["name"]
        del component_with_swid["cpe"]
        del component_with_swid["purl"]

        component_with_coords = dict(component_base)
        del component_with_coords["cpe"]
        del component_with_coords["purl"]
        del component_with_coords["swid"]

        component_with_range = dict(component_base)
        del component_with_range["cpe"]
        del component_with_range["purl"]
        del component_with_range["swid"]
        component_with_range["version"] = "vers:pypi/>=9.0.0"

        id_base = ComponentIdentity.create(component_base, True)
        id_cpe = ComponentIdentity.create(component_with_cpe, True)
        id_purl = ComponentIdentity.create(component_with_purl, True)
        id_swid = ComponentIdentity.create(component_with_swid, True)
        id_coords = ComponentIdentity.create(component_with_coords, True)
        id_range = ComponentIdentity.create(component_with_range, True)

        self.assertEqual(id_base, id_cpe)
        self.assertEqual(id_base, id_purl)
        self.assertEqual(id_base, id_swid)
        self.assertEqual(id_base, id_coords)
        self.assertTrue(id_range, id_base)

    def test_key_in_id(self) -> None:
        component = {
            "type": "library",
            "bom-ref": "some bom-ref",
            "author": "Company Unit",
            "name": self.sample_coordinates["name"],
            "group": self.sample_coordinates["group"],
            "version": self.sample_coordinates["version"],
            "cpe": self.sample_cpe,
            "purl": self.sample_purl,
        }

        component_id = ComponentIdentity.create(component, True)

        cpe_key = Key.from_cpe(self.sample_cpe)
        purl_key = Key.from_purl(self.sample_purl)
        coordinates_key = Key.from_coordinates(**self.sample_coordinates)
        swid_key = Key.from_swid(self.sample_swid)

        self.assertTrue(cpe_key in component_id)
        self.assertTrue(purl_key in component_id)
        self.assertTrue(coordinates_key in component_id)
        self.assertFalse(swid_key in component_id)

    def test_version_range(self) -> None:
        component_base = {
            "name": "some name",
            "group": "some group",
            "version": "vers:pypi/>=1.2",
        }

        component_version_in = dict(component_base)
        component_version_in["version"] = "1.2.1"

        component_version_not_in = dict(component_base)
        component_version_not_in["version"] = "1.1.9"

        component_version_wildcard = dict(component_base)
        component_version_wildcard["version"] = "*"

        id_range = ComponentIdentity.create(component_base, True)
        id_version_in = ComponentIdentity.create(component_version_in, True)
        id_version_not_in = ComponentIdentity.create(component_version_not_in, True)
        id_wildcard = ComponentIdentity.create(component_version_wildcard, True)

        self.assertEqual(id_wildcard, id_version_in)
        self.assertEqual(id_wildcard, id_version_not_in)
        self.assertEqual(id_range, id_version_in)
        self.assertNotEqual(id_range, id_version_not_in)
