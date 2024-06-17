# CycloneDX Editor Validator
# Copyright (C) 2023  Festo SE & Co. KG

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import unittest

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

        id_base = ComponentIdentity.create(component_base, True)
        id_cpe = ComponentIdentity.create(component_with_cpe, True)
        id_purl = ComponentIdentity.create(component_with_purl, True)
        id_swid = ComponentIdentity.create(component_with_swid, True)
        id_coords = ComponentIdentity.create(component_with_coords, True)

        self.assertEqual(id_base, id_cpe)
        self.assertEqual(id_base, id_purl)
        self.assertEqual(id_base, id_swid)
        self.assertEqual(id_base, id_coords)

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
