# SPDX-License-Identifier: GPL-3.0-or-later

import json
import pathlib
import typing as t
import unittest

import cdxev.error
import cdxev.set
import copy

from typing import Sequence, Any


class SetTestCase(unittest.TestCase):
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

    def setUp(self) -> None:
        with open(
            "tests/auxiliary/test_set_sboms/test.cdx.json", encoding="utf_8"
        ) as file:
            self.sbom_fixture = json.load(file)

    def test_add_property(self) -> None:
        updates = [
            {
                "id": {"purl": "pkg:npm/test-app@1.0.0"},
                "set": {"copyright": "2022 Acme Inc"},
            }
        ]
        cfg = cdxev.set.SetConfig(
            False,
            False,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            None,
        )

        cdxev.set.run(self.sbom_fixture, updates, cfg)

        expected = {
            "type": "application",
            "name": "test-app",
            "version": "1.0.0",
            "bom-ref": "pkg:npm/test-app@1.0.0",
            "author": "Company Legal",
            "purl": "pkg:npm/test-app@1.0.0",
            "copyright": "2022 Acme Inc",
        }
        self.assertDictEqual(self.sbom_fixture["metadata"]["component"], expected)

    def test_overwrite_simple_property(self) -> None:
        updates = [
            {
                "id": {"purl": "pkg:npm/test-app@1.0.0"},
                "set": {"author": "Another author"},
            }
        ]
        cfg = cdxev.set.SetConfig(
            True,
            False,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            None,
        )

        cdxev.set.run(self.sbom_fixture, updates, cfg)

        expected = {
            "type": "application",
            "name": "test-app",
            "version": "1.0.0",
            "bom-ref": "pkg:npm/test-app@1.0.0",
            "author": "Another author",
            "purl": "pkg:npm/test-app@1.0.0",
        }
        self.assertDictEqual(self.sbom_fixture["metadata"]["component"], expected)

    def test_overwrite_list(self) -> None:
        updates = [
            {
                "id": {
                    "name": "depA",
                    "group": "com.company.unit",
                    "version": "4.0.2",
                },
                "set": {"licenses": [{"license": {"id": "MIT"}}]},
            }
        ]
        cfg = cdxev.set.SetConfig(
            True,
            False,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            None,
        )

        cdxev.set.run(self.sbom_fixture, updates, cfg)

        expected = {
            "type": "library",
            "name": "depA",
            "group": "com.company.unit",
            "version": "4.0.2",
            "bom-ref": "com.company.unit/depA@4.0.2",
            "author": "Company Unit",
            "licenses": [{"license": {"id": "MIT"}}],
            "externalReferences": [{"type": "website", "url": "https://www.festo.com"}],
        }
        self.assertDictEqual(self.sbom_fixture["components"][0], expected)

    def test_delete_property(self) -> None:
        updates = [
            {
                "id": {"purl": "pkg:npm/test-app@1.0.0"},
                "set": {"author": None},
            }
        ]
        cfg = cdxev.set.SetConfig(
            True,
            False,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            None,
        )

        cdxev.set.run(self.sbom_fixture, updates, cfg)

        expected = {
            "type": "application",
            "name": "test-app",
            "version": "1.0.0",
            "bom-ref": "pkg:npm/test-app@1.0.0",
            "purl": "pkg:npm/test-app@1.0.0",
        }
        self.assertDictEqual(self.sbom_fixture["metadata"]["component"], expected)

    def test_merge_list(self) -> None:
        updates = [
            {
                "id": {
                    "name": "depA",
                    "group": "com.company.unit",
                    "version": "4.0.2",
                },
                "set": {"licenses": {"license": {"id": "MIT"}}},
            }
        ]
        cfg = cdxev.set.SetConfig(
            True,
            False,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            None,
        )

        cdxev.set.run(self.sbom_fixture, updates, cfg)

        expected = {
            "type": "library",
            "name": "depA",
            "group": "com.company.unit",
            "version": "4.0.2",
            "bom-ref": "com.company.unit/depA@4.0.2",
            "author": "Company Unit",
            "licenses": [{"license": {"id": "Apache-2.0"}}, {"license": {"id": "MIT"}}],
            "externalReferences": [{"type": "website", "url": "https://www.festo.com"}],
        }
        self.assertDictEqual(self.sbom_fixture["components"][0], expected)

    def test_overwrite_without_force_raises(self) -> None:
        updates = [
            {
                "id": {"purl": "pkg:npm/test-app@1.0.0"},
                "set": {"author": "Another author"},
            }
        ]
        cfg = cdxev.set.SetConfig(
            False,
            False,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            None,
        )

        self.assertRaises(
            cdxev.error.AppError,
            cdxev.set.run,
            self.sbom_fixture,
            updates,
            cfg,
        )

    def test_multiple_updates_different_components(self) -> None:
        updates: list[dict[str, t.Any]] = [
            {
                "id": {"purl": "pkg:npm/test-app@1.0.0"},
                "set": {"author": "Another author"},
            },
            {
                "id": {
                    "name": "x-ray",
                    "group": "physics",
                    "version": "18.9.5",
                },
                "set": {"licenses": [{"license": {"id": "Apache-2.0"}}]},
            },
            {
                "id": {"name": "depC", "version": "3.2.1"},
                "set": {"author": "Yet another author"},
            },
        ]
        cfg = cdxev.set.SetConfig(
            True,
            False,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            pathlib.Path("MyUpdates.json"),
        )

        meta_component = self.sbom_fixture["metadata"]["component"]
        x_ray = self.sbom_fixture["components"][1]["components"][1]
        dep_c = self.sbom_fixture["components"][2]

        expected_meta_component = dict(meta_component, author="Another author")
        expected_x_ray = dict(x_ray, licenses=[{"license": {"id": "Apache-2.0"}}])
        expected_dep_c = dict(dep_c, author="Yet another author")

        cdxev.set.run(self.sbom_fixture, updates, cfg)

        self.assertDictEqual(meta_component, expected_meta_component)
        self.assertDictEqual(x_ray, expected_x_ray)
        self.assertDictEqual(dep_c, expected_dep_c)

    def test_multiple_updates_same_component(self) -> None:
        updates = [
            {
                "id": {
                    "name": "x-ray",
                    "group": "physics",
                    "version": "18.9.5",
                },
                "set": {"author": "New author", "licenses": None},
            },
            {
                "id": {
                    "name": "x-ray",
                    "group": "physics",
                    "version": "18.9.5",
                },
                "set": {"licenses": [{"license": {"id": "Apache-2.0"}}]},
            },
        ]
        cfg = cdxev.set.SetConfig(
            True,
            False,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            pathlib.Path("MyUpdates.json"),
        )

        x_ray = self.sbom_fixture["components"][1]["components"][1]
        expected = dict(
            x_ray, author="New author", licenses=[{"license": {"id": "Apache-2.0"}}]
        )

        cdxev.set.run(self.sbom_fixture, updates, cfg)

        self.assertDictEqual(expected, x_ray)

    def test_missing_identifier_raises(self) -> None:
        updates = [{"set": {"author": "some author"}}]

        cfg = cdxev.set.SetConfig(
            False,
            False,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            None,
        )

        self.assertRaises(
            cdxev.error.AppError, cdxev.set.run, self.sbom_fixture, updates, cfg
        )

    def test_too_many_identifiers_raises(self) -> None:
        updates = [
            {
                "id": {
                    "swid": self.sample_swid,
                    "purl": self.sample_purl,
                },
                "set": {"author": "some author"},
            },
        ]

        cfg = cdxev.set.SetConfig(
            False,
            False,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            None,
        )

        self.assertRaises(
            cdxev.error.AppError, cdxev.set.run, self.sbom_fixture, updates, cfg
        )

    def test_unsettable_raises(self) -> None:
        updates = [
            {
                "id": {"cpe": self.sample_cpe},
                "set": {"cpe": "this should not be possible to set"},
            },
        ]

        cfg = cdxev.set.SetConfig(
            False,
            False,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            None,
        )

        self.assertRaises(
            cdxev.error.AppError, cdxev.set.run, self.sbom_fixture, updates, cfg
        )

    def test_ids_not_found_raises(self) -> None:
        updates = [
            {
                "id": {"cpe": "non-existent CPE"},
                "set": {"author": "some author"},
            },
            {
                "id": {"purl": "pkg:npm/test-app@1.0.0"},
                "set": {"author": "some author"},
            },
            {
                "id": {"cpe": "another non-existent CPE"},
                "set": {"author": "some author"},
            },
        ]

        cfg = cdxev.set.SetConfig(
            True,
            False,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            pathlib.Path("Some.json"),
        )

        self.assertRaises(
            cdxev.error.AppError, cdxev.set.run, self.sbom_fixture, updates, cfg
        )

    def test_duplicate_target_components(self) -> None:
        updates = [
            {
                "id": {
                    "name": "Rudolph",
                    "version": "6.6.6",
                },
                "set": {"author": "some author"},
            },
        ]

        cfg = cdxev.set.SetConfig(
            True,
            False,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            None,
        )

        cdxev.set.run(self.sbom_fixture, updates, cfg)

        self.assertEqual(
            "some author", self.sbom_fixture["components"][2]["components"][0]["author"]
        )
        self.assertEqual(
            "some author",
            self.sbom_fixture["components"][1]["components"][1]["components"][0][
                "author"
            ],
        )

    def test_set_protected_raises(self) -> None:
        updates = [
            {
                "id": {
                    "name": "depC",
                    "version": "3.2.1",
                },
                "set": {"name": "new name"},
            },
        ]

        cfg = cdxev.set.SetConfig(
            True,
            False,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            None,
        )

        self.assertRaises(
            cdxev.error.AppError, cdxev.set.run, self.sbom_fixture, updates, cfg
        )

    def test_set_allowed_protected(self) -> None:
        updates = [
            {
                "id": {
                    "name": "depC",
                    "version": "3.2.1",
                },
                "set": {"name": "new name"},
            },
        ]

        cfg = cdxev.set.SetConfig(
            True,
            True,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            None,
        )

        cdxev.set.run(self.sbom_fixture, updates, cfg)

        self.assertEqual(self.sbom_fixture["components"][2]["name"], "new name")

    def test_partial_components_dont_match(self) -> None:
        update1 = [
            {
                "id": {
                    "name": "gravity",
                    "version": "0.0.1",
                    # group is missing
                },
                "set": {"name": "new name"},
            },
        ]
        update2 = [
            {
                "id": {
                    "name": "Rudolph",
                    "version": "6.6.6",
                    "group": "this should not be present",
                },
                "set": {"name": "new name"},
            }
        ]

        cfg = cdxev.set.SetConfig(
            True,
            True,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            None,
        )

        with self.assertRaises(
            cdxev.error.AppError,
            msg="Component was matched even though 'group' was missing.",
        ) as cm:
            cdxev.set.run(
                self.sbom_fixture,
                update1,
                cfg,
            )

        self.assertIn(
            "not found and could not be updated", cm.exception.details.description
        )

        with self.assertRaises(
            cdxev.error.AppError,
            msg="Component was matched even though 'group' should not be there.",
        ) as cm:
            cdxev.set.run(
                self.sbom_fixture,
                update2,
                cfg,
            )

        self.assertIn(
            "not found and could not be updated", cm.exception.details.description
        )

    def test_set_ignore_missing(self) -> None:
        updates = [
            {
                "id": {
                    "name": "depC_",
                    "version": "3.2.1",
                },
                "set": {"name": "new name"},
            },
        ]
        cfg = cdxev.set.SetConfig(
            True,
            True,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            None,
            True,
        )

        cdxev.set.run(self.sbom_fixture, copy.deepcopy(updates), cfg)

        cfg = cdxev.set.SetConfig(
            True,
            True,
            [pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")],
            None,
        )

        self.assertRaises(
            cdxev.error.AppError,
            cdxev.set.run,
            self.sbom_fixture,
            updates,
            cfg,
        )


class TestVersionRange(unittest.TestCase):
    def setUp(self) -> None:
        with open(
            (
                "tests/auxiliary/test_set_sboms/Acme_Application_"
                "9.1.1_ec7781220ec7781220ec778122012345_20220217T101458.cdx.json"
            ),
            encoding="utf_8",
        ) as file:
            self.sbom_fixture = json.load(file)

    def test_add_copyright_to_one_component_with_version_range(self) -> None:
        updates = [
            {
                "id": {
                    "name": "Acme_Application",
                    "group": "com.acme.internal",
                    "version": "9.1.1|8.1.1",
                },
                "set": {"copyright": "2022 Acme Inc"},
            }
        ]
        cfg = cdxev.set.SetConfig(
            True,
            False,
            [
                pathlib.Path(
                    "tests/auxiliary/test_set_sboms/Acme_Application_"
                    "9.1.1_ec7781220ec7781220ec778122012345_20220217T101458.cdx.json"
                )
            ],
            None,
        )

        cdxev.set.run(self.sbom_fixture, updates, cfg)

        expected = {
            "type": "application",
            "bom-ref": "acme-app",
            "group": "com.acme.internal",
            "supplier": {"name": "Festo SE & Co. KG"},
            "name": "Acme_Application",
            "version": "9.1.1",
            "copyright": "2022 Acme Inc",
            "hashes": [{"alg": "MD5", "content": "ec7781220ec7781220ec778122012345"}],
            "properties": [{"name": "internal:component:status", "value": "internal"}],
        }
        self.assertDictEqual(self.sbom_fixture["metadata"]["component"], expected)

    def test_add_copyright_to_all_components_with_version_range(self) -> None:
        updates = [
            {
                "id": {
                    "name": "web-framework",
                    "group": "org.acme",
                    "version": "<6.0.0",
                },
                "set": {"copyright": "1990 Acme Inc"},
            }
        ]
        cfg = cdxev.set.SetConfig(
            True,
            False,
            [
                pathlib.Path(
                    "tests/auxiliary/test_set_sboms/Acme_Application_"
                    "9.1.1_ec7781220ec7781220ec778122012345_20220217T101458.cdx.json"
                )
            ],
            None,
        )

        cdxev.set.run(self.sbom_fixture, updates, cfg)
        for component in self.sbom_fixture["components"]:
            self.assertEqual(component["copyright"], "1990 Acme Inc")

    def test_add_copyright_to_all_components_larger_then(self) -> None:
        updates = [
            {
                "id": {
                    "name": "web-framework",
                    "group": "org.acme",
                    "version": ">3.0.0",
                },
                "set": {"copyright": "1990 Acme Inc"},
            }
        ]
        cfg = cdxev.set.SetConfig(
            True,
            False,
            [
                pathlib.Path(
                    "tests/auxiliary/test_set_sboms/Acme_Application_"
                    "9.1.1_ec7781220ec7781220ec778122012345_20220217T101458.cdx.json"
                )
            ],
            None,
        )

        cdxev.set.run(self.sbom_fixture, updates, cfg)
        self.assertEqual(
            self.sbom_fixture["components"][3]["copyright"], "1990 Acme Inc"
        )
        self.assertEqual(
            self.sbom_fixture["components"][4]["copyright"], "1990 Acme Inc"
        )
        self.assertEqual(
            self.sbom_fixture["components"][5]["copyright"], "1990 Acme Inc"
        )

    def test_add_copyright_to_all_several_updates(self) -> None:
        updates: Sequence[dict[str, Any]] = [
            {
                "id": {
                    "name": "web-framework",
                    "group": "org.acme",
                    "version": ">3.0.0",
                },
                "set": {"copyright": "1990 Acme Inc"},
            },
            {
                "id": {
                    "name": "web-framework",
                    "group": "org.acme",
                    "version": "<=3.0.0",
                },
                "set": {"copyright": "2000 Acme Inc"},
            },
            {
                "id": {
                    "name": "web-framework",
                    "group": "org.acme",
                    "version": "<2.0.0|>4.0.0",
                },
                "set": {
                    "supplier": {"name": "New supplier"},
                },
            },
        ]
        cfg = cdxev.set.SetConfig(
            True,
            False,
            [
                pathlib.Path(
                    "tests/auxiliary/test_set_sboms/Acme_Application_"
                    "9.1.1_ec7781220ec7781220ec778122012345_20220217T101458.cdx.json"
                )
            ],
            None,
        )

        cdxev.set.run(self.sbom_fixture, updates, cfg)
        self.assertEqual(
            self.sbom_fixture["components"][3]["copyright"], "1990 Acme Inc"
        )
        self.assertEqual(
            self.sbom_fixture["components"][4]["copyright"], "1990 Acme Inc"
        )
        self.assertEqual(
            self.sbom_fixture["components"][5]["copyright"], "1990 Acme Inc"
        )

        self.assertEqual(
            self.sbom_fixture["components"][0]["copyright"], "2000 Acme Inc"
        )
        self.assertEqual(
            self.sbom_fixture["components"][1]["copyright"], "2000 Acme Inc"
        )
        self.assertEqual(
            self.sbom_fixture["components"][2]["copyright"], "2000 Acme Inc"
        )

        self.assertEqual(
            self.sbom_fixture["components"][0]["supplier"], {"name": "New supplier"}
        )
        self.assertEqual(
            self.sbom_fixture["components"][4]["supplier"], {"name": "New supplier"}
        )
        self.assertEqual(
            self.sbom_fixture["components"][5]["supplier"], {"name": "New supplier"}
        )

    def test_custom_versions(self) -> None:
        path_to_version_file = pathlib.Path("tests/auxiliary/custom_version_list.json")
        cfg = cdxev.set.SetConfig(
            True,
            False,
            [
                pathlib.Path(
                    "tests/auxiliary/test_set_sboms/Acme_Application_"
                    "9.1.1_ec7781220ec7781220ec778122012345_20220217T101458.cdx.json"
                )
            ],
            None,
            False,
            custom_versions=path_to_version_file,
        )
        updates = [
            {
                "id": {
                    "name": "web-framework",
                    "group": "org.acme",
                    "version": ">=Natty Narwhal",
                },
                "set": {"copyright": "1990 Acme Inc"},
            }
        ]
        version_names = [
            "Bionic Beaver",
            "Maverick Meerkat",
            "Natty Narwhal",
            "Oneiric Ocelot",
            "Precise Pangolin",
            "Intrepid Ibex",
        ]
        self.sbom_fixture["components"][5]["copyright"] = "Public domain"
        self.sbom_fixture["components"][1]["copyright"] = "Public domain"
        for index, component in enumerate(self.sbom_fixture["components"]):
            component["version"] = version_names[index]

        cdxev.set.run(self.sbom_fixture, updates, cfg)
        self.assertEqual(
            self.sbom_fixture["components"][0]["copyright"], "1990 Acme Inc"
        )
        self.assertEqual(
            self.sbom_fixture["components"][1]["copyright"], "Public domain"
        )
        self.assertEqual(
            self.sbom_fixture["components"][2]["copyright"], "1990 Acme Inc"
        )

        self.assertEqual(
            self.sbom_fixture["components"][3]["copyright"], "1990 Acme Inc"
        )
        self.assertEqual(
            self.sbom_fixture["components"][4]["copyright"], "1990 Acme Inc"
        )
        self.assertEqual(
            self.sbom_fixture["components"][5]["copyright"], "Public domain"
        )
