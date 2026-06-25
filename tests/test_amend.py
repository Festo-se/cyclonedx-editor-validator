# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import typing as t
import unittest
from pathlib import Path
from unittest.mock import patch

from cdxev.amend.command import run as run_amend
from cdxev.amend.operations import (
    AddBomRef,
    AddLicenseText,
    CleanupSelfReferences,
    Compositions,
    DefaultAuthor,
    DeleteAmbiguousLicenses,
    InferSupplier,
    LicenseNameToId,
    Operation,
)
from cdxev.error import AppError

path_to_folder_with_test_sboms = "tests/auxiliary/test_amend_sboms/"


class AmendTestCase(unittest.TestCase):
    operation: Operation

    def setUp(self) -> None:
        with open(path_to_folder_with_test_sboms + "test.cdx.json", encoding="utf_8_sig") as file:
            self.sbom_fixture = json.load(file)

    def test_no_metadata_component_doesnt_raise(self) -> None:
        if not hasattr(self, "operation"):
            self.skipTest("Skipped on abstract base test case")

        del self.sbom_fixture["metadata"]["component"]
        self.operation.handle_metadata(self.sbom_fixture["metadata"])

    def test_empty_component_doesnt_raise(self) -> None:
        if not hasattr(self, "operation"):
            self.skipTest("Skipped on abstract base test case")

        self.operation.handle_component({})


class CompositionsTestCase(AmendTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.operation = Compositions()

    def test_compositions_cleared(self) -> None:
        self.operation.prepare(self.sbom_fixture)
        self.assertSequenceEqual(
            self.sbom_fixture["compositions"],
            [{"aggregate": "unknown", "assemblies": []}],
        )

    def test_meta_component_keeps_aggregate(self) -> None:
        self.operation.prepare(self.sbom_fixture)
        self.operation.handle_metadata(self.sbom_fixture["metadata"])
        self.assertTrue(
            any(
                comp["aggregate"] == "not_specified"
                and comp["assemblies"] == ["pkg:npm/test-app@1.0.0"]
                for comp in self.sbom_fixture["compositions"]
            )
        )

    def test_meta_component_keeps_unknown_aggregate(self) -> None:
        self.sbom_fixture["compositions"][2]["aggregate"] = "unknown"
        self.operation.prepare(self.sbom_fixture)
        self.operation.handle_metadata(self.sbom_fixture["metadata"])

        self.assertTrue(
            self.sbom_fixture["metadata"]["component"]["bom-ref"]
            in self.sbom_fixture["compositions"][0]["assemblies"]
        )

    def test_meta_component_missing(self) -> None:
        del self.sbom_fixture["metadata"]["component"]
        self.operation.prepare(self.sbom_fixture)
        self.operation.handle_metadata(self.sbom_fixture["metadata"])

        # Assert that all compositions are empty
        self.assertFalse(any(comp["assemblies"] for comp in self.sbom_fixture["compositions"]))

    def test_meta_component_not_in_compositions(self) -> None:
        del self.sbom_fixture["compositions"][2]
        self.operation.prepare(self.sbom_fixture)
        self.operation.handle_metadata(self.sbom_fixture["metadata"])

        # Assert that all compositions are empty
        self.assertFalse(any(comp["assemblies"] for comp in self.sbom_fixture["compositions"]))

    def test_components_added(self) -> None:
        self.operation.prepare(self.sbom_fixture)
        flat_walk_components(self.operation, self.sbom_fixture["components"])

        self.assertEqual(self.sbom_fixture["compositions"][0]["aggregate"], "unknown")
        self.assertSequenceEqual(
            self.sbom_fixture["compositions"][0]["assemblies"],
            ["com.company.unit/depA@4.0.2", "some-vendor/depB@1.2.3", "depC@3.2.1"],
        )


class DefaultAuthorTestCase(AmendTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.operation = DefaultAuthor()

    def test_default_author_added(self) -> None:
        self.operation.handle_metadata(self.sbom_fixture["metadata"])
        self.assertSequenceEqual(self.sbom_fixture["metadata"]["authors"], [{"name": "automated"}])

    def test_existing_author_untouched(self) -> None:
        some_author = {"name": "My Name"}
        self.sbom_fixture["metadata"]["authors"] = [some_author]
        self.operation.handle_metadata(self.sbom_fixture["metadata"])
        self.assertSequenceEqual(self.sbom_fixture["metadata"]["authors"], [some_author])


class InferSupplierTestCase(AmendTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.operation = InferSupplier()

    def test_no_inferral_possible(self) -> None:
        component: dict[str, t.Any] = {}
        expected: dict[str, t.Any] = {}
        self.operation.handle_component(component)
        self.assertDictEqual(expected, component)

    def test_author_already_present(self) -> None:
        component = {"author": "x"}
        expected = {"author": "x", "supplier": {"name": "x"}}
        self.operation.handle_component(component)
        self.assertDictEqual(expected, component)

    def test_supplier_already_present(self) -> None:
        component = {"author": "x", "supplier": {"name": "y"}}
        expected = copy.deepcopy(component)
        self.operation.handle_component(component)
        self.assertDictEqual(expected, component)

    def test_publisher_is_preferred_to_author(self) -> None:
        component = {"author": "x", "publisher": "y"}
        expected = {"author": "x", "supplier": {"name": "y"}, "publisher": "y"}
        self.operation.handle_component(component)
        self.assertDictEqual(expected, component)

    def test_empty_component_stays_empty(self):
        component = {}
        expected = {}
        self.operation.handle_component(component)
        self.assertDictEqual(component, expected)

    def test_author_set_supplier_in_metadata(self) -> None:
        expected = copy.deepcopy(self.sbom_fixture["metadata"]["component"])
        expected["supplier"] = {"url": ["https://www.company.org"]}
        run_amend(self.sbom_fixture)

        self.assertEqual(
            self.sbom_fixture["metadata"]["component"],
            expected,
        )

    def test_supplier_from_website(self) -> None:
        component = {
            "externalReferences": [
                {"type": "vcs", "url": "https://y.com"},
                {"type": "website", "url": "https://x.com"},
            ]
        }
        expected = copy.deepcopy(component) | {"supplier": {"url": ["https://x.com"]}}
        self.operation.handle_component(component)
        self.assertDictEqual(expected, component)

    def test_supplier_from_issue_tracker(self) -> None:
        component = {
            "externalReferences": [
                {"type": "vcs", "url": "https://y.com"},
                {"type": "issue-tracker", "url": "https://x.com"},
            ]
        }
        expected = copy.deepcopy(component) | {"supplier": {"url": ["https://x.com"]}}
        self.operation.handle_component(component)
        self.assertDictEqual(expected, component)

    def test_supplier_from_vcs(self) -> None:
        component = {
            "externalReferences": [
                {"type": "vcs", "url": "https://y.com"},
                {"type": "issue-tracker", "url": "ssh://x.com"},
            ]
        }
        expected = copy.deepcopy(component) | {"supplier": {"url": ["https://y.com"]}}
        self.operation.handle_component(component)
        self.assertDictEqual(expected, component)

    def test_add_name_and_url(self) -> None:
        component = {
            "author": "Author",
            "externalReferences": [
                {"type": "vcs", "url": "https://y.com"},
                {"type": "website", "url": "https://x.com"},
            ],
        }
        expected = copy.deepcopy(component) | {
            "supplier": {"name": "Author", "url": ["https://x.com"]}
        }
        self.operation.handle_component(component)
        self.assertDictEqual(expected, component)


class AddBomRefTestCase(AmendTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.operation = AddBomRef()

    def test_add_bom_ref_to_metadata(self) -> None:
        metadata = {"component": {"type": "application", "name": "test"}}

        self.operation.handle_metadata(metadata)

    def test_add_bom_ref_to_component(self) -> None:
        components = [
            {"type": "library", "name": "compA"},
            {"type": "library", "name": "compB"},
        ]

        flat_walk_components(self.operation, components)

        self.assertIn("bom-ref", components[0])
        self.assertIn("bom-ref", components[1])
        self.assertGreater(len(components[0]["bom-ref"]), 0)
        self.assertGreater(len(components[1]["bom-ref"]), 0)
        self.assertNotEqual(components[0]["bom-ref"], components[1]["bom-ref"])

    def test_dont_overwrite(self) -> None:
        component = {"type": "library", "name": "comp", "bom-ref": "already-present"}

        self.operation.handle_component(component)

        self.assertEqual("already-present", component["bom-ref"])


class LicenseNameToIdTestCase(AmendTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.operation = LicenseNameToId()
        self.operation.prepare(self.sbom_fixture)

    def test_replace_name_with_id(self) -> None:
        component = {
            "licenses": [
                {"license": {"name": "Apache License"}},
                {"license": {"name": "GNU Lesser General Public License, Version 2.1"}},
                {"license": {"name": "Some random name"}},
            ]
        }
        expected = {
            "licenses": [
                {"license": {"id": "Apache-1.0"}},
                {"license": {"id": "LGPL-2.1-only"}},
                {"license": {"name": "Some random name"}},
            ]
        }
        self.operation.handle_component(component)
        self.assertDictEqual(component, expected)

    def test_no_name_and_no_id_in_license_doesnt_raise(self) -> None:
        self.sbom_fixture["components"][0]["licenses"] = [{}]
        self.operation.handle_component(self.sbom_fixture["components"][0])


def flat_walk_components(operation: Operation, components: t.Sequence[dict[str, t.Any]]) -> None:
    """
    Test-helper which applies an operation to a flat sequence of components. subcomponents are
    ignored.
    """
    for c in components:
        operation.handle_component(c)


class AddLicenseTextTestCase(AmendTestCase):
    def setUp(self) -> None:
        super().setUp()
        license_dir = Path("tests/auxiliary/licenses")
        self.operation = AddLicenseText(license_dir)
        self.operation.prepare(self.sbom_fixture)

    def test_add_text(self):
        component = {
            "licenses": [
                {"license": {"id": "Apache-1.0"}},
                {"license": {"name": "license_name"}},
            ]
        }
        expected = {
            "licenses": [
                {"license": {"id": "Apache-1.0"}},
                {
                    "license": {
                        "name": "license_name",
                        "text": {"content": "The text describing a license."},
                    }
                },
            ]
        }
        self.operation.handle_component(component)
        self.assertDictEqual(component, expected)

    def test_keep_existing_text(self):
        component = {
            "licenses": [
                {"license": {"name": "license_name", "text": {"content": "My text."}}},
            ]
        }
        expected = copy.deepcopy(component)
        self.operation.handle_component(component)
        self.assertDictEqual(component, expected)

    def test_file_extension_ignored(self):
        component = {
            "licenses": [
                {"license": {"name": "another license"}},
                {"license": {"name": "license_name"}},
            ]
        }
        expected = {
            "licenses": [
                {
                    "license": {
                        "name": "another license",
                        "text": {"content": "The text describing another license."},
                    }
                },
                {
                    "license": {
                        "name": "license_name",
                        "text": {"content": "The text describing a license."},
                    }
                },
            ]
        }
        self.operation.handle_component(component)
        self.assertDictEqual(component, expected)

    def test_name_is_case_insensitive(self):
        component = {
            "licenses": [
                {"license": {"name": "ANOTHER license"}},
                {"license": {"name": "uppercase"}},
            ]
        }
        expected = {
            "licenses": [
                {
                    "license": {
                        "name": "ANOTHER license",
                        "text": {"content": "The text describing another license."},
                    }
                },
                {
                    "license": {
                        "name": "uppercase",
                        "text": {"content": "UPPERCASE LICENSE"},
                    }
                },
            ]
        }
        self.operation.handle_component(component)
        self.assertDictEqual(component, expected)

    def test_invalid_license_dir_raises(self):
        operation = AddLicenseText(Path("somethingthatsurelydoesntexist"))
        with self.assertRaises(AppError):
            operation.prepare(self.sbom_fixture)

    def test_find_text_returns_none_for_unknown_license(self):
        self.assertIsNone(self.operation._find_text("does-not-exist"))

    def test_find_text_raises_if_encoding_cannot_be_detected(self):
        with patch("cdxev.amend.operations.charset_normalizer.from_path") as mocked:
            mocked.return_value.best.return_value = None
            with self.assertRaises(ValueError):
                self.operation._find_text("license_name")

    def test_handle_metadata_adds_license_text(self):
        metadata = {
            "component": {
                "name": "meta",
                "licenses": [{"license": {"name": "license_name"}}],
            }
        }
        self.operation.handle_metadata(metadata)
        self.assertEqual(
            "The text describing a license.",
            metadata["component"]["licenses"][0]["license"]["text"]["content"],
        )


class DeleteAmbiguousLicensesTestCase(AmendTestCase):
    def setUp(self):
        super().setUp()
        self.operation = DeleteAmbiguousLicenses()
        self.component = self.sbom_fixture["components"][0]

    def test_delete_one_license_in_set(self):
        self.component["licenses"] = [
            {"license": {"id": "Apache-2.0"}},
            {"license": {"name": "Some license"}},
        ]
        expected = copy.deepcopy(self.component)
        expected["licenses"] = [{"license": {"id": "Apache-2.0"}}]

        self.operation.handle_component(self.component)
        self.assertDictEqual(self.component, expected)

    def test_delete_sole_license(self):
        self.component["licenses"] = [
            {"license": {"name": "Some license"}},
        ]
        expected = copy.deepcopy(self.component)
        del expected["licenses"]

        self.operation.handle_component(self.component)
        self.assertDictEqual(self.component, expected)

    def test_delete_multiple_licenses(self):
        self.component["licenses"] = [
            {"license": {"name": "Some license"}},
            {"license": {"id": "Apache-2.0"}},
            {
                "license": {
                    "name": "License with text",
                    "text": {"content": "Full text"},
                }
            },
            {"license": {"name": "Foo license"}},
            {"license": {"name": "Bar license"}},
        ]
        expected = copy.deepcopy(self.component)
        expected["licenses"] = [
            {"license": {"id": "Apache-2.0"}},
            {
                "license": {
                    "name": "License with text",
                    "text": {"content": "Full text"},
                }
            },
        ]

        self.operation.handle_component(self.component)
        self.assertDictEqual(self.component, expected)

    def test_dont_delete_id(self):
        self.component["licenses"] = [
            {"license": {"id": "Apache-2.0"}},
        ]
        expected = copy.deepcopy(self.component)

        self.operation.handle_component(self.component)
        self.assertDictEqual(self.component, expected)

    def test_dont_delete_expression(self):
        self.component["licenses"] = [
            {"expression": "Apache-2.0 AND (MIT OR GPL-2.0-only)"},
        ]
        expected = copy.deepcopy(self.component)

        self.operation.handle_component(self.component)
        self.assertDictEqual(self.component, expected)

    def test_dont_delete_name_with_text(self):
        self.component["licenses"] = [
            {"license": {"name": "Some license", "text": {"content": "Full text"}}},
        ]
        expected = copy.deepcopy(self.component)

        self.operation.handle_component(self.component)
        self.assertDictEqual(self.component, expected)

    def test_dont_delete_name_with_url(self):
        self.component["licenses"] = [
            {"license": {"name": "Some license", "url": "https://example.org/license"}},
        ]
        expected = copy.deepcopy(self.component)

        self.operation.handle_component(self.component)
        self.assertDictEqual(self.component, expected)

    def test_handle_metadata_filters_metadata_component_licenses(self):
        metadata = {
            "component": {
                "licenses": [
                    {"license": {"name": "Some license"}},
                    {"license": {"id": "MIT"}},
                ]
            }
        }
        self.operation.handle_metadata(metadata)
        self.assertEqual([{"license": {"id": "MIT"}}], metadata["component"]["licenses"])


class CleanupSelfReferencesTestCase(AmendTestCase):
    def setUp(self):
        super().setUp()
        self.operation = CleanupSelfReferences()

    def test_remove_duplicate_metadata_component_and_fix_references(self):
        self.sbom_fixture["metadata"]["component"] = {
            "type": "application",
            "name": "test-app",
            "version": "1.0.0",
            "purl": "pkg:npm/test-app@1.0.0",
            "bom-ref": "meta-ref",
            "licenses": [{"license": {"id": "MIT"}}],
        }
        self.sbom_fixture["components"] = [
            {
                "type": "application",
                "name": "test-app",
                "version": "1.0.0",
                "purl": "pkg:npm/test-app@1.0.0",
                "bom-ref": "legacy-ref",
                "externalReferences": [{"type": "website", "url": "https://example.org"}],
            },
            {
                "type": "library",
                "name": "depA",
                "version": "1.0.0",
                "bom-ref": "dep-a",
            },
        ]
        self.sbom_fixture["dependencies"] = [
            {"ref": "legacy-ref", "dependsOn": ["dep-a", "legacy-ref", "dep-a"]},
            {"ref": "meta-ref", "dependsOn": ["legacy-ref", "dangling-ref"]},
            {"ref": "dep-a", "dependsOn": ["legacy-ref"]},
            {"ref": "dangling-ref", "dependsOn": ["meta-ref"]},
        ]
        self.sbom_fixture["compositions"] = [
            {
                "aggregate": "complete",
                "assemblies": ["legacy-ref", "meta-ref", "legacy-ref", "dangling-ref"],
            }
        ]
        self.sbom_fixture["vulnerabilities"] = [
            {
                "id": "CVE-2024-0001",
                "affects": [
                    {"ref": "legacy-ref", "versions": [{"version": "1.0.0"}]},
                    {"ref": "legacy-ref", "versions": [{"version": "2.0.0"}]},
                    {"ref": "dep-a"},
                    {"ref": "dangling-ref"},
                ],
            }
        ]

        self.operation.prepare(self.sbom_fixture)

        self.assertFalse(
            any(
                component.get("bom-ref") == "legacy-ref"
                for component in self.sbom_fixture["components"]
            )
        )
        metadata_component = self.sbom_fixture["metadata"]["component"]
        self.assertEqual("meta-ref", metadata_component["bom-ref"])
        self.assertEqual("application", metadata_component["type"])
        self.assertIn(
            {"type": "website", "url": "https://example.org"},
            metadata_component["externalReferences"],
        )

        self.assertEqual(
            [
                {"ref": "meta-ref", "dependsOn": ["dep-a", "dangling-ref"]},
                {"ref": "dep-a", "dependsOn": ["meta-ref"]},
                {"ref": "dangling-ref", "dependsOn": ["meta-ref"]},
            ],
            self.sbom_fixture["dependencies"],
        )
        self.assertEqual(
            [
                {
                    "aggregate": "complete",
                    "assemblies": ["meta-ref", "dangling-ref"],
                }
            ],
            self.sbom_fixture["compositions"],
        )
        self.assertEqual(
            [
                {
                    "ref": "meta-ref",
                    "versions": [{"version": "1.0.0"}, {"version": "2.0.0"}],
                },
                {"ref": "dep-a"},
                {"ref": "dangling-ref"},
            ],
            self.sbom_fixture["vulnerabilities"][0]["affects"],
        )

    def test_keep_component_with_conflicting_strong_identity(self):
        self.sbom_fixture["metadata"]["component"] = {
            "type": "application",
            "name": "test-app",
            "version": "1.0.0",
            "purl": "pkg:npm/test-app@1.0.0",
            "bom-ref": "meta-ref",
        }
        conflicting_component = {
            "type": "application",
            "name": "test-app",
            "version": "1.0.0",
            "purl": "pkg:npm/test-app@2.0.0",
            "bom-ref": "other-ref",
        }
        self.sbom_fixture["components"] = [conflicting_component]

        self.operation.prepare(self.sbom_fixture)

        self.assertEqual([conflicting_component], self.sbom_fixture["components"])

    def test_no_duplicate_component_leaves_sbom_unchanged(self):
        original = copy.deepcopy(self.sbom_fixture)

        self.operation.prepare(self.sbom_fixture)

        self.assertEqual(original, self.sbom_fixture)

    def test_nested_duplicate_is_removed(self):
        self.sbom_fixture["metadata"]["component"] = {
            "type": "application",
            "name": "root-app",
            "version": "1.0.0",
            "purl": "pkg:npm/root-app@1.0.0",
            "bom-ref": "meta-ref",
        }
        self.sbom_fixture["components"] = [
            {
                "type": "library",
                "name": "wrapper",
                "version": "1.0.0",
                "bom-ref": "wrapper-ref",
                "components": [
                    {
                        "type": "application",
                        "name": "root-app",
                        "version": "1.0.0",
                        "purl": "pkg:npm/root-app@1.0.0",
                        "bom-ref": "legacy-ref",
                        "licenses": [{"license": {"id": "MIT"}}],
                    }
                ],
            }
        ]
        self.sbom_fixture["dependencies"] = [
            {"ref": "wrapper-ref", "dependsOn": ["legacy-ref"]},
            {"ref": "legacy-ref", "dependsOn": []},
        ]

        self.operation.prepare(self.sbom_fixture)

        nested = self.sbom_fixture["components"][0]["components"]
        self.assertEqual([], nested)
        self.assertEqual(
            [
                {"ref": "wrapper-ref", "dependsOn": ["meta-ref"]},
                {"ref": "meta-ref", "dependsOn": []},
            ],
            self.sbom_fixture["dependencies"],
        )
        self.assertEqual(
            [{"license": {"id": "MIT"}}],
            self.sbom_fixture["metadata"]["component"]["licenses"],
        )

    def test_missing_metadata_component_noop(self):
        del self.sbom_fixture["metadata"]["component"]
        original = copy.deepcopy(self.sbom_fixture)

        self.operation.prepare(self.sbom_fixture)

        self.assertEqual(original, self.sbom_fixture)

    def test_missing_metadata_bom_ref_is_generated_and_used(self):
        self.sbom_fixture["metadata"]["component"] = {
            "type": "application",
            "name": "root-app",
            "version": "1.0.0",
            "purl": "pkg:npm/root-app@1.0.0",
        }
        self.sbom_fixture["components"] = [
            {
                "type": "application",
                "name": "root-app",
                "version": "1.0.0",
                "purl": "pkg:npm/root-app@1.0.0",
                "bom-ref": "legacy-ref",
            },
            {
                "type": "library",
                "name": "depA",
                "version": "1.0.0",
                "bom-ref": "dep-a",
            },
        ]
        self.sbom_fixture["dependencies"] = [
            {"ref": "dep-a", "dependsOn": ["legacy-ref"]},
        ]

        self.operation.prepare(self.sbom_fixture)

        metadata_ref = self.sbom_fixture["metadata"]["component"].get("bom-ref")
        self.assertIsInstance(metadata_ref, str)
        self.assertNotEqual("", metadata_ref)
        self.assertEqual(
            [{"ref": "dep-a", "dependsOn": [metadata_ref]}],
            self.sbom_fixture["dependencies"],
        )

    def test_keeps_non_empty_metadata_scalar_values(self):
        self.sbom_fixture["metadata"]["component"] = {
            "type": "application",
            "name": "root-app",
            "version": "1.0.0",
            "purl": "pkg:npm/root-app@1.0.0",
            "bom-ref": "meta-ref",
            "publisher": "Preferred Publisher",
        }
        self.sbom_fixture["components"] = [
            {
                "type": "application",
                "name": "root-app",
                "version": "1.0.0",
                "purl": "pkg:npm/root-app@1.0.0",
                "bom-ref": "legacy-ref",
                "publisher": "Legacy Publisher",
            }
        ]

        self.operation.prepare(self.sbom_fixture)

        self.assertEqual(
            "Preferred Publisher",
            self.sbom_fixture["metadata"]["component"]["publisher"],
        )

    def test_handles_malformed_dependency_composition_and_vulnerability_sections(self):
        self.sbom_fixture["metadata"]["component"] = {
            "type": "application",
            "name": "root-app",
            "version": "1.0.0",
            "purl": "pkg:npm/root-app@1.0.0",
            "bom-ref": "meta-ref",
        }
        self.sbom_fixture["components"] = [
            {
                "type": "application",
                "name": "root-app",
                "version": "1.0.0",
                "purl": "pkg:npm/root-app@1.0.0",
                "bom-ref": "legacy-ref",
            }
        ]
        self.sbom_fixture["dependencies"] = [
            {"ref": "legacy-ref", "dependsOn": "invalid"},
            {"ref": "meta-ref", "dependsOn": [1, "legacy-ref", "meta-ref"]},
            {"ref": 12, "dependsOn": ["legacy-ref"]},
        ]
        self.sbom_fixture["compositions"] = [
            {"aggregate": "unknown", "assemblies": "invalid"},
            {"aggregate": "incomplete", "assemblies": ["legacy-ref", 3, "meta-ref"]},
        ]
        self.sbom_fixture["vulnerabilities"] = [
            {
                "id": "CVE-2024-0002",
                "affects": "invalid",
            },
            {
                "id": "CVE-2024-0003",
                "affects": [
                    {"ref": "legacy-ref", "versions": [{"version": "1.0.0"}]},
                    {"ref": "legacy-ref", "versions": [{"version": "2.0.0"}]},
                    {"ref": "unknown"},
                    {"ref": 123},
                ],
            },
        ]

        self.operation.prepare(self.sbom_fixture)

        self.assertEqual(
            [
                {"ref": "meta-ref", "dependsOn": "invalid"},
                {"ref": "meta-ref", "dependsOn": [1]},
                {"ref": 12, "dependsOn": ["meta-ref"]},
            ],
            self.sbom_fixture["dependencies"],
        )
        self.assertEqual(
            "invalid",
            self.sbom_fixture["compositions"][0]["assemblies"],
        )
        self.assertEqual(
            ["meta-ref", 3],
            self.sbom_fixture["compositions"][1]["assemblies"],
        )
        self.assertEqual(
            [
                {
                    "ref": "meta-ref",
                    "versions": [{"version": "1.0.0"}, {"version": "2.0.0"}],
                },
                {"ref": "unknown"},
                {"ref": 123},
            ],
            self.sbom_fixture["vulnerabilities"][1]["affects"],
        )

    def test_preserve_orphaned_and_invalid_refs(self):
        self.sbom_fixture["metadata"]["component"] = {
            "type": "application",
            "name": "root-app",
            "version": "1.0.0",
            "purl": "pkg:npm/root-app@1.0.0",
            "bom-ref": "meta-ref",
        }
        self.sbom_fixture["components"] = [
            {
                "type": "application",
                "name": "root-app",
                "version": "1.0.0",
                "purl": "pkg:npm/root-app@1.0.0",
                "bom-ref": "legacy-ref",
            },
            {
                "type": "library",
                "name": "depA",
                "version": "1.0.0",
                "bom-ref": "dep-a",
            },
        ]
        self.sbom_fixture["dependencies"] = [
            {"ref": "legacy-ref", "dependsOn": ["legacy-ref", "dep-a", "orphan-ref"]},
            {"ref": "dep-a", "dependsOn": ["legacy-ref", "orphan-ref"]},
            {"ref": "orphan-ref", "dependsOn": ["legacy-ref"]},
            {"ref": 7, "dependsOn": ["legacy-ref"]},
        ]
        self.sbom_fixture["compositions"] = [
            {"aggregate": "complete", "assemblies": ["legacy-ref", "orphan-ref"]}
        ]
        self.sbom_fixture["vulnerabilities"] = [
            {
                "id": "CVE-2024-1234",
                "affects": [{"ref": "legacy-ref"}, {"ref": "orphan-ref"}, {"ref": 12}],
            }
        ]

        self.operation.prepare(self.sbom_fixture)

        self.assertEqual(
            [
                {"ref": "meta-ref", "dependsOn": ["dep-a", "orphan-ref"]},
                {"ref": "dep-a", "dependsOn": ["meta-ref", "orphan-ref"]},
                {"ref": "orphan-ref", "dependsOn": ["meta-ref"]},
                {"ref": 7, "dependsOn": ["meta-ref"]},
            ],
            self.sbom_fixture["dependencies"],
        )
        self.assertEqual(
            [{"aggregate": "complete", "assemblies": ["meta-ref", "orphan-ref"]}],
            self.sbom_fixture["compositions"],
        )
        self.assertEqual(
            [
                {
                    "id": "CVE-2024-1234",
                    "affects": [{"ref": "meta-ref"}, {"ref": "orphan-ref"}, {"ref": 12}],
                }
            ],
            self.sbom_fixture["vulnerabilities"],
        )

    def test_private_helpers_cover_edge_branches(self):
        op = self.operation

        self.assertEqual("x", op._normalize_value(" X "))
        self.assertEqual('{"a": 1}', op._normalize_value({"a": 1}))
        self.assertEqual([1], op._normalize_value([1]))

        self.assertTrue(op._is_empty(None))
        self.assertTrue(op._is_empty([]))
        self.assertFalse(op._is_empty(0))
        self.assertEqual("7", op._item_key(7))

        self.assertFalse(op._is_duplicate_of_metadata({}, {}))

        target = {"nested": {"x": ""}, "arr": [{"k": 1}], "publisher": "", "keep": "yes"}
        source = {
            "nested": {"x": "v"},
            "arr": [{"k": 1}, {"k": 2}],
            "publisher": "pub",
            "keep": "no",
        }
        op._merge_component_data(target, source)
        self.assertEqual("v", target["nested"]["x"])
        self.assertEqual([{"k": 1}, {"k": 2}], target["arr"])
        self.assertEqual("pub", target["publisher"])
        self.assertEqual("yes", target["keep"])

    def test_replace_helpers_short_circuit_and_targeted_cleanup(self):
        op = self.operation

        sbom_dependencies: dict[str, t.Any] = {"dependencies": []}
        op._replace_ref_in_dependencies(sbom_dependencies, "same", "same")
        self.assertEqual([], sbom_dependencies["dependencies"])

        sbom_dependencies = {
            "dependencies": [
                {"ref": "a", "dependsOn": ["legacy", "legacy", "b"]},
            ]
        }
        op._replace_ref_in_dependencies(sbom_dependencies, "legacy", "meta")
        self.assertEqual(
            [{"ref": "a", "dependsOn": ["meta", "b"]}],
            sbom_dependencies["dependencies"],
        )

        sbom_dependencies = {"dependencies": {"ref": "x"}}
        op._replace_ref_in_dependencies(sbom_dependencies, "legacy", "meta")
        self.assertEqual({"ref": "x"}, sbom_dependencies["dependencies"])

        sbom_compositions: dict[str, t.Any] = {"compositions": []}
        op._replace_ref_in_compositions(sbom_compositions, "same", "same")
        self.assertEqual([], sbom_compositions["compositions"])

        sbom_compositions = {"compositions": {"assemblies": ["legacy"]}}
        op._replace_ref_in_compositions(sbom_compositions, "legacy", "meta")
        self.assertEqual({"assemblies": ["legacy"]}, sbom_compositions["compositions"])

        sbom_vuln: dict[str, t.Any] = {"vulnerabilities": []}
        op._replace_ref_in_vulnerabilities(sbom_vuln, "same", "same")
        self.assertEqual([], sbom_vuln["vulnerabilities"])

        sbom_vuln = {
            "vulnerabilities": [
                {"affects": [{"ref": "other"}]},
                {"affects": "invalid"},
            ]
        }
        op._replace_ref_in_vulnerabilities(sbom_vuln, "legacy", "meta")
        self.assertEqual(
            [{"affects": [{"ref": "other"}]}, {"affects": "invalid"}],
            sbom_vuln["vulnerabilities"],
        )

    def test_merge_helpers_branch_coverage(self):
        op = self.operation

        affects: list[t.Any] = [
            {"ref": "meta"},
            {"ref": "meta", "versions": [{"version": "1.0.0"}]},
            {"ref": "other"},
        ]
        op._merge_affects_for_ref(affects, "meta")
        self.assertEqual(
            [
                {"ref": "meta", "versions": [{"version": "1.0.0"}]},
                {"ref": "other"},
            ],
            affects,
        )

        sbom: dict[str, t.Any] = {"dependencies": {"ref": "x"}}
        op._merge_dependencies_for_ref(sbom, "x")
        self.assertEqual({"ref": "x"}, sbom["dependencies"])

        sbom = {
            "dependencies": [
                {"ref": "meta", "dependsOn": ["meta", "a"]},
                {"ref": "meta", "dependsOn": ["b"]},
                {"ref": "other", "dependsOn": ["meta"]},
            ]
        }
        op._merge_dependencies_for_ref(sbom, "meta")
        self.assertEqual(
            [
                {"ref": "meta", "dependsOn": ["a", "b"]},
                {"ref": "other", "dependsOn": ["meta"]},
            ],
            sbom["dependencies"],
        )


if __name__ == "__main__":
    unittest.main()
