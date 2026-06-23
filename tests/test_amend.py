# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import typing as t
import unittest
from pathlib import Path

from cdxev.amend.command import run as run_amend
from cdxev.amend.operations import (
    AddBomRef,
    AddLicenseText,
    Compositions,
    DefaultAuthor,
    DeleteAmbiguousLicenses,
    HierarchicalBomRefs,
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


def _iter_components(components: t.Sequence[dict]) -> t.Iterator[dict]:
    for component in components:
        yield component
        yield from _iter_components(component.get("components", []))


def _collect_known_bom_refs(sbom: dict) -> set[str]:
    refs = {
        component["bom-ref"]
        for component in _iter_components(sbom.get("components", []))
        if component.get("bom-ref", "")
    }
    metadata_component = sbom.get("metadata", {}).get("component", {})
    metadata_ref = metadata_component.get("bom-ref", "")
    if metadata_ref:
        refs.add(metadata_ref)
    return refs


def _assert_no_dangling_refs(sbom: dict) -> None:
    known_refs = _collect_known_bom_refs(sbom)

    for dependency in sbom.get("dependencies", []):
        reference = dependency.get("ref", "")
        if reference:
            assert reference in known_refs, f"Dangling dependency ref: {reference}"
        for depends_on_ref in dependency.get("dependsOn", []):
            assert depends_on_ref in known_refs, f"Dangling dependsOn ref: {depends_on_ref}"

    for composition in sbom.get("compositions", []):
        for assembly_ref in composition.get("assemblies", []):
            assert assembly_ref in known_refs, f"Dangling composition assembly ref: {assembly_ref}"

    for vulnerability in sbom.get("vulnerabilities", []):
        for affected in vulnerability.get("affects", []):
            affected_ref = affected.get("ref", "")
            if affected_ref:
                assert affected_ref in known_refs, f"Dangling vulnerability ref: {affected_ref}"


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


class HierarchicalBomRefsTestCase(unittest.TestCase):
    def test_multilevel_nesting(self) -> None:
        sbom = {
            "components": [
                {
                    "name": "app",
                    "components": [{"name": "lib", "components": [{"name": "core"}]}],
                }
            ]
        }

        run_amend(sbom, selected=[HierarchicalBomRefs])

        root = sbom["components"][0]
        child = root["components"][0]
        grandchild = child["components"][0]
        self.assertEqual("app", root["bom-ref"])
        self.assertEqual("app/lib", child["bom-ref"])
        self.assertEqual("app/lib/core", grandchild["bom-ref"])

    def test_metadata_component_as_root(self) -> None:
        sbom = {
            "metadata": {"component": {"name": "product"}},
            "components": [{"name": "app", "components": [{"name": "lib"}]}],
        }

        run_amend(sbom, selected=[HierarchicalBomRefs])

        self.assertEqual("product", sbom["metadata"]["component"]["bom-ref"])
        self.assertEqual("product/app", sbom["components"][0]["bom-ref"])
        self.assertEqual("product/app/lib", sbom["components"][0]["components"][0]["bom-ref"])

    def test_reference_rewriting(self) -> None:
        sbom = {
            "components": [
                {
                    "name": "app",
                    "bom-ref": "pkg:npm/app@1.0",
                    "components": [{"name": "lib", "bom-ref": "urn:uuid:sub-lib"}],
                }
            ],
            "dependencies": [
                {"ref": "urn:uuid:sub-lib", "dependsOn": ["pkg:npm/app@1.0"]},
            ],
            "compositions": [
                {
                    "aggregate": "complete",
                    "assemblies": ["urn:uuid:sub-lib", "pkg:npm/app@1.0"],
                }
            ],
            "vulnerabilities": [{"id": "CVE-1", "affects": [{"ref": "urn:uuid:sub-lib"}]}],
        }

        run_amend(sbom, selected=[HierarchicalBomRefs])

        self.assertEqual("app", sbom["components"][0]["bom-ref"])
        self.assertEqual("app/lib", sbom["components"][0]["components"][0]["bom-ref"])
        self.assertEqual("app/lib", sbom["dependencies"][0]["ref"])
        self.assertEqual(["app"], sbom["dependencies"][0]["dependsOn"])
        self.assertEqual(
            ["app/lib", "app"],
            sbom["compositions"][0]["assemblies"],
        )
        self.assertEqual("app/lib", sbom["vulnerabilities"][0]["affects"][0]["ref"])
        _assert_no_dangling_refs(sbom)

    def test_sibling_name_collision(self) -> None:
        sbom = {
            "components": [
                {
                    "name": "app",
                    "components": [{"name": "utils"}, {"name": "utils"}],
                }
            ]
        }

        run_amend(sbom, selected=[HierarchicalBomRefs])

        child_refs = [child["bom-ref"] for child in sbom["components"][0]["components"]]
        self.assertEqual(["app/utils", "app/utils-1"], child_refs)
        _assert_no_dangling_refs(sbom)

    def test_component_without_name_uses_fallback_leaf(self) -> None:
        sbom = {"components": [{"bom-ref": "old/ref with space"}, {}]}

        run_amend(sbom, selected=[HierarchicalBomRefs])

        first_ref = sbom["components"][0]["bom-ref"]
        second_ref = sbom["components"][1]["bom-ref"]
        self.assertEqual("old_ref_with_space", first_ref)
        self.assertNotEqual("", second_ref)
        self.assertFalse(second_ref.endswith("/"))
        self.assertNotEqual(first_ref, second_ref)

    def test_existing_purl_or_uuid_refs_are_overwritten(self) -> None:
        sbom = {
            "components": [
                {"name": "app", "bom-ref": "pkg:npm/foo@1.0"},
                {"name": "worker", "bom-ref": "550e8400-e29b-41d4-a716-446655440000"},
            ],
            "dependencies": [
                {"ref": "pkg:npm/foo@1.0", "dependsOn": ["550e8400-e29b-41d4-a716-446655440000"]}
            ],
        }

        run_amend(sbom, selected=[HierarchicalBomRefs])

        self.assertEqual("app", sbom["components"][0]["bom-ref"])
        self.assertEqual("worker", sbom["components"][1]["bom-ref"])
        self.assertEqual("app", sbom["dependencies"][0]["ref"])
        self.assertEqual(["worker"], sbom["dependencies"][0]["dependsOn"])
        _assert_no_dangling_refs(sbom)

    def test_sanitization_of_name(self) -> None:
        sbom = {"components": [{"name": "My App/Core"}]}

        run_amend(sbom, selected=[HierarchicalBomRefs])

        self.assertEqual("My_App_Core", sbom["components"][0]["bom-ref"])

    def test_idempotence(self) -> None:
        sbom = {
            "components": [
                {"name": "app", "components": [{"name": "lib"}]},
            ]
        }

        run_amend(sbom, selected=[HierarchicalBomRefs])
        first_run_refs = [
            component["bom-ref"]
            for component in _iter_components(sbom["components"])
        ]

        run_amend(sbom, selected=[HierarchicalBomRefs])
        second_run_refs = [
            component["bom-ref"]
            for component in _iter_components(sbom["components"])
        ]

        self.assertSequenceEqual(first_run_refs, second_run_refs)
        self.assertNotIn("app/app/lib", second_run_refs)

    def test_flat_sbom(self) -> None:
        sbom = {"components": [{"name": "app"}, {"name": "lib"}]}

        run_amend(sbom, selected=[HierarchicalBomRefs])

        self.assertEqual("app", sbom["components"][0]["bom-ref"])
        self.assertEqual("lib", sbom["components"][1]["bom-ref"])

    def test_operation_is_not_default(self) -> None:
        sbom = {"components": [{"name": "app", "bom-ref": "custom/ref"}]}

        run_amend(sbom)

        self.assertEqual("custom/ref", sbom["components"][0]["bom-ref"])


if __name__ == "__main__":
    unittest.main()
