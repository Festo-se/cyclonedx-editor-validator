import copy
import datetime
import json
import typing as t
import unittest

from cdxev.amend import process_license
from cdxev.amend.command import run as run_amend
from cdxev.amend.operations import (
    AddBomRef,
    Compositions,
    DefaultAuthor,
    DeleteAmbigiousLicenses,
    InferCopyright,
    InferSupplier,
    LicenseNameToId,
    Operation,
)
from cdxev.error import AppError
from tests.auxiliary.sbomFunctionsTests import compare_sboms

path_to_folder_with_test_sboms = "tests/auxiliary/test_amend_sboms/"


class AmendTestCase(unittest.TestCase):
    def setUp(self) -> None:
        with open(
            path_to_folder_with_test_sboms + "test.cdx.json", encoding="utf_8"
        ) as file:
            self.sbom_fixture = json.load(file)


class CommandIntegrationTestCase(AmendTestCase):
    def test_compositions(self) -> None:
        run_amend(self.sbom_fixture)

        expected_assemblies = [
            "pkg:npm/test-app@1.0.0",
            "com.company.unit/depA@4.0.2",
            "some-vendor/depB@1.2.3",
            "some-vendor/depB@1.2.3:physics/gravity@0.0.1",
            "some-vendor/depB@1.2.3:physics/x-ray@18.9.5",
            "some-vendor/depB@1.2.3:physics/x-ray@18.9.5:Rudolph@6.6.6",
            "depC@3.2.1",
            "depC@3.2.1:Rudolph@6.6.6",
        ]
        expected_assemblies.sort()
        self.sbom_fixture["compositions"][0]["assemblies"].sort()
        self.assertSequenceEqual(
            self.sbom_fixture["compositions"][0]["assemblies"],
            expected_assemblies,
        )

    def test_meta_author(self) -> None:
        run_amend(self.sbom_fixture)

        self.assertSequenceEqual(
            self.sbom_fixture["metadata"]["authors"], [{"name": "automated"}]
        )

    def test_suppliers(self) -> None:
        run_amend(self.sbom_fixture)
        components = self.sbom_fixture["components"]
        self.assertIn("supplier", components[0])
        self.assertDictEqual(
            {
                "name": "Some Vendor Inc.",
                "url": ["https://www.some-vendor.com"],
            },
            components[1]["supplier"],
        )
        self.assertDictEqual(
            {"url": ["https://www.universe.com"]},
            components[1]["components"][0]["supplier"],
        )
        self.assertNotIn("supplier", components[1]["components"][1])
        self.assertDictEqual(
            {"url": ["https://northpole.com/rudolph.git"]},
            components[1]["components"][1]["components"][0]["supplier"],
        )
        self.assertDictEqual(
            {
                "name": "Some Vendor Inc.",
                "url": ["https://www.some-vendor.com"],
            },
            components[1]["supplier"],
        )
        self.assertNotIn("supplier", components[2])


class CompositionsTestCase(AmendTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.operation = Compositions()

    def test_compositions_cleared(self) -> None:
        self.operation.prepare(self.sbom_fixture)
        self.assertSequenceEqual(
            self.sbom_fixture["compositions"],
            [{"aggregate": "incomplete", "assemblies": []}],
        )

    def test_meta_component_added(self) -> None:
        self.operation.prepare(self.sbom_fixture)
        self.operation.handle_metadata(self.sbom_fixture["metadata"])
        self.assertTrue(
            any(
                comp["aggregate"] == "not_specified"
                and comp["assemblies"] == ["pkg:npm/test-app@1.0.0"]
                for comp in self.sbom_fixture["compositions"]
            )
        )

    def test_components_added(self) -> None:
        self.operation.prepare(self.sbom_fixture)
        flat_walk_components(self.operation, self.sbom_fixture["components"])

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
        self.assertSequenceEqual(
            self.sbom_fixture["metadata"]["authors"], [{"name": "automated"}]
        )

    def test_existing_author_untouched(self) -> None:
        some_author = {"name": "My Name"}
        self.sbom_fixture["metadata"]["authors"] = [some_author]
        self.operation.handle_metadata(self.sbom_fixture["metadata"])
        self.assertSequenceEqual(
            self.sbom_fixture["metadata"]["authors"], [some_author]
        )


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
        expected = copy.deepcopy(component)
        self.operation.handle_component(component)
        self.assertDictEqual(expected, component)

    def test_supplier_already_present(self) -> None:
        component = {"author": "x", "supplier": {"name": "y"}}
        expected = copy.deepcopy(component)
        self.operation.handle_component(component)
        self.assertDictEqual(expected, component)

    def test_publisher_is_preferred_to_author(self) -> None:
        component = {"author": "x", "publisher": "y"}
        expected = copy.deepcopy(component)
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

    def test_supplier_get_not_overwritten(self) -> None:
        self.sbom_fixture["components"][0]["supplier"] = {
            "bom-ref": "Reference to a supplier entry",
            "name": "Some name of a supplier",
            "url": "https://someurl.com",
        }
        run_amend(self.sbom_fixture)
        self.assertEqual(
            self.sbom_fixture["components"][0]["supplier"]["name"],
            "Some name of a supplier",
        )
        self.assertEqual(
            self.sbom_fixture["components"][0]["supplier"]["url"], "https://someurl.com"
        )
        self.assertEqual(
            self.sbom_fixture["components"][0]["supplier"]["bom-ref"],
            "Reference to a supplier entry",
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


class ProcessLicenseTestCase(AmendTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.operation = LicenseNameToId()

    def test_replace_name_with_id(self) -> None:
        self.sbom_fixture["metadata"]["component"]["licenses"] = [
            {"license": {"name": "Apache License"}}
        ]
        self.operation.handle_metadata(self.sbom_fixture["metadata"])
        self.assertEqual(
            self.sbom_fixture["metadata"]["component"]["licenses"][0]["license"]["id"],
            "Apache-1.0",
        )
        self.sbom_fixture["components"][0]["licenses"] = [
            {"license": {"name": "Apache License"}}
        ]
        self.operation.handle_component(self.sbom_fixture["components"][0])
        self.assertEqual(
            self.sbom_fixture["components"][0]["licenses"][0]["license"]["id"],
            "Apache-1.0",
        )

    def test_no_component_in_metadata(self) -> None:
        exception_thrown = False
        test_sbom = copy.deepcopy(self.sbom_fixture)
        test_sbom["metadata"].pop("component")
        try:
            self.operation.handle_metadata(test_sbom["metadata"])
        except KeyError:
            exception_thrown = True
        self.assertFalse(exception_thrown)

    def test_no_name_and_no_id_in_license(self) -> None:
        exception_thrown = False
        test_sbom = copy.deepcopy(self.sbom_fixture)
        test_sbom["components"][0]["licenses"] = [{}]
        try:
            self.operation.handle_component(test_sbom["components"][0])
        except KeyError:
            exception_thrown = True
        self.operation.handle_component(test_sbom["components"][0])
        self.assertFalse(exception_thrown)

    def test_empty_component(self) -> None:
        exception_thrown = False
        test_sbom = copy.deepcopy(self.sbom_fixture)
        test_sbom["components"] = [{}]
        try:
            self.operation.handle_component(test_sbom["components"][0])
        except KeyError:
            exception_thrown = True
        self.assertFalse(exception_thrown)


def flat_walk_components(
    operation: Operation, components: t.Sequence[dict[str, t.Any]]
) -> None:
    """
    Test-helper which applies an operation to a flat sequence of components. subcomponents are
    ignored.
    """
    for c in components:
        operation.handle_component(c)


class TestReplaceLicenseNameWithIdFunctions(unittest.TestCase):
    def test_find_license_id(self) -> None:
        with open(
            (path_to_folder_with_test_sboms + "/example_list_with_license_names.json"),
            "r",
            encoding="utf-8-sig",
        ) as my_file:
            list_of_license_names = json.load(my_file)
        for licenses in list_of_license_names:
            license_id = licenses["exp"]
            for names in licenses["names"]:
                self.assertEqual(
                    process_license.find_license_id(names, list_of_license_names),
                    license_id,
                )

    def test_find_license_id_fail(self) -> None:
        with open(
            (path_to_folder_with_test_sboms + "example_list_with_license_names.json"),
            "r",
            encoding="utf-8-sig",
        ) as my_file:
            list_of_license_names = json.load(my_file)
        self.assertEqual(
            process_license.find_license_id(10, list_of_license_names),  # type: ignore
            "",
        )
        self.assertEqual(
            process_license.find_license_id("no license", list_of_license_names), ""
        )
        self.assertEqual(
            process_license.find_license_id({}, list_of_license_names),  # type: ignore
            "",
        )

    def test_process_license_replace_name_with_id(self) -> None:
        with open(
            (path_to_folder_with_test_sboms + "example_list_with_license_names.json"),
            "r",
            encoding="utf-8-sig",
        ) as my_file:
            list_of_license_names = json.load(my_file)
        with open(
            (path_to_folder_with_test_sboms + "bom_licenses_changed.json"),
            "r",
            encoding="utf-8-sig",
        ) as my_file:
            sbom = json.load(my_file)
        with open(
            (path_to_folder_with_test_sboms + "bom_licenses_changed_with_id.json"),
            "r",
            encoding="utf-8-sig",
        ) as my_file:
            sbom_with_id = json.load(my_file)
        process_license.process_license(
            sbom["metadata"]["component"], list_of_license_names
        )
        for component in sbom["components"]:
            process_license.process_license(component, list_of_license_names)
        self.assertTrue(compare_sboms(sbom, sbom_with_id))


class GetLicenseTextFromFile(unittest.TestCase):
    def test_get_license_text_from_folder(self) -> None:
        path_to_license_folder = "tests/auxiliary/licenses"
        license_text = process_license.get_license_text_from_folder(
            "license_name", path_to_license_folder
        )
        self.assertEqual(license_text, "The text describing a license.")

    def test_process_license_replace_license_text(self) -> None:
        path_to_license_folder = "tests/auxiliary/licenses"
        with open(
            (path_to_folder_with_test_sboms + "example_list_with_license_names.json"),
            "r",
            encoding="utf-8-sig",
        ) as my_file:
            list_of_license_names = json.load(my_file)
        component = {
            "type": "library",
            "bom-ref": "pkg:nuget/some name@1.3.3",
            "publisher": "some publisher",
            "name": "some name",
            "version": "1.3.2",
            "cpe": "",
            "description": "some description",
            "scope": "required",
            "hashes": [{"alg": "SHA-512", "content": "5F6996E38A31861449A493B938"}],
            "licenses": [
                {"license": {"name": "license_name", "text": {"content": "other text"}}}
            ],
            "copyright": "Copyright 2000-2021 some name Contributors",
            "purl": "pkg:nuget/some name@1.3.2",
        }
        process_license.process_license(
            component, list_of_license_names, path_to_license_folder
        )
        self.assertEqual(
            component["licenses"][0]["license"]["text"]["content"],  # type: ignore
            "The text describing a license.",
        )

    def test_process_license_add_license_text(self) -> None:
        path_to_license_folder = "tests/auxiliary/licenses"
        with open(
            (path_to_folder_with_test_sboms + "example_list_with_license_names.json"),
            "r",
            encoding="utf-8-sig",
        ) as my_file:
            list_of_license_names = json.load(my_file)
        component = {
            "type": "library",
            "bom-ref": "pkg:nuget/some name@1.3.3",
            "publisher": "some publisher",
            "name": "some name",
            "version": "1.3.2",
            "cpe": "",
            "description": "some description",
            "scope": "required",
            "hashes": [{"alg": "SHA-512", "content": "5F6996E38A31861449A493B938"}],
            "licenses": [
                {
                    "license": {
                        "name": "license_name",
                    }
                }
            ],
            "copyright": "Copyright 2000-2021 some name Contributors",
            "purl": "pkg:nuget/some name@1.3.2",
        }
        process_license.process_license(
            component, list_of_license_names, path_to_license_folder
        )
        self.assertEqual(
            component["licenses"][0]["license"]["text"]["content"],  # type: ignore
            "The text describing a license.",
        )

    def test_process_license_add_license_text_with_space(self) -> None:
        path_to_license_folder = "tests/auxiliary/licenses"
        with open(
            (path_to_folder_with_test_sboms + "example_list_with_license_names.json"),
            "r",
            encoding="utf-8-sig",
        ) as my_file:
            list_of_license_names = json.load(my_file)
        component = {
            "type": "library",
            "bom-ref": "pkg:nuget/some name@1.3.3",
            "publisher": "some publisher",
            "name": "some name",
            "version": "1.3.2",
            "cpe": "",
            "description": "some description",
            "scope": "required",
            "hashes": [{"alg": "SHA-512", "content": "5F6996E38A31861449A493B938"}],
            "licenses": [
                {
                    "license": {
                        "name": "another license",
                    }
                }
            ],
            "copyright": "Copyright 2000-2021 some name Contributors",
            "purl": "pkg:nuget/some name@1.3.2",
        }
        process_license.process_license(
            component, list_of_license_names, path_to_license_folder
        )
        self.assertEqual(
            component["licenses"][0]["license"]["text"]["content"],  # type: ignore
            "The text describing another license.",
        )

    def test_error_messages_does_not_exist(self) -> None:
        path_to_license_folder = "thispathdoesnotexist"
        with self.assertRaises(AppError) as ae:
            process_license.get_license_text_from_folder(
                "license_name", path_to_license_folder
            )
            self.assertIn(
                "The submitted path thispathdoesnotexist does not exist.",
                ae.exception.details.description,
            )

    def test_error_messages_not_a_folder(self) -> None:
        path_to_license_folder = "tests/test_amend.py"
        with self.assertRaises(AppError) as ae:
            process_license.get_license_text_from_folder(
                "license_name", path_to_license_folder
            )
            self.assertIn(
                "The submitted path (tests/test_amend.py) does not lead to a folder.",
                ae.exception.details.description,
            )


class TestInferCopyright(AmendTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.operation = InferCopyright()

    def test_no_supplier_is_given(self) -> None:
        component = {"name": "something"}
        expected = {"name": "something"}
        self.operation.handle_component(component)
        self.assertDictEqual(expected, component)

    def test_supplier_and_license_is_present(self) -> None:
        component = {"licenses": [], "supplier": {"name": "some_supplier"}}
        expected = {"licenses": [], "supplier": {"name": "some_supplier"}}
        self.operation.handle_component(component)
        self.assertDictEqual(expected, component)

    def test_supplier_and_copyright_is_present(self) -> None:
        component = {"copyright": "some copyright", "supplier": {"name": "Acme Inc."}}
        expected = {"copyright": "some copyright", "supplier": {"name": "Acme Inc."}}
        self.operation.handle_component(component)
        self.assertDictEqual(expected, component)

    def test_create_copyright(self) -> None:
        component = {"supplier": {"name": "Acme Inc."}}
        year = datetime.date.today().year
        copyright = f"Copyright (c) {year} Acme Inc."
        expected = {"copyright": copyright, "supplier": {"name": "Acme Inc."}}
        self.operation.handle_component(component)
        self.assertDictEqual(expected, component)

    def test_set_copyright_from_supplier_in_metadata(self) -> None:
        year = datetime.date.today().year
        self.sbom_fixture["metadata"]["component"]["supplier"] = {"name": "Acme Inc."}
        run_amend(self.sbom_fixture, selected=[InferCopyright])
        self.assertEqual(
            self.sbom_fixture["metadata"]["component"]["copyright"],
            f"Copyright (c) {year} Acme Inc.",
        )

    def test_set_copyright_from_supplier_in_components(self) -> None:
        self.sbom_fixture["components"][0].pop("licenses")
        self.sbom_fixture["components"][0].pop("externalReferences")
        self.sbom_fixture["components"][0]["supplier"] = {"name": "Acme Inc."}
        year = datetime.date.today().year
        run_amend(self.sbom_fixture, selected=[InferCopyright])
        company = self.sbom_fixture["components"][0]["supplier"]["name"]
        self.assertEqual(
            self.sbom_fixture["components"][0]["copyright"],
            f"Copyright (c) {year} {company}",
        )


class DeleteAmbigiousLicensesTestCase(AmendTestCase):
    def setUp(self):
        super().setUp()
        self.operation = DeleteAmbigiousLicenses()
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
        expected["licenses"] = []

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


if __name__ == "__main__":
    unittest.main()
