# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
import os
import typing as t
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cdxev.error import AppError
from cdxev.validator.helper import validate_filename
from cdxev.validator.validate import validate_sbom

path_to_folder_with_test_sboms = "tests/auxiliary/test_validate_sboms/"

path_to_sbom = (
    path_to_folder_with_test_sboms
    + "Acme_Application_9.1.1_ec7781220ec7781220ec778122012345_20220217T101458.cdx.json"
)

path_to_modified_sbom = (
    path_to_folder_with_test_sboms + "modified_sbom/"
    "Acme_Application_9.1.1_20220217T101458.cdx.json"
)

list_of_spec_versions = ["1.3", "1.4", "1.5", "1.6"]
list_of_spec_versions_containing_licensing = ["1.5", "1.6"]


def search_for_word_issues(word: str, issue_list: list) -> bool:
    is_valid = False
    for issue in issue_list:
        if word.lower() in str(issue[0][0]).lower():
            is_valid = True
    return is_valid


@patch("cdxev.validator.validate.logger")
def validate_test(
    sbom: dict,
    mock_logger: Mock,
    report_format: str = "stdout",
    filename_regex: str = "",
    schema_type: str = "custom",
    schema_path: t.Optional[Path] = None,
) -> list:
    mock_logger.error.call_args_list = []
    errors_occurred = validate_sbom(
        sbom=sbom,
        input_format="json",
        file=Path(path_to_sbom),
        report_format=report_format,
        report_path=Path(""),
        schema_type=schema_type,
        filename_regex=filename_regex,
        schema_path=schema_path,
    )
    if not errors_occurred:
        return ["no issue"]
    messages = mock_logger.error.call_args_list
    return messages


def get_test_sbom(path_bom: str = path_to_sbom) -> dict:
    with open(path_bom, "r") as read_file:
        sbom = json.load(read_file)
    return sbom


class TestValidateInit(unittest.TestCase):
    @unittest.skipUnless("CI" in os.environ, "running only in CI")
    def test_custom_schema(self) -> None:
        sbom = get_test_sbom()
        issues = validate_test(sbom, schema_type="default", schema_path=None)
        self.assertEqual(issues, ["no issue"])

    def test_missing_specversion(self) -> None:
        sbom = {
            "bomFormat": "CycloneDX",
        }
        with self.assertRaisesRegex(AppError, ".*'specVersion'.*"):
            validate_test(sbom)


class TestValidateMetadata(unittest.TestCase):
    def test_metadata_missing(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom.pop("metadata")
            issues = validate_test(sbom)
            self.assertTrue(search_for_word_issues("metadata", issues))

    def test_timestamp(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["timestamp"] = "2022-02-17T10:14:59Zpp"
            issues = validate_test(sbom)
            results = search_for_word_issues("timestamp", issues)
            self.assertEqual(results, True)
            sbom["metadata"].pop("timestamp")
            issues = validate_test(sbom)
            results = search_for_word_issues("timestamp", issues)
            self.assertEqual(results, True)
            sbom["metadata"]["timestamp"] = "2022-02-17T10:14:59Z"
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("name", issues), True)

    def test_metadata_authors_missing(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"].pop("authors")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("authors", issues), True)

    def test_metadata_authors_name_missing(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["authors"][0].pop("name")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("name", issues), True)
            self.assertEqual(search_for_word_issues("authors", issues), True)

    def test_metadata_component_missing(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"].pop("component")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("metadata", issues), True)
            self.assertEqual(search_for_word_issues("component", issues), True)

    def test_metadata_component_field_missing(self) -> None:
        for fields in [
            "type",
            "name",
            "version",
            "bom-ref",
        ]:
            for spec_version in list_of_spec_versions:
                sbom = get_test_sbom()
                sbom["specVersion"] = spec_version
                sbom["metadata"]["component"].pop(fields)
                issues = validate_test(sbom)
                self.assertEqual(search_for_word_issues(fields, issues), True)

    def test_metadata_component_supplier_and_author_missing(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["component"].pop("supplier")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("supplier", issues), True)
            self.assertEqual(search_for_word_issues("author", issues), True)

    def test_metadata_component_author_festo_no_copyright(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["component"].pop("copyright")
            sbom["metadata"]["component"]["author"] = "festo"
            sbom["metadata"]["component"]["supplier"] = {"name": "Acme"}
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("copyright", issues), True)

    def test_metadata_component_with_license(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["component"].pop("copyright")
            sbom["metadata"]["component"]["supplier"] = {"name": "Acme"}
            sbom["metadata"]["component"]["licenses"] = [
                {"license": {"id": "Apache-1.0"}}
            ]
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_metadata_component_author_festo_copyright_not_festo(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["component"].pop("supplier")
            sbom["metadata"]["component"]["author"] = "festo"
            sbom["metadata"]["component"]["copyright"] = "something"
            issues = validate_test(sbom)
            self.assertEqual(
                search_for_word_issues("[Ff][Ee][Ss][Tt][Oo]", issues), True
            )

    def test_metadata_internal_component_copyright_missing(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["component"].pop("copyright")
            issues = validate_test(sbom)
            sbom["metadata"]["component"]["licenses"] = [
                {"license": {"name": "license"}}
            ]
            sbom["metadata"]["component"]["properties"] = [
                {"name": "something", "value": "something"}
            ]
            self.assertEqual(search_for_word_issues("copyright", issues), True)

    def test_metadata_component_no_license_or_copyright(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["component"].pop("copyright")
            sbom["metadata"]["component"]["properties"] = [
                {"name": "something", "value": "something"}
            ]
            sbom["metadata"]["component"]["group"] = "some group"
            sbom["metadata"]["component"]["supplier"]["name"] = "ppp"
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("copyright", issues), True)
            self.assertEqual(search_for_word_issues("licenses", issues), True)

    def test_metadata_no_legitimate_spec_version(self) -> None:
        sbom = get_test_sbom()
        sbom["specVersion"] = "0.0"
        with self.assertRaises(AppError) as ae:
            validate_test(sbom)
        self.assertIn(
            "No built-in schema found for CycloneDX version " + sbom["specVersion"],
            ae.exception.details.description,
        )

    def test_metadata_illegitimate_bom_format(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["bomFormat"] = "wrongFormat"
            issues = validate_test(sbom)
            self.assertTrue(search_for_word_issues("CycloneDX", issues))

    def test_metadata_component_licensetype_appliance_no_licensor_or_licensee(
        self,
    ) -> None:
        for spec_version in list_of_spec_versions_containing_licensing:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["component"]["licenses"] = [
                {
                    "license": {
                        "name": "some_name",
                        "url": "https://spdx.org/licenses/GPL-2.0-only.html",
                        "text": {"content": "some text"},
                        "licensing": {
                            "licenseTypes": ["appliance"],
                            "expiration": "2023-04-13T20:20:39+00:00",
                        },
                    }
                }
            ]
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_metadata_component_supplier_festo_no_copyright_with_licenses(
        self,
    ) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["component"] = {
                "type": "application",
                "bom-ref": "acme-app",
                "group": "com.festo.internal",
                "supplier": {"name": "Festo SE & Co. KG"},
                "name": "Acme_Application",
                "version": "9.1.1",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "hashes": [
                    {"alg": "MD5", "content": "ec7781220ec7781220ec778122012345"}
                ],
            }
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_metadata_component_author_festo_no_copyright_with_licenses(
        self,
    ) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["component"] = {
                "type": "application",
                "bom-ref": "acme-app",
                "group": "com.festo.internal",
                "author": "Festo",
                "name": "Acme_Application",
                "version": "9.1.1",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "hashes": [
                    {"alg": "MD5", "content": "ec7781220ec7781220ec778122012345"}
                ],
            }
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])


class TestValidateComponents(unittest.TestCase):
    def test_components_empty(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom.pop("components")
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_components_component_field_missing(self) -> None:
        for component_number in [0, 1]:
            for fields in [
                "type",
                "name",
                "version",
                "bom-ref",
            ]:
                for spec_version in list_of_spec_versions:
                    sbom = get_test_sbom()
                    sbom["specVersion"] = spec_version
                    sbom["components"][component_number].pop(fields)
                    issues = validate_test(sbom)
                    self.assertEqual(search_for_word_issues(fields, issues), True)

    def test_supplier_only_url(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["supplier"] = {"url": ["https://example.com"]}
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_components_component_supplier_and_author_missing(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0].pop("supplier")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("supplier", issues), True)
            self.assertEqual(search_for_word_issues("author", issues), True)

    def test_components_component_supplier_missing_author(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0].pop("supplier")
            sbom["components"][0]["author"] = "author"
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_components_component_license_and_copyright_missing(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0].pop("licenses")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("licenses", issues), True)

    def test_components_component_copyright_instead_of_license_etc(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0].pop("licenses")
            sbom["components"][0]["copyright"] = "ppp"
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_components_component_license_or_expression(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {"license": {"name": "Apache-2.0"}, "expression": "Apache-2.0"}
            ]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("expression", issues), True)
            self.assertEqual(search_for_word_issues("license", issues), True)

    def test_components_component_license_expression(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [{"expression": "Apache-2.0"}]
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_components_license_without_name_and_id(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [{"license": {}}]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("name", issues), True)
            self.assertEqual(search_for_word_issues("id", issues), True)

    def test_components_license_additional_fields(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {
                    "license": {
                        "id": "GPL-2.0-only",
                        "url": "https://spdx.org/licenses/GPL-2.0-only.html",
                        "text2": {
                            "content": "GNU GENERAL PUBLIC LICENSE\r\nVersion 2, ..."
                        },
                    }
                }
            ]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("additional", issues), True)

    def test_components_licenses_is_empty(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = []
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("empty", issues), True)

    def test_components_license_name_without_text(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [{"license": {"name": "something"}}]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("text", issues), True)

    def test_components_license_text_without_content(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {"license": {"name": "something", "text": {}}}
            ]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("content", issues), True)

    def test_components_license_wrong_spdxid(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {
                    "license": {
                        "id": "some_id",
                        "url": "https://spdx.org/licenses/GPL-2.0-only.html",
                    }
                }
            ]
            issues = validate_test(sbom)
            self.assertEqual(
                search_for_word_issues("not a valid SPDX ID", issues), True
            )

    def test_components_no_license_or_copyright_for_device(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["type"] = "device"
            sbom["components"][0].pop("licenses")
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_metadata_component_no_license_or_copyright_for_device_supplier(
        self,
    ) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["component"]["type"] = "device"
            sbom["metadata"]["component"].pop("copyright")
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_metadata_component_no_license_or_copyright_for_device_author(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["component"]["author"] = "Festo"
            sbom["metadata"]["component"]["type"] = "device"
            sbom["metadata"]["component"].pop("copyright")
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_components_component_copyright(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][-1].pop("copyright")
            sbom["components"][-1].pop("licenses")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("copyright", issues), True)

    def test_version_short(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["version"] = ""
            issues = validate_test(sbom)
            self.assertEqual(
                search_for_word_issues("'version' should not be empty", issues), True
            )

    def test_supplier_empty(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["supplier"] = {"name": ""}
            issues = validate_test(sbom)
            self.assertEqual(
                search_for_word_issues("'name' should not be empty", issues), True
            )

    def test_no_components_no_dependencies(
        self,
    ) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom.pop("components")
            sbom.pop("dependencies")
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    @patch("cdxev.validator.validate.logger", spec=logging.Logger)
    def test_external_bom(self, mock_logger: Mock) -> None:
        for spec_version in list_of_spec_versions:
            with self.subTest(spec_version=spec_version):
                mock_logger.reset_mock()
                sbom = get_test_sbom()
                sbom["specVersion"] = spec_version
                sbom["components"][0] = {
                    "type": "library",
                    "name": "Externally described component",
                    "bom-ref": "foo",
                    "externalReferences": [
                        {
                            "type": "bom",
                            "url": "urn:cdx:8428fc58-c402-4a4f-9f8d-0d96d2ad07e3/1",
                        }
                    ],
                }
                validate_sbom(
                    sbom=sbom,
                    input_format="json",
                    file=Path(path_to_sbom),
                    report_format=None,
                    report_path=None,
                    schema_type="custom",
                    filename_regex=None,
                    schema_path=None,
                )
                mock_logger.error.assert_not_called()
                mock_logger.warning.assert_called_with(
                    "Component [bom-ref: foo] is described by an external BOM. "
                    "The validity of the referenced BOM cannot be checked."
                )


class TestValidateDependencies(unittest.TestCase):
    def test_dependencies_missing(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom.pop("dependencies")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("dependencies", issues), True)

    def test_dependencies_ref_missing(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["dependencies"][0].pop("ref")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("ref", issues), True)

    def test_dependencies_duplicate_dependson(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["dependencies"][0]["dependsOn"].append(
                sbom["dependencies"][0]["dependsOn"][0]
            )
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("are non-unique", issues), True)


class TestValidateCompositions(unittest.TestCase):
    def test_compositions_missing(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom.pop("compositions")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("compositions", issues), True)

    def test_compositions_aggregate_missing(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["compositions"][0].pop("aggregate")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("aggregate", issues), True)

    def test_compositions_assemblies_missing(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["compositions"][0].pop("assemblies")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("assemblies", issues), True)

    def test_compositions_aggregate_not_valid(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["compositions"][0]["aggregate"] = "something"
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("aggregate", issues), True)


class TestValidateUseOwnSchema(unittest.TestCase):
    def test_use_own_schema(self) -> None:
        sbom = get_test_sbom()
        sbom.pop("compositions")
        sbom.pop("dependencies")
        v = validate_sbom(
            sbom,
            "json",
            Path(path_to_sbom),
            "",
            Path(""),
            schema_path=(
                Path(__file__).parent.resolve()
                / "auxiliary"
                / "test_validate_sboms"
                / "test_schema.json"
            ),
            schema_type=None,
            filename_regex=None,
        )
        self.assertEqual(v, 0)

    def test_use_own_schema_path_does_not_exist(self) -> None:
        sbom = get_test_sbom()
        with self.assertRaises(AppError) as ap:
            validate_test(sbom, schema_path=Path("No_Path"), schema_type=None)
        self.assertIn(
            "Path does not exist or is not a file",
            ap.exception.details.description,
        )

    def test_use_own_schema_invalid_json(self) -> None:
        sbom = get_test_sbom()
        with self.assertRaises(AppError) as ap:
            validate_test(
                sbom, schema_path=Path("cdxev/auxiliary/schema"), schema_type=None
            )
        self.assertIn(
            "Path does not exist or is not a file",
            ap.exception.details.description,
        )


class TestValidateLicensing(unittest.TestCase):
    def test_correct_license(self) -> None:
        for spec_version in list_of_spec_versions_containing_licensing:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {
                    "license": {
                        "name": "some_name",
                        "url": "https://spdx.org/licenses/GPL-2.0-only.html",
                        "text": {"content": "some text"},
                        "licensing": {
                            "licenseTypes": ["other"],
                            "licensor": {"individual": {"name": "Something"}},
                            "licensee": {"organization": {"name": "Acme.ing"}},
                            "expiration": "2023-04-13T20:20:39+00:00",
                        },
                    }
                }
            ]
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_no_licensor(self) -> None:
        for spec_version in list_of_spec_versions_containing_licensing:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {
                    "license": {
                        "name": "some_name",
                        "url": "https://spdx.org/licenses/GPL-2.0-only.html",
                        "text": {"content": "some text"},
                        "licensing": {
                            "licenseTypes": ["other"],
                            "licensee": {"organization": {"name": "Acme.ing"}},
                            "expiration": "2023-04-13T20:20:39+00:00",
                        },
                    }
                }
            ]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("licensor", issues), True)

    def test_no_licensee(self) -> None:
        for spec_version in list_of_spec_versions_containing_licensing:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {
                    "license": {
                        "name": "some_name",
                        "url": "https://spdx.org/licenses/GPL-2.0-only.html",
                        "text": {"content": "some text"},
                        "licensing": {
                            "licenseTypes": ["other"],
                            "licensor": {"individual": {"name": "Something"}},
                            "expiration": "2023-04-13T20:20:39+00:00",
                        },
                    }
                }
            ]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("licensee", issues), True)

    def test_licensetype_appliance_no_licensor_or_licensee(self) -> None:
        for spec_version in list_of_spec_versions_containing_licensing:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {
                    "license": {
                        "name": "some_name",
                        "url": "https://spdx.org/licenses/GPL-2.0-only.html",
                        "text": {"content": "some text"},
                        "licensing": {
                            "licenseTypes": ["appliance"],
                            "expiration": "2023-04-13T20:20:39+00:00",
                        },
                    }
                }
            ]
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_no_license_types(self) -> None:
        for spec_version in list_of_spec_versions_containing_licensing:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {
                    "license": {
                        "name": "some_name",
                        "url": "https://spdx.org/licenses/GPL-2.0-only.html",
                        "text": {"content": "some text"},
                        "licensing": {
                            "licensor": {"individual": {"name": "Something"}},
                            "licensee": {"organization": {"name": "Acme.ing"}},
                            "expiration": "2023-04-13T20:20:39+00:00",
                        },
                    }
                }
            ]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("licenseTypes", issues), True)

    def test_no_licensing(self) -> None:
        for spec_version in list_of_spec_versions_containing_licensing:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {
                    "license": {
                        "name": "some_name",
                        "url": "https://spdx.org/licenses/GPL-2.0-only.html",
                        "text": {"content": "some text"},
                    }
                }
            ]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("licensing", issues), True)

    def test_licensing_no_text(self) -> None:
        for spec_version in list_of_spec_versions_containing_licensing:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {
                    "license": {
                        "name": "some_name",
                        "url": "https://spdx.org/licenses/GPL-2.0-only.html",
                        "licensing": {
                            "licenseTypes": ["other"],
                            "licensor": {"individual": {"name": "Something"}},
                            "licensee": {"organization": {"name": "Acme.ing"}},
                            "expiration": "2023-04-13T20:20:39+00:00",
                        },
                    }
                }
            ]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("text", issues), True)

    def test_not_allowed_license_type(self) -> None:
        for spec_version in list_of_spec_versions_containing_licensing:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {
                    "license": {
                        "name": "some_name",
                        "url": "https://spdx.org/licenses/GPL-2.0-only.html",
                        "text": {"content": "some text"},
                        "licensing": {
                            "licenseTypes": ["something"],
                            "licensor": {"individual": {"name": "Something"}},
                            "licensee": {"organization": {"name": "Acme.ing"}},
                            "expiration": "2023-04-13T20:20:39+00:00",
                        },
                    }
                }
            ]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("something", issues), True)

    def test_licensing_neither_organization_nor_individual(self) -> None:
        for spec_version in list_of_spec_versions_containing_licensing:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {
                    "license": {
                        "name": "some_name",
                        "url": "https://spdx.org/licenses/GPL-2.0-only.html",
                        "text": {"content": "some text"},
                        "licensing": {
                            "licenseTypes": ["other"],
                            "licensor": {},
                            "licensee": {"organization": {"name": "Acme.ing"}},
                            "expiration": "2023-04-13T20:20:39+00:00",
                        },
                    }
                }
            ]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("individual", issues), True)
            self.assertEqual(search_for_word_issues("organization", issues), True)

    def test_licensing_additional_field(self) -> None:
        for spec_version in list_of_spec_versions_containing_licensing:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {
                    "license": {
                        "name": "some_name",
                        "url": "https://spdx.org/licenses/GPL-2.0-only.html",
                        "text": {"content": "some text"},
                        "licensing": {
                            "licenseTypes": ["other"],
                            "licensor": {"individual": {"name": "Something"}},
                            "licensee": {"organization": {"name": "Acme.ing"}},
                            "expiration": "2023-04-13T20:20:39+00:00",
                            "additional_field": "",
                        },
                    }
                }
            ]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("additional", issues), True)

    def test_license_text_with_empty_content(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {
                    "license": {
                        "id": "GPL-2.0-only",
                        "url": "https://spdx.org/licenses/GPL-2.0-only.html",
                        "text": {"content": ""},
                    },
                }
            ]
            issues = validate_test(sbom)
            self.assertEqual(
                search_for_word_issues("'content' should not be empty", issues), True
            )


class TestValidateUseSchemaType(unittest.TestCase):
    @unittest.skipUnless("CI" in os.environ, "running only in CI")
    def test_default_schema(self) -> None:
        sbom = get_test_sbom()
        v = validate_sbom(
            sbom,
            "json",
            Path(path_to_sbom),
            "",
            Path(""),
            schema_type="default",
            schema_path=None,
            filename_regex=None,
        )
        self.assertEqual(v, 0)


class TestInternalNameSchema(unittest.TestCase):
    def test_components_supplier_festo_copyright_not_no_licenses(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0] = {
                "type": "application",
                "bom-ref": "someprogramm application",
                "supplier": {"name": "Festo SE & Co.KG"},
                "group": "",
                "name": "someprogramm",
                "version": "T4.0.1.30",
                "hashes": [
                    {"alg": "SHA-256", "content": "3942447fac867ae5cdb3229b658f4d48"}
                ],
                "copyright": "3rd Party",
            }
            issues = validate_test(sbom)
            self.assertEqual(
                search_for_word_issues("[Ff][Ee][Ss][Tt][Oo]", issues), True
            )

    def test_components_supplier_festo_no_copyright_with_licenses(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0] = {
                "type": "application",
                "bom-ref": "someprogramm application",
                "supplier": {"name": "Festo SE & Co.KG"},
                "group": "",
                "name": "someprogramm",
                "version": "T4.0.1.30",
                "hashes": [
                    {"alg": "SHA-256", "content": "3942447fac867ae5cdb3229b658f4d48"}
                ],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            }
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_components_author_festo_no_copyright_with_licenses(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0] = {
                "type": "application",
                "bom-ref": "someprogramm application",
                "author": "Festo SE & Co.KG",
                "group": "",
                "name": "someprogramm",
                "version": "T4.0.1.30",
                "hashes": [
                    {"alg": "SHA-256", "content": "3942447fac867ae5cdb3229b658f4d48"}
                ],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            }
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_components_supplier_festo_copyright_not_with_licenses(self) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0] = {
                "type": "application",
                "bom-ref": "someprogramm application",
                "supplier": {"name": "Festo SE & Co.KG"},
                "group": "",
                "name": "someprogramm",
                "version": "T4.0.1.30",
                "hashes": [
                    {"alg": "SHA-256", "content": "3942447fac867ae5cdb3229b658f4d48"}
                ],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "copyright": "3rd Party",
            }
            issues = validate_test(sbom)
            self.assertEqual(
                search_for_word_issues("[Ff][Ee][Ss][Tt][Oo]", issues), True
            )

    def test_copyright_festo_supplier_not_no_licenses(
        self,
    ) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0] = {
                "type": "application",
                "bom-ref": "someprogramm application",
                "author": "automated",
                "supplier": {"name": "Acme SE & Co.KG"},
                "group": "com.festo.internal",
                "name": "someprogramm",
                "version": "T4.0.1.30",
                "hashes": [
                    {"alg": "SHA-256", "content": "3942447fac867ae5cdb3229b658f4d48"}
                ],
                "copyright": "festo",
            }
            issues = validate_test(sbom)
            self.assertEqual(
                search_for_word_issues("[Ff][Ee][Ss][Tt][Oo]", issues), True
            )

    def test_copyright_festo_supplier_not_with_licenses(
        self,
    ) -> None:
        for spec_version in list_of_spec_versions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0] = {
                "type": "application",
                "bom-ref": "someprogramm application",
                "author": "automated",
                "supplier": {"name": "Acme SE & Co.KG"},
                "group": "com.festo.internal",
                "name": "someprogramm",
                "version": "T4.0.1.30",
                "hashes": [
                    {"alg": "SHA-256", "content": "3942447fac867ae5cdb3229b658f4d48"}
                ],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "copyright": "festo",
            }
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_internal_component_copyright_festo_supplier_not(self) -> None:
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "metadata": {
                "timestamp": "2022-02-17T10:14:58Z",
                "authors": [{"name": "automated"}],
                "component": {
                    "type": "application",
                    "bom-ref": "acme-app",
                    "supplier": {"name": "Acme"},
                    "copyright": "Acme",
                    "name": "Acme_Application",
                    "version": "9.1.1",
                    "hashes": [
                        {"alg": "MD5", "content": "ec7781220ec7781220ec778122012345"}
                    ],
                    "properties": [
                        {"name": "internal:component:status", "value": "internal"}
                    ],
                },
            },
            "components": [
                {
                    "type": "application",
                    "bom-ref": "acme-app",
                    "supplier": {"name": "Acme"},
                    "name": "Acme_Application",
                    "copyright": "Festo SE & Co. KG 2022, all rights reserved",
                    "version": "9.1.1",
                    "group": "com.festo.internal",
                    "hashes": [
                        {"alg": "MD5", "content": "ec7781220ec7781220ec778122012345"}
                    ],
                    "properties": [
                        {"name": "internal:component:status", "value": "internal"}
                    ],
                }
            ],
            "compositions": [],
            "dependencies": [],
        }
        for spec_version in list_of_spec_versions:
            sbom["specVersion"] = spec_version
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("supplier", issues), True)
            self.assertEqual(
                search_for_word_issues("([Ff][Ee][Ss][Tt][Oo])", issues), True
            )

    def test_internal_component_copyright_festo_supplier_empty(self) -> None:
        sbom = get_test_sbom()
        sbom["components"][0]["supplier"] = {}
        sbom["components"][0][
            "copyright"
        ] = "Festo SE & Co. KG 2022, all rights reserved"
        for spec_version in list_of_spec_versions:
            sbom["specVersion"] = spec_version
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("name", issues), True)


class TestInternalMetaData(unittest.TestCase):
    def test_internal_component_metadata_no_issue(self) -> None:
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "metadata": {
                "timestamp": "2022-02-17T10:14:58Z",
                "authors": [{"name": "automated"}],
                "component": {
                    "type": "application",
                    "bom-ref": "acme-app",
                    "supplier": {"name": "Acme"},
                    "name": "Acme_Application",
                    "licenses": [{"license": {"id": "Apache-1.0"}}],
                    "version": "9.1.1",
                    "hashes": [
                        {"alg": "MD5", "content": "ec7781220ec7781220ec778122012345"}
                    ],
                    "properties": [
                        {"name": "internal:component:status", "value": "internal"}
                    ],
                },
            },
            "compositions": [],
            "dependencies": [],
        }
        for spec_version in list_of_spec_versions:
            sbom["specVersion"] = spec_version
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_internal_component_metadata_no_copyright_author_festo(self) -> None:
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "metadata": {
                "timestamp": "2022-02-17T10:14:58Z",
                "authors": [{"name": "automated"}],
                "component": {
                    "type": "application",
                    "bom-ref": "acme-app",
                    "group": "com.festo.internal",
                    "author": "festo",
                    "name": "Acme_Application",
                    "version": "9.1.1",
                    "hashes": [
                        {"alg": "MD5", "content": "ec7781220ec7781220ec778122012345"}
                    ],
                    "properties": [
                        {"name": "internal:component:status", "value": "internal"}
                    ],
                },
            },
            "compositions": [],
            "dependencies": [],
        }
        for spec_version in list_of_spec_versions:
            sbom["specVersion"] = spec_version
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("copyright", issues), True)

    def test_internal_component_metadata_no_copyright_supplier_festo(self) -> None:
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "metadata": {
                "timestamp": "2022-02-17T10:14:58Z",
                "authors": [{"name": "automated"}],
                "component": {
                    "type": "application",
                    "bom-ref": "acme-app",
                    "group": "com.festo.internal",
                    "supplier": {"name": "festo"},
                    "name": "Acme_Application",
                    "version": "9.1.1",
                    "hashes": [
                        {"alg": "MD5", "content": "ec7781220ec7781220ec778122012345"}
                    ],
                    "properties": [
                        {"name": "internal:component:status", "value": "internal"}
                    ],
                },
            },
            "compositions": [],
            "dependencies": [],
        }
        for spec_version in list_of_spec_versions:
            sbom["specVersion"] = spec_version
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("copyright", issues), True)

    def test_component_metadata_not_internal_license(self) -> None:
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "metadata": {
                "timestamp": "2022-02-17T10:14:58Z",
                "authors": [{"name": "automated"}],
                "component": {
                    "type": "application",
                    "bom-ref": "acme-app",
                    "group": "com.festo.internal",
                    "licenses": [{"license": {"id": "Apache-1.0"}}],
                    "supplier": {"name": "acme"},
                    "name": "Acme_Application",
                    "version": "9.1.1",
                    "hashes": [
                        {"alg": "MD5", "content": "ec7781220ec7781220ec778122012345"}
                    ],
                    "properties": [
                        {"name": "internal:component:status", "value": "internal"}
                    ],
                },
            },
            "compositions": [],
            "dependencies": [],
        }
        for spec_version in list_of_spec_versions:
            sbom["specVersion"] = spec_version
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_component_metadata_empty_license(self) -> None:
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "metadata": {
                "timestamp": "2022-02-17T10:14:58Z",
                "authors": [{"name": "automated"}],
                "component": {
                    "type": "application",
                    "bom-ref": "acme-app",
                    "group": "com.festo.internal",
                    "licenses": [],
                    "supplier": {"name": "acme"},
                    "name": "Acme_Application",
                    "version": "9.1.1",
                    "hashes": [
                        {"alg": "MD5", "content": "ec7781220ec7781220ec778122012345"}
                    ],
                    "properties": [
                        {"name": "internal:component:status", "value": "internal"}
                    ],
                },
            },
            "compositions": [],
            "dependencies": [],
        }
        for spec_version in list_of_spec_versions:
            sbom["specVersion"] = spec_version
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("empty", issues), True)

    def test_internal_component_metadata_supplier_copyright_no_issue(self) -> None:
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "metadata": {
                "timestamp": "2022-02-17T10:14:58Z",
                "authors": [{"name": "automated"}],
                "component": {
                    "type": "application",
                    "bom-ref": "acme-app",
                    "copyright": "Festo SE & Co. KG 2022, all rights reserved",
                    "supplier": {"name": "festo"},
                    "name": "Acme_Application",
                    "version": "9.1.1",
                    "hashes": [
                        {"alg": "MD5", "content": "ec7781220ec7781220ec778122012345"}
                    ],
                    "properties": [
                        {"name": "internal:component:status", "value": "internal"}
                    ],
                },
            },
            "compositions": [],
            "dependencies": [],
        }
        for spec_version in list_of_spec_versions:
            sbom["specVersion"] = spec_version
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_internal_component_metadata_copyright_festo_no_supplier(self) -> None:
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "metadata": {
                "timestamp": "2022-02-17T10:14:58Z",
                "authors": [{"name": "automated"}],
                "component": {
                    "type": "application",
                    "bom-ref": "acme-app",
                    "author": "Acme",
                    "copyright": "Festo SE & Co. KG 2022, all rights reserved",
                    "name": "Acme_Application",
                    "version": "9.1.1",
                    "hashes": [
                        {"alg": "MD5", "content": "ec7781220ec7781220ec778122012345"}
                    ],
                    "properties": [
                        {"name": "internal:component:status", "value": "internal"}
                    ],
                },
            },
            "compositions": [],
            "dependencies": [],
        }
        for spec_version in list_of_spec_versions:
            sbom["specVersion"] = spec_version
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("supplier", issues), True)

    def test_component_in_tools(self) -> None:
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "metadata": {
                "timestamp": "2022-02-17T10:14:58Z",
                "authors": [{"name": "automated"}],
                "component": {
                    "type": "application",
                    "bom-ref": "acme-app",
                    "supplier": {"name": "festo"},
                    "author": "Acme",
                    "copyright": "Festo SE & Co. KG 2022, all rights reserved",
                    "name": "Acme_Application",
                    "version": "9.1.1",
                    "hashes": [
                        {"alg": "MD5", "content": "ec7781220ec7781220ec778122012345"}
                    ],
                    "properties": [
                        {"name": "internal:component:status", "value": "internal"}
                    ],
                },
                "tools": {
                    "components": [
                        {"name": "Tool A", "type": "application"},
                        {"name": "Tool B", "type": "platform"},
                    ]
                },
            },
            "compositions": [],
            "dependencies": [],
        }
        for spec_version in list_of_spec_versions_containing_licensing:
            sbom["specVersion"] = spec_version
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])


class TestValidateFilename(unittest.TestCase):
    def setUp(self) -> None:
        self.sbom = get_test_sbom()

    def test_valid_with_default_schema(self) -> None:
        for filename in ["bom.json", "random.cdx.json", "-.cdx.json"]:
            with self.subTest(filename=filename):
                result = validate_filename(filename, "", self.sbom, "default")
                self.assertFalse(result)

    def test_invalid_with_default_schema(self) -> None:
        for filename in ["bomjson", "bom.jso", "random.bom.json", ".cdx.json"]:
            with self.subTest(filename=filename):
                result = validate_filename(filename, "", self.sbom, "default")
                self.assertIsInstance(result, str)

    def test_valid_with_custom_schema(self) -> None:
        for filename in [
            "bom.json",
            "Acme_Application_9.1.1_20220217T101458.cdx.json",
            "Acme_Application_9.1.1_ec7781220ec7781220ec778122012345.cdx.json",
            "Acme_Application_9.1.1_ec7781220ec7781220ec778122012345_20220217T101458.cdx.json",
        ]:
            with self.subTest(filename=filename):
                result = validate_filename(filename, "", self.sbom, "custom")
                self.assertFalse(result)

    def test_invalid_with_custom_schema(self) -> None:
        for filename in [
            "bomjson",
            "bom.jso",
            "random.bom.json",
            ".cdx.json",
            "Acme_Application_20220217T101458.cdx.json",
            "unknown_9.1.1_ec7781220ec7781220ec778122012345.cdx.json",
            "Acme_Application_9.1.1.cdx.json",
            "Acme_Application.cdx.json",
            "Acme_Application_9.1.1_20220217T101458.json",
            "Acme_Application_9.1.1_20220217T101458.cdx",
        ]:
            with self.subTest(filename=filename):
                result = validate_filename(filename, "", self.sbom, "custom")
                self.assertIsInstance(result, str)
