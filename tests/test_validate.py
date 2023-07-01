import json
import os
import unittest
from pathlib import Path
from unittest import mock

from cdxev.error import AppError
from cdxev.validator.validate import validate_sbom
from cdxev.validator.helper import (
    create_error_non_unique_bom_ref,
    get_errors_for_non_unique_bomrefs,
    plausibility_check,
    get_upstream_dependency_bom_refs,
    check_for_orphaned_bom_refs,
)
from cdxev.auxiliary.identity import ComponentIdentity

path_to_folder_with_test_sboms = "tests/auxiliary/test_validate_sboms/"

path_to_sbom = (
    path_to_folder_with_test_sboms + "Acme_Application_9.1.1_20220217T101458.cdx.json"
)

path_to_second_sbom = (
    path_to_folder_with_test_sboms + "sub_programm_T5.0.3.96_20220217T101458_cdx.json"
)

path_to_modified_sbom = (
    path_to_folder_with_test_sboms + "modified_sbom/"
    "Acme_Application_9.1.1_20220217T101458.cdx.json"
)

list_of_specVersions = ["1.3", "1.4"]


def search_for_word_issues(word: str, issue_list: list) -> bool:
    is_valid = False
    for issue in issue_list:
        if word.lower() in str(issue[0][0]).lower():
            is_valid = True
    return is_valid


def search_for_word_list_of_errors(word: str, issue_list: list) -> bool:
    is_valid = False
    for issue in issue_list:
        if word.lower() in issue.lower():
            is_valid = True
    return is_valid


@mock.patch("cdxev.validator.validate.logger")
def validate_test(
    sbom: dict,
    mock_logger: unittest.mock.Mock,
    report_format: str = "stdout",
    filename_regex: str = "",
    schema_type: str = "custom",
    schema_path: str = "",
    plausability_check: str = "no",
) -> list:
    mock_logger.error.call_args_list = []
    errors_occurred = validate_sbom(
        sbom=sbom,
        input_format="json",
        file=Path(path_to_sbom),
        report_format=report_format,
        output=Path(""),
        schema_type=schema_type,
        filename_regex=filename_regex,
        schema_path=schema_path,
        plausability_check=plausability_check,
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
    def test_filename_regex(self) -> None:
        filename_regex = ".*"
        sbom = get_test_sbom()
        issues = validate_test(sbom, filename_regex=filename_regex)
        self.assertEqual(issues, ["no issue"])

    def test_wrong_filename(self) -> None:
        filename_regex = "(myfancybom.json)"
        sbom = get_test_sbom()
        issues = validate_test(sbom, filename_regex=filename_regex)
        self.assertTrue(search_for_word_issues("file name is not according to", issues))

    @unittest.skipUnless("CI" in os.environ, "running only in CI")
    def test_custom_schema(self) -> None:
        sbom = get_test_sbom()
        issues = validate_test(sbom, schema_type="default")
        self.assertEqual(issues, ["no issue"])

    def test_warnings_ng_format(self) -> None:
        sbom = get_test_sbom()
        sbom["components"][0].pop("version")
        issues = validate_test(sbom, report_format="warnings-ng")
        self.assertTrue(
            search_for_word_issues("'version' is a required property", issues)
        )


class TestValidateMetadata(unittest.TestCase):
    def test_metadata_missing(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom.pop("metadata")
            issues = validate_test(sbom)
            self.assertTrue(search_for_word_issues("metadata", issues))

    def test_timestamp(self) -> None:
        for spec_version in list_of_specVersions:
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
            self.assertEqual(search_for_word_issues("name", issues), True)

    def test_metadata_authors_missing(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"].pop("authors")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("authors", issues), True)

    def test_metadata_authors_name_missing(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["authors"][0].pop("name")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("name", issues), True)
            self.assertEqual(search_for_word_issues("authors", issues), True)

    def test_metadata_component_missing(self) -> None:
        for spec_version in list_of_specVersions:
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
            "group",
            "version",
            "bom-ref",
        ]:
            for spec_version in list_of_specVersions:
                sbom = get_test_sbom()
                sbom["specVersion"] = spec_version
                sbom["metadata"]["component"].pop(fields)
                issues = validate_test(sbom)
                self.assertEqual(search_for_word_issues(fields, issues), True)

    def test_metadata_component_supplier_missing(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["component"].pop("supplier")
            sbom["metadata"]["component"]["publisher"] = "pup"
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["metadata"]["component"].pop("supplier")
            sbom["metadata"]["component"]["author"] = "pup"
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_metadata_internal_component_copyright_missing(self) -> None:
        for spec_version in list_of_specVersions:
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
        for spec_version in list_of_specVersions:
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
            "Unable to load schema for specVersion " + sbom["specVersion"],
            ae.exception.details.description,
        )

    def test_metadata_illegitimate_bomFormat(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["bomFormat"] = "wrongFormat"
            issues = validate_test(sbom)
            self.assertTrue(search_for_word_issues("CycloneDX", issues))


class TestValidateComponents(unittest.TestCase):
    def test_components_empty(self) -> None:
        for spec_version in list_of_specVersions:
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
                for spec_version in list_of_specVersions:
                    sbom = get_test_sbom()
                    sbom["specVersion"] = spec_version
                    sbom["components"][component_number].pop(fields)
                    issues = validate_test(sbom)
                    self.assertEqual(search_for_word_issues(fields, issues), True)

    def test_components_component_supplier_etc(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0].pop("supplier")
            issues = validate_test(sbom)
            self.assertEqual(
                search_for_word_issues("supplier", issues)
                or search_for_word_issues("authors", issues)
                or search_for_word_issues("publisher", issues),
                True,
            )

    def test_components_component_license_and_copyright_missing(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0].pop("licenses")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("licenses", issues), True)

    def test_components_component_copyright_instead_of_license_etc(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0].pop("licenses")
            sbom["components"][0]["copyright"] = "ppp"
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_components_component_license_or_expression(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {"license": {"name": "Apache-2.0"}, "expression": "Apache-2.0"}
            ]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("expression", issues), True)
            self.assertEqual(search_for_word_issues("license", issues), True)

    def test_components_component_license_expression(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [{"expression": "Apache-2.0"}]
            issues = validate_test(sbom)
            self.assertEqual(issues, ["no issue"])

    def test_components_license_without_name_and_id(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [{"license": {}}]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("name", issues), True)
            self.assertEqual(search_for_word_issues("id", issues), True)

    def test_components_license_additional_fields(self) -> None:
        for spec_version in list_of_specVersions:
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

    def test_components_license_name_without_text(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [{"license": {"name": "something"}}]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("text", issues), True)

    def test_components_license_text_without_content(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["licenses"] = [
                {"license": {"name": "something", "text": {}}}
            ]
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("content", issues), True)

    def test_components_license_wrong_spdxid(self) -> None:
        for spec_version in list_of_specVersions:
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

    def test_components_component_copyright(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][-1].pop("copyright")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("copyright", issues), True)

    def test_version_short(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["components"][0]["version"] = ""
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("must not be empty", issues), True)


class TestValidateDependencies(unittest.TestCase):
    def test_dependencies_missing(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom.pop("dependencies")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("dependencies", issues), True)

    def test_dependencies_ref_missing(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["dependencies"][0].pop("ref")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("ref", issues), True)

    def test_dependencies_duplicate_dependsOn(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["dependencies"][0]["dependsOn"].append(
                sbom["dependencies"][0]["dependsOn"][0]
            )
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("are non-unique", issues), True)


class TestValidateCompositions(unittest.TestCase):
    def test_compositions_missing(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom.pop("compositions")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("compositions", issues), True)

    def test_compositions_aggregate_missing(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["compositions"][0].pop("aggregate")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("aggregate", issues), True)

    def test_compositions_assemblies_missing(self) -> None:
        for spec_version in list_of_specVersions:
            sbom = get_test_sbom()
            sbom["specVersion"] = spec_version
            sbom["compositions"][0].pop("assemblies")
            issues = validate_test(sbom)
            self.assertEqual(search_for_word_issues("assemblies", issues), True)

    def test_compositions_aggregate_not_valid(self) -> None:
        for spec_version in list_of_specVersions:
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
                str(Path(__file__).parent.resolve())
                + "/auxiliary/test_validate_sboms/test_schema.json"
            ),
        )
        self.assertEqual(v, 0)

    def test_use_own_schema_path_does_not_exist(self) -> None:
        sbom = get_test_sbom()
        with self.assertRaises(AppError) as ap:
            validate_test(sbom, schema_path="No_Path")
        self.assertIn(
            "Path to the provided schema does not exist",
            ap.exception.details.description,
        )

    def test_use_own_schema_invalid_JSON(self) -> None:
        sbom = get_test_sbom()
        with self.assertRaises(AppError) as ap:
            validate_test(sbom, schema_path="cdxev/auxiliary/schema")
        self.assertIn(
            (
                "The submitted schema is not a valid"
                " JSON file and could not be loaded"
            ),
            ap.exception.details.description,
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
        )
        self.assertEqual(v, 0)


class TestPlausabilityCheck(unittest.TestCase):
    def test_not_unique_bom_ref(self) -> None:
        sbom = get_test_sbom()
        sbom["components"][0]["bom-ref"] = "some-ref"
        sbom["components"][-1]["bom-ref"] = "some-ref"
        issues = validate_test(sbom)
        self.assertEqual(search_for_word_issues("non unique bom-ref", issues), True)

    def test_non_unique_bomref_in_Metadata(self) -> None:
        sbom = get_test_sbom()
        sbom["metadata"]["component"]["bom-ref"] = "bom-ref_1"
        sbom["components"][-1]["bom-ref"] = "bom-ref_1"
        issues = validate_test(sbom)
        self.assertEqual(search_for_word_issues("non unique bom-ref", issues), True)

    def test_several_non_unique_bomref_in_Metadata(self) -> None:
        sbom = get_test_sbom()
        sbom["metadata"]["component"]["bom-ref"] = "bom-ref_1"
        sbom["components"][-1]["bom-ref"] = "bom-ref_1"
        sbom["components"][1]["bom-ref"] = "bom-ref_2"
        sbom["components"][-2]["bom-ref"] = "bom-ref_2"
        issues = validate_test(sbom)
        self.assertEqual(search_for_word_issues("non unique bom-ref", issues), True)

    def test_plausibility_check_valid_sbom(self) -> None:
        sbom = get_test_sbom()
        self.assertEqual(plausibility_check(sbom), [])

    def test_check_for_orphaned_bom_refs_dependencies(self) -> None:
        sbom = get_test_sbom(path_to_second_sbom)
        sbom["dependencies"][3]["ref"] = "new_reference"
        issues = plausibility_check(sbom)
        self.assertEqual(search_for_word_list_of_errors("dependencies", issues), True)

    def test_check_for_orphaned_bom_refs_dependencies_dependson(self) -> None:
        sbom = get_test_sbom(path_to_second_sbom)
        sbom["dependencies"][3]["dependsOn"].append("new_reference")
        issues = plausibility_check(sbom)
        self.assertEqual(search_for_word_list_of_errors("dependencies", issues), True)

    def test_check_for_orphaned_bom_refs_vulnerabilities(self) -> None:
        sbom = get_test_sbom(path_to_second_sbom)
        sbom["vulnerabilities"][1]["affects"][0]["ref"] = "new_reference"
        issues = plausibility_check(sbom)
        self.assertEqual(search_for_word_list_of_errors("vulnerabilitie", issues), True)

    def test_check_for_orphaned_bom_refs_compositions(self) -> None:
        sbom = get_test_sbom(path_to_second_sbom)
        sbom["compositions"][0]["assemblies"].append("new_reference")
        issues = plausibility_check(sbom)
        self.assertEqual(search_for_word_list_of_errors("compositions", issues), True)

    def test_validate_active_plausibility_check(self) -> None:
        sbom = get_test_sbom()
        sbom["compositions"][0]["assemblies"].append("new_ref")
        issues = validate_test(sbom, plausability_check="yes")
        print(issues)
        self.assertEqual(search_for_word_issues("orphaned bom-ref", issues), True)


class TestPlausabilityHelperFunctions(unittest.TestCase):
    def test_one_non_unique_bom_ref(self) -> None:
        sbom = get_test_sbom()
        sbom["components"][0]["bom-ref"] = "bom-ref_1"
        sbom["components"][-1]["bom-ref"] = "bom-ref_1"
        error = create_error_non_unique_bom_ref("bom-ref_1", sbom)
        id_1 = ComponentIdentity.create(sbom["components"][0], allow_unsafe=True)
        id_2 = ComponentIdentity.create(sbom["components"][-1], allow_unsafe=True)
        expected_error = (
            "SBOM has the mistake: found non unique bom-ref. "
            "The reference (bom-ref_1) is used in several components. Those are"
            f"({id_1})"
            f"({id_2})"
        )
        self.assertEqual(error, expected_error)

    def test_get_errors_non_unique_sbom(self) -> None:
        sbom = get_test_sbom()
        sbom["components"][0]["bom-ref"] = "bom-ref_1"
        sbom["components"][-1]["bom-ref"] = "bom-ref_1"
        error = get_errors_for_non_unique_bomrefs(sbom)
        id_1 = ComponentIdentity.create(sbom["components"][0], allow_unsafe=True)
        id_2 = ComponentIdentity.create(sbom["components"][-1], allow_unsafe=True)
        expected_error = (
            "SBOM has the mistake: found non unique bom-ref. "
            "The reference (bom-ref_1) is used in several components. Those are"
            f"({id_1})"
            f"({id_2})"
        )
        self.assertEqual(error, [expected_error])

    def test_plausibility_two_orphaned_sbom(self) -> None:
        sbom = get_test_sbom()
        sbom["dependencies"][3]["dependsOn"].append("new_reference")
        sbom["dependencies"][3]["dependsOn"].append("new_reference_2")
        list_of_errors = plausibility_check(sbom)
        self.assertEqual(
            search_for_word_list_of_errors("dependencies", list_of_errors), True
        )
        self.assertEqual(
            search_for_word_list_of_errors("new_reference", list_of_errors), True
        )
        self.assertEqual(
            search_for_word_list_of_errors("new_reference_2", list_of_errors), True
        )

    def test_get_a_list_of_upstream_dependencies(self) -> None:
        sbom = get_test_sbom(path_to_second_sbom)
        list_of_upstream_dependencies = get_upstream_dependency_bom_refs(
            "sub_programm", sbom["dependencies"]
        )
        list_of_dependencies = [
            "sp_first_component",
            "sp_second_component",
            "sp_fourth_component",
            "sp_fifth_component",
            "sp_sixth_component",
            "sp_seventh_component",
            "sp_eight_component",
            "sp_ninth_component",
            "sp_tenth_component",
            "sp_eleventh_component",
            "sp_twelfth_component",
            "sp_thirteenth_component",
            "sp_fourteenth_component",
            "sp_sixteenth_component",
            "sp_seventeenth_component",
            "sp_fifteenth_component",
        ]
        self.assertEqual(set(list_of_upstream_dependencies), set(list_of_dependencies))
        list_of_upstream_dependencies = get_upstream_dependency_bom_refs(
            "sp_seventeenth_component", sbom["dependencies"]
        )
        self.assertEqual(set(list_of_upstream_dependencies), set([]))
        list_of_upstream_dependencies = get_upstream_dependency_bom_refs(
            "sp_fifth_component", sbom["dependencies"]
        )
        self.assertEqual(
            set(list_of_upstream_dependencies), set(["sp_seventeenth_component"])
        )
        list_of_upstream_dependencies = get_upstream_dependency_bom_refs(
            "sp_seventh_component", sbom["dependencies"]
        )
        list_of_dependencies = [
            "sp_ninth_component",
            "sp_twelfth_component",
            "sp_seventeenth_component",
            "sp_thirteenth_component",
            "sp_fourteenth_component",
            "sp_fifteenth_component",
            "sp_sixteenth_component",
            "sp_eleventh_component",
            "sp_tenth_component",
        ]
        self.assertEqual(set(list_of_upstream_dependencies), set(list_of_dependencies))

    def test_check_for_orphaned_bom_refs_valid_sbom(self) -> None:
        sbom = get_test_sbom(path_to_second_sbom)
        self.assertEqual(check_for_orphaned_bom_refs(sbom), [])
