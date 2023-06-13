import unittest
import json
from cdxev.plausibility_check import (
    get_upstream_dependency_bom_refs,
    check_for_orphaned_bom_refs,
    check_logic_of_dependencies,
    plausibility_check,
)
import unittest.mock
from pathlib import Path

path_to_folder_with_test_sboms = "tests/auxiliary/test_plausibility_check_sboms/"


def search_for_word_issues(word: str, issue_list: str) -> bool:
    is_valid = False
    for issue in issue_list:
        if word.lower() in str(issue).lower():
            is_valid = True
    return is_valid


def search_for_word_list_of_error_dicts(word: str, issue_list: list[dict]) -> bool:
    is_valid = False
    for issue in issue_list:
        for key in issue.keys():
            if word.lower() in issue[key].lower():
                is_valid = True
    return is_valid


@unittest.mock.patch("cdxev.plausibility_check.logger")
def plausibility_test(
    sbom: dict, mock_logger: unittest.mock.Mock, functionname: str = ""
) -> list:
    messages = "No function called"
    mock_logger.error.call_args_list = []
    if functionname == "check_orphaned_bom_refs":
        errors_occured = check_for_orphaned_bom_refs(sbom)
        return errors_occured
    elif functionname == "check_logic_of_dependencies":
        errors_occured = check_logic_of_dependencies(sbom)
        return errors_occured
    elif functionname == "plausibility_check":
        errors_occured = plausibility_check(
            sbom, file=Path("somepath"), report_format="rp", output=Path("output")
        )
        if not errors_occured:
            return "no issue"
        messages = mock_logger.error.call_args_list
    return messages


def get_dependency_test_sbom() -> dict:
    path = (
        path_to_folder_with_test_sboms
        + "sub_programm_T5.0.3.96_20220217T101458_cdx.json"
    )
    with open(path, "r") as read_file:
        sbom = json.load(read_file)
    return sbom


class TestPlausibilityCheck(unittest.TestCase):
    def test_plausibility_check_valid_sbom(self) -> None:
        sbom = get_dependency_test_sbom()
        self.assertEqual(
            plausibility_check(
                sbom, file=Path("somepath"), report_format="rp", output=Path("output")
            ),
            0,
        )

    def test_plausibility_two_orphaned_sbom(self) -> None:
        sbom = get_dependency_test_sbom()
        sbom["dependencies"][3]["dependsOn"].append("new_reference")
        sbom["dependencies"][3]["dependsOn"].append("new_reference_2")
        issues = plausibility_test(sbom, functionname="plausibility_check")
        self.assertEqual(search_for_word_issues("dependencies", issues), True)
        self.assertEqual(search_for_word_issues("new_reference", issues), True)
        self.assertEqual(search_for_word_issues("new_reference_2", issues), True)

    def test_check_logic_of_dependencies_unconnected(self) -> None:
        sbom = get_dependency_test_sbom()
        sbom["dependencies"][1]["dependsOn"] = []
        issues = plausibility_test(sbom, functionname="plausibility_check")
        self.assertTrue(search_for_word_issues("not connected", issues))
        self.assertTrue(search_for_word_issues("eight_component", issues))
        self.assertTrue(search_for_word_issues("ninth_component", issues))

    def test_check_logic_of_dependencies_unconnected_and_orphaned(self) -> None:
        sbom = get_dependency_test_sbom()
        sbom["dependencies"][1]["dependsOn"] = ["sp_seventh_component"]
        sbom["dependencies"][3]["dependsOn"].append("new_reference")
        issues = plausibility_test(sbom, functionname="plausibility_check")
        self.assertTrue(search_for_word_issues("not connected", issues))
        self.assertTrue(search_for_word_issues("eight_component", issues))
        self.assertTrue(search_for_word_issues("orphaned", issues))
        self.assertTrue(search_for_word_issues("new_reference", issues))


class TestGetListOfUpostreamDependencies(unittest.TestCase):
    def test_get_a_list_of_upstream_dependencies(self) -> None:
        sbom = get_dependency_test_sbom()
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


class TestCheckForOrphanedbom_refs(unittest.TestCase):
    def test_check_for_orphaned_bom_refs_valid_sbom(self) -> None:
        sbom = get_dependency_test_sbom()
        self.assertEqual(check_for_orphaned_bom_refs(sbom), [])

    def test_check_for_orphaned_bom_refs_dependencies(self) -> None:
        sbom = get_dependency_test_sbom()
        sbom["dependencies"][3]["ref"] = "new_reference"
        issues = plausibility_test(sbom, functionname="check_orphaned_bom_refs")
        self.assertEqual(
            search_for_word_list_of_error_dicts("dependencies", issues), True
        )

    def test_check_for_orphaned_bom_refs_dependencies_dependson(self) -> None:
        sbom = get_dependency_test_sbom()
        sbom["dependencies"][3]["dependsOn"].append("new_reference")
        issues = plausibility_test(sbom, functionname="check_orphaned_bom_refs")
        self.assertEqual(
            search_for_word_list_of_error_dicts("dependencies", issues), True
        )

    def test_check_for_orphaned_bom_refs_vulnerabilities(self) -> None:
        sbom = get_dependency_test_sbom()
        sbom["vulnerabilities"][1]["affects"][0]["ref"] = "new_reference"
        issues = plausibility_test(sbom, functionname="check_orphaned_bom_refs")
        self.assertEqual(
            search_for_word_list_of_error_dicts("vulnerabilitie", issues), True
        )

    def test_check_for_orphaned_bom_refs_compositions(self) -> None:
        sbom = get_dependency_test_sbom()
        sbom["compositions"][0]["assemblies"].append("new_reference")
        issues = plausibility_test(sbom, functionname="check_orphaned_bom_refs")
        self.assertEqual(
            search_for_word_list_of_error_dicts("compositions", issues), True
        )


class TestCheckLogicOfDependencies(unittest.TestCase):
    def test_check_logic_of_dependencies_valid_sbom(self) -> None:
        sbom = get_dependency_test_sbom()
        issues = check_logic_of_dependencies(sbom)
        self.assertEqual(issues, [])

    def test_check_logic_of_dependencies_unconnected(self) -> None:
        sbom = get_dependency_test_sbom()
        sbom["dependencies"][1]["dependsOn"] = ["sp_seventh_component"]
        issues = plausibility_test(sbom, functionname="check_logic_of_dependencies")
        self.assertTrue(search_for_word_list_of_error_dicts("not connected", issues))

    def test_check_logic_of_dependencies_circular(self) -> None:
        sbom = get_dependency_test_sbom()
        sbom["dependencies"][8]["dependsOn"].append("sp_first_component")
        issues = plausibility_test(sbom, functionname="check_logic_of_dependencies")
        self.assertTrue(search_for_word_list_of_error_dicts("circular", issues))

    def test_check_connceted_via_orphaned_bomref(self) -> None:
        sbom = get_dependency_test_sbom()
        sbom["dependencies"][1]["dependsOn"] = [
            "sp_seventh_component",
            "orphaned bom-ref",
        ]
        sbom["dependencies"].append(
            {"ref": "orphaned bom-ref", "dependsOn": ["sp_eight_component"]}
        )
        issues = plausibility_test(sbom, functionname="check_logic_of_dependencies")
        print(issues)
        self.assertTrue(search_for_word_list_of_error_dicts("orphaned", issues))
        self.assertTrue(search_for_word_list_of_error_dicts("connected", issues))
