import copy
import json
import re
import unittest
from pathlib import Path

import cdxev.vex as vex
import cdxev.vex as vex

path_to_test_folder = "tests/auxiliary/test_vex/"


def load_file(file_path: Path) -> dict:
    with open(path_to_test_folder + file_path, "r", encoding="utf-8-sig") as my_file:
        vex_file = json.load(my_file)
    return vex_file


class TestVulnerabilityFunctions(unittest.TestCase):

    def test_init_vex_header(self):
        expected_output = {"bomFormat": "CycloneDX", "specVersion": "1.3", "version": 1}

        with open(
            path_to_test_folder + "bom.json", "r", encoding="utf-8-sig"
        ) as my_file:
            sbom = json.load(my_file)
        result = vex.init_vex_header(sbom)

        self.assertEqual(result, expected_output)

    def test_get_list_of_ids_default(self):
        with open(
            path_to_test_folder + "list_default.csv", "r", encoding="utf-8-sig"
        ) as my_file:
            expected_output = my_file.read()
        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex.get_list_of_ids(vex_file, "default")
        self.assertEqual(result, expected_output)

    def test_get_list_of_ids_default_missing_id(self):
        file = load_file("vex.json")
        expected_output = self.helper_list_output()
        id = file["vulnerabilities"][0]["id"]
        expected_output = expected_output.replace(id, "-")
        file["vulnerabilities"][0].pop("id")
        result = vex.get_list_of_ids(file, "default")
        self.assertEqual(result, expected_output)

    def test_get_list_of_ids_default_missing_references(self):
        file = load_file("vex.json")
        expected_output = self.helper_list_output()
        references = file["vulnerabilities"][0]["references"][0]["id"]
        expected_output = expected_output.replace(references, "-")
        file["vulnerabilities"][0].pop("references")
        result = vex.get_list_of_ids(file, "default")
        self.assertEqual(result, expected_output)

    def test_get_list_of_ids_default_missing_references_id(self):
        file = load_file("vex.json")
        expected_output = self.helper_list_output()
        references = file["vulnerabilities"][0]["references"][0]["id"]
        expected_output = expected_output.replace(references, "-")
        file["vulnerabilities"][0]["references"][0].pop("id")
        result = vex.get_list_of_ids(file, "default")
        self.assertEqual(result, expected_output)

    def test_get_list_of_ids_default_missing_description(self):
        file = load_file("vex.json")
        expected_output = self.helper_list_output()
        description = re.sub(
            r"[\t\n\r\|]+", "", file["vulnerabilities"][0]["description"]
        )
        expected_output = expected_output.replace(description, "-")
        file["vulnerabilities"][0].pop("description")
        result = vex.get_list_of_ids(file, "default")
        self.assertEqual(result, expected_output)

    def test_get_list_of_ids_default_missing_analysis(self):
        file = load_file("vex.json")
        expected_output = self.helper_list_output()
        state = file["vulnerabilities"][0]["analysis"]["state"]
        expected_output = expected_output.replace(state, "-")
        file["vulnerabilities"][0].pop("analysis")
        result = vex.get_list_of_ids(file, "default")
        self.assertEqual(result, expected_output)

    def test_get_list_of_ids_default_missing_analysis_state(self):
        file = load_file("vex.json")
        expected_output = self.helper_list_output()
        state = file["vulnerabilities"][0]["analysis"]["state"]
        expected_output = expected_output.replace(state, "-")
        file["vulnerabilities"][0]["analysis"].pop("state")
        result = vex.get_list_of_ids(file, "default")
        self.assertEqual(result, expected_output)

    def test_get_list_of_ids_lightweight(self):
        with open(
            path_to_test_folder + "list_lightweight.csv", "r", encoding="utf-8-sig"
        ) as my_file:
            expected_output = my_file.read()

        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex.get_list_of_ids(vex_file, "lightweight")
        self.assertEqual(result, expected_output)

    def test_get_list_of_ids_lightweight_missing_data(self):
        with open(
            path_to_test_folder + "list_lightweight_missing_data.csv",
            "r",
            encoding="utf-8-sig",
        ) as my_file:
            expected_output = my_file.read()
        with open(
            path_to_test_folder + "vex_missing_data.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex.get_list_of_ids(vex_file, "lightweight")
        self.assertEqual(result, expected_output)

    def test_search_key(self):
        test_dict = {
            "key1": "value",
            "key2": "value",
            "nested": {"nested_key1": "value", "nested": {"key3": "test"}},
        }
        result = vex.search_key(test_dict, "key3", "test")
        self.assertEqual(result, True)

    def test_search_key_not_found(self):
        test_dict = {
            "key1": "value",
            "key2": "value",
            "nested": {"nested_key1": "value", "nested": {"key3": "test"}},
        }
        result = vex.search_key(test_dict, "key3", "value")
        self.assertEqual(result, False)

    def test_search_key_not_dict(self):
        test_dict = {}
        result = vex.search_key(test_dict, "key", "value")
        self.assertEqual(result, False)

    def test_get_list_of_trimmed_vulnerabilities(self):
        with open(
            path_to_test_folder + "trimmed_vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            expected_output = json.load(my_file)

        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex.get_list_of_trimed_vulnerabilities(vex_file, "not_affected")
        self.assertEqual(result, expected_output)

    def test_get_list_of_trimmed_vulnerabilities_not_found_keyval_pair(self):
        file = load_file("vex.json")
        expected_output = []
        result = vex.get_list_of_trimed_vulnerabilities(file, "test", "test")
        self.assertEqual(result.get("vulnerabilities"), expected_output)

    def test_get_vulnerability_by_id(self):
        with open(
            path_to_test_folder + "searched_vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            expected_output = json.load(my_file)

        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex.get_vulnerability_by_id(vex_file, "CVE-1013-0002")
        self.assertEqual(result, expected_output)

    def test_get_vulnerability_by_id_missing_data(self):
        file = load_file("vex.json")
        file["vulnerabilities"][0].pop("id")
        expected_output = copy.deepcopy(file)
        result = vex.get_vulnerability_by_id(
            file, "SNYK-JAVA-COMFASTERXMLJACKSONCORE-1048302"
        )
        self.assertEqual(result, expected_output)

    def test_get_vex_from_sbom(self):
        with open(
            path_to_test_folder + "embedded_vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            embedded_vex = json.load(my_file)

        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)

        result = vex.get_vex_from_sbom(embedded_vex)
        self.assertEqual(result, vex_file)

    # Test subcommands
    def test_vex_list_command(self):
        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex.vex("list", vex_file, "", "default")
        self.assertIn("ID,RefID,Description,Status", result)

    def test_vex_trim_command(self):
        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex.vex("trim", vex_file, "not_affected", "")
        self.assertEqual(len(result["vulnerabilities"]), 8)

    def test_vex_search_command(self):
        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex.vex("search", vex_file, "", "", "CVE-1013-0002")
        self.assertEqual(len(result["vulnerabilities"]), 1)

    def test_vex_extract_command(self):
        with open(
            path_to_test_folder + "embedded_vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            embedded_vex = json.load(my_file)
        result = vex.vex("extract", embedded_vex, "", "", "", "")
        self.assertEqual(result["vulnerabilities"], embedded_vex["vulnerabilities"])

    def test_vex_invalid_subcommand(self):
        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex.vex("invalid_command", vex_file, "", "")
        self.assertEqual(result, {})
