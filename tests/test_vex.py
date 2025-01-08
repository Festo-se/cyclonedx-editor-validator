import json
import unittest

import cdxev.vex as vex

path_to_test_folder = "tests/auxiliary/test_vex/"


class TestVulnerabilityFunctions(unittest.TestCase):

    def test_init_vex_header(self):
        expected_output = {"bomFormat": "CycloneDX", "specVersion": "1.3", "version": 1}

        with open(
            path_to_test_folder + "bom.json", "r", encoding="utf-8-sig"
        ) as my_file:
            sbom = json.load(my_file)
        result = vex.init_vex_header(sbom)

        self.assertEquals(result, expected_output)

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

    def test_get_list_of_ids_default_missing_data(self):
        with open(
            path_to_test_folder + "list_default_missing_data.csv", "r", encoding="utf-8-sig"
        ) as my_file:
            expected_output = my_file.read()
        with open(
            path_to_test_folder + "vex_missing_data.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex.get_list_of_ids(vex_file, "default")
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
            path_to_test_folder + "list_lightweight_missing_data.csv", "r", encoding="utf-8-sig"
        ) as my_file:
            expected_output = my_file.read()
        with open(
            path_to_test_folder + "vex_missing_data.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex.get_list_of_ids(vex_file, "lightweight")
        self.assertEqual(result, expected_output)

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
        with open(
            path_to_test_folder + "searched_vex_missing_data.json", "r", encoding="utf-8-sig"
        ) as my_file:
            expected_output = json.load(my_file)

        with open(
            path_to_test_folder + "vex_missing_data.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex.get_vulnerability_by_id(vex_file, "CVE-1013-0005")
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
        result = vex.vex("extract", embedded_vex, "", "", "")
        self.assertEqual(result["vulnerabilities"], embedded_vex["vulnerabilities"])

    def test_vex_invalid_subcommand(self):
        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex.vex("invalid_command", vex_file, "", "")
        self.assertEqual(result, None) 
