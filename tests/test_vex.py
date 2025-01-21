import json
import unittest
from pathlib import Path

import cdxev.vex as vex

path_to_test_folder = "tests/auxiliary/test_vex/"


def load_file(file_path: Path) -> dict:
    with open(path_to_test_folder + file_path, "r", encoding="utf-8-sig") as my_file:
        vex_file = json.load(my_file)
    return vex_file


class TestVulnerabilityFunctions(unittest.TestCase):

    def test_init_vex_header(self):
        expected_output = {"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1}

        file = load_file("embedded_vex.json")
        result = vex.init_vex_header(file)

        self.assertEquals(result, expected_output)

    def test_get_list_of_ids_default(self):
        file = load_file("vex.json")
        result = vex.get_list_of_ids(file, "default")
        expected_output = (
            "ID,RefID,Description,Status\n"
            + file.get("vulnerabilities", [])[0].get("id", "-")
            + ","
            + file.get("vulnerabilities", [])[0].get("references", [])[0].get("id", "-")
            + ","
            + file.get("vulnerabilities", [])[0].get("description", "-")
            + ","
            + file.get("vulnerabilities", [])[0].get("analysis", {}).get("state", "-")
            + "\n"
        )
        self.assertEqual(result, expected_output)

    def test_get_list_of_ids_default_missing_data(self):
        file = load_file("vex.json")
        file.get("vulnerabilities", [])[0].pop("id")
        file.get("vulnerabilities", [])[0].pop("description")
        file.get("vulnerabilities", [])[0].get("references", [])[0].pop("id")
        file.get("vulnerabilities", [])[0].get("analysis", {}).pop("state")

        expected_output = "ID,RefID,Description,Status\n" + "-,-,-,-\n"
        result = vex.get_list_of_ids(file, "default")
        self.assertEqual(result, expected_output)

    def test_get_list_of_ids_lightweight(self):
        file = load_file("vex.json")
        expected_output = (
            "ID,RefID\n"
            + file.get("vulnerabilities", [])[0].get("id", "-")
            + ","
            + file.get("vulnerabilities", [])[0].get("references", [])[0].get("id", "-")
            + "\n"
        )
        result = vex.get_list_of_ids(file, "lightweight")
        self.assertEqual(result, expected_output)

    def test_get_list_of_trimmed_vulnerabilities(self):
        file = load_file("vex.json")
        file.get("vulnerabilities").append(
            {"id": "CVE-2020-25649", "analysis": {"state": "exploitable"}}
        )
        expected_output = file
        expected_output.get("vulnerabilities", []).pop(1)
        result = vex.get_list_of_trimed_vulnerabilities(file, "not_affected")
        self.assertEqual(result, expected_output)

    def test_get_vulnerability_by_id(self):
        file = load_file("vex.json")
        file.get("vulnerabilities").append(file.get("vulnerabilities")[0].copy())
        file.get("vulnerabilities")[1]["id"] = "CVE-2020-25648"
        expected_output = file
        expected_output.get("vulnerabilities", []).pop(1)
        result = vex.get_vulnerability_by_id(file, "CVE-2020-25649")
        self.assertEqual(result, expected_output)

    def test_get_vulnerability_by_id_missing_data(self):
        file = load_file("vex.json")
        file.get("vulnerabilities", [])[0].pop("id")
        expected_output = file
        result = vex.get_vulnerability_by_id(
            file, "SNYK-JAVA-COMFASTERXMLJACKSONCORE-1048302"
        )
        self.assertEqual(result, expected_output)

    def test_get_vex_from_sbom(self):
        file = load_file("embedded_vex.json")
        result = vex.get_vex_from_sbom(file)
        self.assertEqual(result, load_file("vex.json"))

    # Test subcommands
    def test_vex_list_command(self):

        result = vex.vex("list", load_file("vex.json"), "", "default")
        self.assertIn("ID,RefID,Description,Status", result)

    def test_vex_trim_command(self):

        result = vex.vex("trim", load_file("vex.json"), "not_affected", "")
        self.assertEqual(len(result["vulnerabilities"]), 1)

    def test_vex_search_command(self):

        result = vex.vex("search", load_file("vex.json"), "", "", "CVE-2020-25649")
        self.assertEqual(len(result["vulnerabilities"]), 1)

    def test_vex_extract_command(self):
        with open(
            path_to_test_folder + "embedded_vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            embedded_vex = json.load(my_file)
        result = vex.vex("extract", embedded_vex, "", "", "")
        self.assertEqual(result["vulnerabilities"], embedded_vex["vulnerabilities"])

    def test_vex_invalid_subcommand(self):

        result = vex.vex("invalid_command", load_file("vex.json"), "", "")
        self.assertEqual(result, {})
