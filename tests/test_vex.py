
import json
import unittest

from cdxev.vex import *

path_to_test_folder = (
    "tests/auxiliary/test_vex/"
)

class TestVulnerabilityFunctions(unittest.TestCase):

    def test_init_vex_header(self):
        expected_output = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "version": 1
        }

        with open(
            path_to_test_folder + "bom.json", "r", encoding="utf-8-sig"
        ) as my_file:
            sbom = json.load(my_file)
        result = init_vex_header(sbom)
            
        self.assertEquals(result, expected_output)

    def test_get_list_of_ids_default(self):
        expected_output = ("CVE-ID,Description,Status\nCVE-1012-0001,some description of a vulnerability,exploitable\nCVE-1013-0002,some description of a vulnerability 2,not_affected\nCVE-1013-0003,some description of a vulnerability 3,exploitable\nCVE-1013-0004,some description of a vulnerability 4,exploitable\nCVE-1013-0005,some description of a vulnerability 5,not_affected\nCVE-1013-0006,some description of a vulnerability 5,not_affected\nCVE-1012-0007,some description of a vulnerability 6,exploitable\nCVE-1013-0008,some description of a vulnerability 7,not_affected\nCVE-1013-0009,some description of a vulnerability 8,not_affected\nCVE-1013-0010,some description of a vulnerability 9,not_affected\nCVE-1013-0011,some description of a vulnerability 10,not_affected\nCVE-1012-0012,some description of a vulnerability 11,exploitable\nCVE-1012-0013,some description of a vulnerability 12,not_affected\nCVE-1012-0014,some description of a vulnerability 13,exploitable\n")
        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex = json.load(my_file)
        result = get_list_of_ids(vex, "default")
        self.assertEqual(result, expected_output)

    def test_get_list_of_ids_lightweight(self):
        expected_output = "CVE-ID\nCVE-1012-0001\nCVE-1013-0002\nCVE-1013-0003\nCVE-1013-0004\nCVE-1013-0005\nCVE-1013-0006\nCVE-1012-0007\nCVE-1013-0008\nCVE-1013-0009\nCVE-1013-0010\nCVE-1013-0011\nCVE-1012-0012\nCVE-1012-0013\nCVE-1012-0014\n"
        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex = json.load(my_file)
        result = get_list_of_ids(vex, "lightweight")
        self.assertEqual(result, expected_output)

    def test_get_list_of_trimmed_vulnerabilities(self):
        expected_output = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "version": 1,
            "vulnerabilities": [
                {
                    "description": "some description of a vulnerability 2",
                    "id": "CVE-1013-0002",
                    "ratings": [
                        {
                            "score": 7.2,
                            "severity": "high",
                            "method": "CVSSv31",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
                        }
                    ],
                    "published": "1013-01-01T01:02Z",
                    "updated": "1013-03-02T12:24Z",
                    "affects": [
                        {
                            "ref": "11231231"
                        }
                    ],
                    "analysis": {
                        "state": "not_affected",
                        "justification": "add justification here",
                        "response": [
                            "add response here",
                            "more than one response is possible"
                        ],
                        "detail": "the fields state, justification and response are enums, please see CycloneDX specification"
                    }
                },
                {
                    "description": "some description of a vulnerability 5",
                    "id": "CVE-1013-0005",
                    "ratings": [
                        {
                            "score": 9.8,
                            "severity": "critical",
                            "method": "CVSSv31",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        }
                    ],
                    "published": "1013-01-01T01:03Z",
                    "updated": "1013-03-03T12:24Z",
                    "affects": [
                        {
                            "ref": "11231231"
                        }
                    ],
                    "analysis": {
                        "state": "not_affected",
                        "justification": "add justification here",
                        "response": [
                            "add response here",
                            "more than one response is possible"
                        ],
                        "detail": "the fields state, justification and response are enums, please see CycloneDX specification"
                    }
                },
                {
                    "description": "some description of a vulnerability 5",
                    "id": "CVE-1013-0006",
                    "ratings": [
                        {
                            "score": 7.2,
                            "severity": "high",
                            "method": "CVSSv31",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
                        }
                    ],
                    "published": "1013-01-01T01:03Z",
                    "updated": "1013-03-04T12:24Z",
                    "affects": [
                        {
                            "ref": "11231231"
                        }
                    ],
                    "analysis": {
                        "state": "not_affected",
                        "justification": "add justification here",
                        "response": [
                            "add response here",
                            "more than one response is possible"
                        ],
                        "detail": "the fields state, justification and response are enums, please see CycloneDX specification"
                    }
                },
                {
                    "description": "some description of a vulnerability 7",
                    "id": "CVE-1013-0008",
                    "ratings": [
                        {
                            "score": 7.2,
                            "severity": "high",
                            "method": "CVSSv31",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
                        }
                    ],
                    "published": "1013-01-01T01:05Z",
                    "updated": "1013-03-07T12:24Z",
                    "affects": [
                        {
                            "ref": "11231231"
                        }
                    ],
                    "analysis": {
                        "state": "not_affected",
                        "justification": "add justification here",
                        "response": [
                            "add response here",
                            "more than one response is possible"
                        ],
                        "detail": "the fields state, justification and response are enums, please see CycloneDX specification"
                    }
                },
                {
                    "description": "some description of a vulnerability 8",
                    "id": "CVE-1013-0009",
                    "ratings": [
                        {
                            "score": 7.2,
                            "severity": "high",
                            "method": "CVSSv31",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
                        }
                    ],
                    "published": "1013-01-01T01:05Z",
                    "updated": "1013-03-07T12:24Z",
                    "affects": [
                        {
                            "ref": "11231231"
                        }
                    ],
                    "analysis": {
                        "state": "not_affected",
                        "justification": "add justification here",
                        "response": [
                            "add response here",
                            "more than one response is possible"
                        ],
                        "detail": "the fields state, justification and response are enums, please see CycloneDX specification"
                    }
                },
                {
                    "description": "some description of a vulnerability 9",
                    "id": "CVE-1013-0010",
                    "ratings": [
                        {
                            "score": 7.2,
                            "severity": "high",
                            "method": "CVSSv31",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
                        }
                    ],
                    "published": "1013-01-01T01:06Z",
                    "updated": "1013-03-08T12:24Z",
                    "affects": [
                        {
                            "ref": "11231231"
                        }
                    ],
                    "analysis": {
                        "state": "not_affected",
                        "justification": "add justification here",
                        "response": [
                            "add response here",
                            "more than one response is possible"
                        ],
                        "detail": "the fields state, justification and response are enums, please see CycloneDX specification"
                    }
                },
                {
                    "description": "some description of a vulnerability 10",
                    "id": "CVE-1013-0011",
                    "ratings": [
                        {
                            "score": 7.2,
                            "severity": "high",
                            "method": "CVSSv31",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
                        }
                    ],
                    "published": "1013-01-01T01:06Z",
                    "updated": "1013-03-09T12:24Z",
                    "affects": [
                        {
                            "ref": "11231231"
                        }
                    ],
                    "analysis": {
                        "state": "not_affected",
                        "justification": "add justification here",
                        "response": [
                            "add response here",
                            "more than one response is possible"
                        ],
                        "detail": "the fields state, justification and response are enums, please see CycloneDX specification"
                    }
                },
                {
                    "description": "some description of a vulnerability 12",
                    "id": "CVE-1012-0013",
                    "ratings": [
                        {
                            "score": 5.3,
                            "severity": "medium",
                            "method": "CVSSv31",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
                        },
                        {
                            "score": 5.0,
                            "severity": "medium",
                            "method": "CVSSv2",
                            "vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N"
                        }
                    ],
                    "published": "1012-01-01T01:08Z",
                    "updated": "1013-03-12T12:24Z",
                    "affects": [
                        {
                            "ref": "ref_first_component@1.3.3"
                        }
                    ],
                    "analysis": {
                        "state": "not_affected",
                        "justification": "add justification here",
                        "response": [
                            "add response here",
                            "more than one response is possible"
                        ],
                        "detail": "the fields state, justification and response are enums, please see CycloneDX specification"
                    }
                }
            ]
        }
        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex = json.load(my_file)
        result = get_list_of_trimed_vulnerabilities(vex, "not_affected")
        self.assertEqual(result, expected_output)

    def test_get_vulnerability_by_id(self):
        expected_output = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "version": 1,
            "vulnerabilities": [
                {
                    "description": "some description of a vulnerability 2",
                    "id": "CVE-1013-0002",
                    "ratings": [
                        {
                            "score": 7.2,
                            "severity": "high",
                            "method": "CVSSv31",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
                        }
                    ],
                    "published": "1013-01-01T01:02Z",
                    "updated": "1013-03-02T12:24Z",
                    "affects": [
                        {
                            "ref": "11231231"
                        }
                    ],
                    "analysis": {
                        "state": "not_affected",
                        "justification": "add justification here",
                        "response": [
                            "add response here",
                            "more than one response is possible"
                        ],
                        "detail": "the fields state, justification and response are enums, please see CycloneDX specification"
                    }
                }
            ]
        }
        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex = json.load(my_file)
        result = get_vulnerability_by_id(vex, "CVE-1013-0002")
        self.assertEqual(result, expected_output)

    def test_get_vex_from_sbom(self):
        with open(
            path_to_test_folder + "embedded_vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            embedded_vex = json.load(my_file)

        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex = json.load(my_file)
        
        result = get_vex_from_sbom(embedded_vex)
        self.assertEqual(result, vex)

#Test subcommands
    def test_vex_list_command(self):
        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex("list", vex_file, "", "default")
        self.assertIn("CVE-ID,Description,Status", result)

    def test_vex_trim_command(self):
        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex("trim", vex_file, "not_affected", "")
        self.assertEqual(len(result["vulnerabilities"]), 8)

    def test_vex_search_command(self):
        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        result = vex("search", vex_file, "", "", "CVE-1013-0002")
        self.assertEqual(len(result["vulnerabilities"]), 1)

    def test_vex_extract_command(self):
        with open(
            path_to_test_folder + "embedded_vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            embedded_vex = json.load(my_file)
        result = vex("extract", embedded_vex, "", "", "")
        self.assertEqual(result["vulnerabilities"], embedded_vex["vulnerabilities"])
    
    def test_vex_invalid_subcommand(self):
        with open(
            path_to_test_folder + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex_file = json.load(my_file)
        with self.assertRaises(ValueError):  # or return an error message if you handle it differently
            vex("invalid_command", vex_file, "", "")