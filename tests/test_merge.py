# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import unittest

from cdxev import merge
from cdxev.auxiliary.identity import ComponentIdentity, VulnerabilityIdentity
from tests.auxiliary import helper as helper

path_to_folder_with_test_sboms = "tests/auxiliary/test_merge_sboms/"


class TestCompareSboms(unittest.TestCase):
    def test_equal(self) -> None:
        sbom1 = helper.load_governing_program()
        self.assertTrue(helper.compare_sboms(sbom1, sbom1))

    def test_unequal(self) -> None:
        sbom1 = helper.load_governing_program()
        sbom2 = helper.load_sub_program()
        self.assertFalse(helper.compare_sboms(sbom1, sbom2))


class TestMergeSboms(unittest.TestCase):
    def test_no_vulnerabilities(self) -> None:
        sbom1 = helper.load_governing_program()
        sbom2 = helper.load_sub_program()
        sbom_merged = helper.load_governing_program_merged_sub_program()
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_vulnerabilities_in_the_second(self) -> None:
        sbom1 = helper.load_governing_program()
        sbom2 = helper.load_sub_program()
        vulnerabilities = helper.load_sections_for_test_sbom()[
            "merge_vulnerabilities_tests"
        ]["test_merge_vulnerabilities"]
        original_vulnerabilities = vulnerabilities["original_vulnerabilities"]

        sbom2["vulnerabilities"] = original_vulnerabilities
        sbom_merged = helper.load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = original_vulnerabilities
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_vulnerabilities_in_the_first(self) -> None:
        sbom1 = helper.load_governing_program()
        vulnerabilities = helper.load_sections_for_test_sbom()[
            "merge_vulnerabilities_tests"
        ]["test_merge_vulnerabilities"]
        original_vulnerabilities = vulnerabilities["original_vulnerabilities"]

        sbom1["vulnerabilities"] = original_vulnerabilities
        sbom2 = helper.load_sub_program()
        sbom_merged = helper.load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = original_vulnerabilities
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_merge_sboms_same_sbom(self) -> None:
        vulnerabilities = helper.load_sections_for_test_sbom()[
            "merge_vulnerabilities_tests"
        ]["test_merge_vulnerabilities"]
        original_vulnerabilities = vulnerabilities["original_vulnerabilities"]
        new_vulnerabilities = vulnerabilities["new_vulnerabilities"]
        merged_vulnerabilities = vulnerabilities["merged_vulnerabilities"]

        sbom1 = helper.load_governing_program()
        sbom1["vulnerabilities"] = new_vulnerabilities
        sbom2 = helper.load_sub_program()
        sbom2["vulnerabilities"] = original_vulnerabilities
        sbom_merged = helper.load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = merged_vulnerabilities
        sbom3 = helper.load_governing_program()
        sbom3["vulnerabilities"] = original_vulnerabilities
        sbom4 = helper.load_sub_program()
        sbom4["components"][2]["version"] = "2.24.0"
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom1]), sbom1))
        self.assertTrue(helper.compare_sboms(merge.merge([sbom2, sbom2]), sbom2))
        self.assertTrue(helper.compare_sboms(merge.merge([sbom3, sbom3]), sbom3))
        self.assertTrue(helper.compare_sboms(merge.merge([sbom4, sbom4]), sbom4))
        self.assertTrue(
            helper.compare_sboms(merge.merge([sbom_merged, sbom_merged]), sbom_merged)
        )

    def test_no_composition_in_sboms(self) -> None:
        sbom1 = helper.load_governing_program()
        sbom2 = helper.load_sub_program()
        sbom1.pop("compositions")
        sbom2.pop("compositions")
        sbom_merged = helper.load_governing_program_merged_sub_program()
        merged_sbom = merge.merge([sbom1, sbom2])
        sbom_merged.pop("compositions")
        self.assertTrue(helper.compare_sboms(merged_sbom, sbom_merged))


class TestMergeSeveralSboms(unittest.TestCase):
    def test_merge_3_sboms(self) -> None:
        governing_program = helper.load_governing_program()
        sub_program = helper.load_sub_program()
        sub_sub_program = helper.load_additional_sbom_dict()["sub_sub_program"]
        goal_sbom = helper.load_additional_sbom_dict()["merge_government_sub_sub_sub"]
        merged_bom = merge.merge([governing_program, sub_program, sub_sub_program])

        self.assertTrue(helper.compare_sboms(merged_bom, goal_sbom))

    def test_merge_4_sboms(self) -> None:
        governing_program = helper.load_governing_program()
        sub_program = helper.load_sub_program()
        sub_sub_program = helper.load_additional_sbom_dict()["sub_sub_program"]
        goal_sbom = helper.load_additional_sbom_dict()[
            "merge_government_sub_sub_sub_and_sub_sub_2"
        ]
        sub_sub_program_2 = helper.load_additional_sbom_dict()["sub_sub_program_2"]
        merged_bom = merge.merge(
            [governing_program, sub_program, sub_sub_program, sub_sub_program_2]
        )

        self.assertTrue(helper.compare_sboms(merged_bom, goal_sbom))


class TestMergeComponents(unittest.TestCase):
    def test_merge_components(self) -> None:
        sections = helper.load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]
        original_sbom = sections["merge.input_1"]
        new_sbom = sections["merge.input_2"]
        merge.make_bom_refs_unique([original_sbom, new_sbom])
        merge.unify_bom_refs([original_sbom, new_sbom])

        goal_sbom = sections["test_merge_replace_ref_goal"]

        merged_components = merge.merge_components(original_sbom, new_sbom)
        self.assertEqual(merged_components, goal_sbom["components"])

    def test_filter_component(self) -> None:
        # considered test cases:
        # - top level component present, sub component not
        # - top level component not present, sublevel component present
        #   sub_sub component not present
        # - top level not present, sub_sub present
        components = helper.load_sections_for_test_sbom()["hierarchical_components"]
        present_components = [
            ComponentIdentity.create(components["component_1"], allow_unsafe=True),
            ComponentIdentity.create(components["component_3"], allow_unsafe=True),
            ComponentIdentity.create(
                components["component_2_sub_1"], allow_unsafe=True
            ),
            ComponentIdentity.create(
                components["component_4_sub_1_sub_2"], allow_unsafe=True
            ),
        ]

        new_components = helper.load_sections_for_test_sbom()[
            "test_filter_component_new_components"
        ]
        components["component_1"]["components"] = [components["component_1_sub_1"]]

        add_to_existing: dict[ComponentIdentity, dict] = {}

        merge.filter_component(
            present_components,
            new_components,
            add_to_existing,
        )

        add_to_existing_expected = {
            ComponentIdentity.create(components["component_1"], allow_unsafe=True): [
                components["component_1_sub_1"]
            ],
            ComponentIdentity.create(
                components["component_2_sub_1"], allow_unsafe=True
            ): [components["component_2_sub_1_sub_1"]],
        }

        add_to_existing_identical = True
        for key in add_to_existing_expected.keys():
            if add_to_existing_expected[key] != add_to_existing[key]:
                add_to_existing_identical = False

        self.assertTrue(
            len(add_to_existing.keys()) == len(add_to_existing_expected.keys())
        )
        self.assertTrue(add_to_existing_identical)

    def test_individual_merge_cases(self) -> None:
        test_cases = helper.load_sections_for_test_sbom()["singled_out_test_cases"]

        for key in test_cases.keys():
            original = test_cases[key]["original"]
            new = test_cases[key]["new"]
            merged_hr = test_cases[key]["merged_hr"]
            merged_nm = test_cases[key]["merged_normal"]
            merged_hierarchical = merge.merge_components(
                copy.deepcopy({"components": original}),
                copy.deepcopy({"components": new}),
                hierarchical=True,
            )
            merged_normal = merge.merge_components(
                copy.deepcopy({"components": original}),
                copy.deepcopy({"components": new}),
            )

            self.assertCountEqual(merged_hierarchical, merged_hr)
            self.assertCountEqual(merged_normal, merged_nm)

    def test_merge_hierarchical(self) -> None:
        new_components = helper.load_sections_for_test_sbom()[
            "test_merge_hierarchical_new_components"
        ]
        present_components = helper.load_sections_for_test_sbom()[
            "test_merge_hierarchical_present_components"
        ]

        merged_components = merge.merge_components(
            {"components": present_components},
            {"components": new_components},
            hierarchical=True,
        )

        expected_components = helper.load_sections_for_test_sbom()[
            "hierarchical_expected"
        ]

        self.assertEqual(merged_components, expected_components)


class TestMergeCompositions(unittest.TestCase):
    def test_only_first_sbom_contains_compositions(self) -> None:
        governing_program = helper.load_governing_program()
        sub_program = helper.load_sub_program()
        sub_program.pop("compositions")
        merged_sbom = merge.merge([governing_program, sub_program])
        goal_sbom = helper.load_governing_program_merged_sub_program()
        goal_sbom["compositions"] = governing_program["compositions"]
        self.assertTrue(helper.compare_sboms(merged_sbom, goal_sbom))

    def test_only_second_sbom_contains_compositions(self) -> None:
        compositions_2 = [
            {"aggregate": "incomplete", "assemblies": ["first_ref", "second_ref"]}
        ]
        compositions_1: list[dict] = []
        merge.merge_compositions(compositions_1, compositions_2)
        self.assertEqual(compositions_1, compositions_2)

    def test_merge_compositions_one_aggregate(self) -> None:
        compositions_1 = [
            {"aggregate": "incomplete", "assemblies": ["first_ref", "second_ref"]}
        ]
        compositions_2 = [
            {
                "aggregate": "incomplete",
                "assemblies": ["third_ref", "second_ref", "fourth_ref"],
            }
        ]
        merged_compositions = [
            {
                "aggregate": "incomplete",
                "assemblies": ["first_ref", "second_ref", "third_ref", "fourth_ref"],
            }
        ]
        merge.merge_compositions(compositions_1, compositions_2)
        self.assertEqual(compositions_1, merged_compositions)

    def test_merge_compositions_multiple_aggregates(self) -> None:
        compositions_1 = [
            {"aggregate": "incomplete", "assemblies": ["first_ref", "second_ref"]},
            {"aggregate": "complete", "assemblies": ["complete_one", "complete_two"]},
        ]
        compositions_2 = [
            {
                "aggregate": "incomplete",
                "assemblies": ["third_ref", "second_ref", "fourth_ref"],
            },
            {"aggregate": "complete", "assemblies": ["complete_three", "complete_two"]},
            {"aggregate": "unknown", "assemblies": ["unknown_one", "unknown_two"]},
        ]
        merged_compositions = [
            {
                "aggregate": "incomplete",
                "assemblies": ["first_ref", "second_ref", "third_ref", "fourth_ref"],
            },
            {
                "aggregate": "complete",
                "assemblies": ["complete_one", "complete_two", "complete_three"],
            },
            {"aggregate": "unknown", "assemblies": ["unknown_one", "unknown_two"]},
        ]
        merge.merge_compositions(compositions_1, compositions_2)
        self.assertEqual(compositions_1, merged_compositions)


class TestMergeVulnerabilities(unittest.TestCase):
    basic_vulnerability = {
        "id": "CVE-2021-44228",
        "source": {
            "name": "NVD",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        },
        "ratings": [
            {
                "source": {
                    "name": "NVD",
                    "url": "https:",
                },
                "score": 10.0,
                "severity": "critical",
                "method": "CVSSv31",
                "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            }
        ],
        "analysis": {
            "state": "exploitable",
            "response": ["will_not_fix", "update"],
            "detail": "Versions of Products ABC and JKL are affected by the vulnerability.",
        },
        "affects": [
            {
                "ref": "Product 1",
                "versions": [
                    {"version": "2.4", "status": "affected"},
                    {"version": "2.6", "status": "affected"},
                    {"range": "vers:generic/>=2.9|<=4.1", "status": "affected"},
                ],
            },
            {
                "ref": "Product 2",
                "versions": [
                    {"range": "vers:generic/>=4.5|<=5.0", "status": "affected"}
                ],
            },
        ],
    }

    def calculate_merged_vulnerabilities(
        self, vulnerability_1: dict, vulnerability_2: dict
    ) -> list[dict]:
        vulnerability_identities = {
            json.dumps(
                vulnerability_1, sort_keys=True
            ): VulnerabilityIdentity.from_vulnerability(vulnerability_1),
            json.dumps(
                vulnerability_2, sort_keys=True
            ): VulnerabilityIdentity.from_vulnerability(vulnerability_2),
        }
        return merge.merge_vulnerabilities(
            [vulnerability_1], [vulnerability_2], vulnerability_identities
        )

    # Same Product affected
    def test_2_different_vulnerabilities(self) -> None:
        # test 2 different vulnerabilities
        vulnerability_1 = copy.deepcopy(self.basic_vulnerability)
        vulnerability_2 = copy.deepcopy(self.basic_vulnerability)
        vulnerability_2["id"] = "something else"
        merged_vulnerabilities = self.calculate_merged_vulnerabilities(
            vulnerability_1, vulnerability_2
        )
        self.assertEqual(merged_vulnerabilities, [vulnerability_1, vulnerability_2])

    def test_same_vulnerabilities_different_analysis_and_affects(self) -> None:
        # test same vulnerabilities different analysis and affects
        vulnerability_1 = copy.deepcopy(self.basic_vulnerability)
        vulnerability_3 = copy.deepcopy(self.basic_vulnerability)
        vulnerability_3["analysis"]["state"] = "false_positive"
        vulnerability_3["affects"] = [
            {
                "ref": "Product 1",
                "versions": [{"version": "10", "status": "unaffected"}],
            }
        ]

        merged_vulnerabilities = self.calculate_merged_vulnerabilities(
            vulnerability_1, vulnerability_3
        )

        self.assertEqual(merged_vulnerabilities, [vulnerability_1, vulnerability_3])

    def test_same_vulnerabilities_different_analysis_and_same_affects(
        self,
    ) -> None:
        # test same vulnerabilities different analysis and same affects
        vulnerability_1 = copy.deepcopy(self.basic_vulnerability)
        vulnerability_4 = copy.deepcopy(self.basic_vulnerability)
        vulnerability_4["analysis"]["state"] = "false_positive"
        vulnerability_4["affects"] = [
            {
                "ref": "Product 1",
                "versions": [
                    {"version": "2.4", "status": "unaffected"},
                    {"version": "2.6", "status": "unaffected"},
                ],
            }
        ]

        merged_vulnerabilities = self.calculate_merged_vulnerabilities(
            vulnerability_1, vulnerability_4
        )
        self.assertEqual(merged_vulnerabilities, [vulnerability_1])

    def test_same_vulnerabilities_different_analysis_and_overlapping_affects(
        self,
    ) -> None:
        # test same vulnerabilities different analysis and overlapping affects
        vulnerability_1 = copy.deepcopy(self.basic_vulnerability)
        vulnerability_5 = copy.deepcopy(self.basic_vulnerability)
        vulnerability_5["analysis"]["state"] = "false_positive"
        vulnerability_5["affects"] = [
            {
                "ref": "Product 1",
                "versions": [
                    {"version": "3.0", "status": "unaffected"},
                    {"range": "vers:generic/<2.6", "status": "unaffected"},
                ],
            }
        ]
        vulnerability_5_merged = copy.deepcopy(vulnerability_5)

        merged_vulnerabilities = self.calculate_merged_vulnerabilities(
            vulnerability_1, vulnerability_5
        )
        vulnerability_5_merged["affects"] = [
            {
                "ref": "Product 1",
                "versions": [
                    {"range": "vers:generic/<2.6|!=2.4", "status": "unaffected"}
                ],
            }
        ]
        # drops one and removes the other from the range
        self.assertEqual(
            merged_vulnerabilities, [vulnerability_1, vulnerability_5_merged]
        )

    def test_same_vulnerabilities_same_analysis_and_other_affects(self) -> None:
        # Merge of the same vulnerability with other affects
        vulnerability_1 = copy.deepcopy(self.basic_vulnerability)
        vulnerability_6 = copy.deepcopy(self.basic_vulnerability)
        vulnerability_6["affects"] = [
            {
                "ref": "Product 1",
                "versions": [
                    {"version": "10.0", "status": "affected"},
                    {"range": "vers:generic/>20", "status": "affected"},
                ],
            }
        ]
        merged_vulnerabilities = self.calculate_merged_vulnerabilities(
            vulnerability_1, vulnerability_6
        )
        vulnerability_1_merged = copy.deepcopy(vulnerability_1)
        vulnerability_1_merged["affects"][0]["versions"].append(
            vulnerability_6["affects"][0]["versions"][0]
        )
        vulnerability_1_merged["affects"][0]["versions"].append(
            vulnerability_6["affects"][0]["versions"][1]
        )
        self.assertEqual(merged_vulnerabilities, [vulnerability_1_merged])

    def test_same_vulnerability(self) -> None:
        # Merge of the same vulnerability with other affects
        vulnerability_1 = copy.deepcopy(self.basic_vulnerability)
        vulnerability_2 = copy.deepcopy(self.basic_vulnerability)

        merged_vulnerabilities = self.calculate_merged_vulnerabilities(
            vulnerability_1, vulnerability_2
        )
        self.assertEqual(merged_vulnerabilities, [vulnerability_1])

    def test_merge_responses_same_vulnerability(self) -> None:
        # Merge of the same vulnerability with other affects
        vulnerability_1 = copy.deepcopy(self.basic_vulnerability)
        vulnerability_2 = copy.deepcopy(self.basic_vulnerability)
        vulnerability_merged = copy.deepcopy(vulnerability_1)

        vulnerability_2["analysis"]["response"].append("another")
        merged_vulnerabilities = self.calculate_merged_vulnerabilities(
            vulnerability_1, vulnerability_2
        )
        vulnerability_merged["analysis"]["response"].append("another")

        self.assertEqual(merged_vulnerabilities, [vulnerability_merged])

    def test_new_product(
        self,
    ) -> None:
        # test same vulnerabilities different analysis and overlapping affects
        vulnerability_1 = copy.deepcopy(self.basic_vulnerability)
        vulnerability_2 = copy.deepcopy(self.basic_vulnerability)
        new_affects = {
            "ref": "Product 3",
            "versions": [
                {"version": "3.0", "status": "unaffected"},
                {"range": "vers:generic/<2.6", "status": "unaffected"},
            ],
        }
        vulnerability_2["affects"] = [new_affects]

        vulnerability_merged = copy.deepcopy(vulnerability_1)

        merged_vulnerabilities = self.calculate_merged_vulnerabilities(
            vulnerability_1, vulnerability_2
        )
        vulnerability_merged["affects"].append(new_affects)
        # drops one and removes the other from the range
        self.assertEqual(merged_vulnerabilities, [vulnerability_merged])

    def test_merge_vulnerabilities(self) -> None:
        vulnerabilities = helper.load_sections_for_test_sbom()[
            "merge_vulnerabilities_tests"
        ]["test_merge_vulnerabilities"]
        original_vulnerabilities = vulnerabilities["original_vulnerabilities"]
        new_vulnerabilities = vulnerabilities["new_vulnerabilities"]
        merged_vulnerabilities = vulnerabilities["merged_vulnerabilities"]

        identities = merge.get_identities_for_vulnerabilities(
            original_vulnerabilities + new_vulnerabilities
        )
        actual_merged = merge.merge_vulnerabilities(
            original_vulnerabilities, new_vulnerabilities, identities
        )
        self.assertEqual(merged_vulnerabilities, actual_merged)

    def test_merge_only_one_vulnerabilities(self) -> None:
        vulnerabilities = helper.load_sections_for_test_sbom()[
            "merge_vulnerabilities_tests"
        ]["test_merge_vulnerabilities"]
        original_vulnerabilities = vulnerabilities["original_vulnerabilities"]
        new_vulnerabilities = vulnerabilities["new_vulnerabilities"]

        identities_1 = merge.get_identities_for_vulnerabilities(
            original_vulnerabilities
        )

        identities_2 = merge.get_identities_for_vulnerabilities(new_vulnerabilities)

        actual_merged = merge.merge_vulnerabilities(
            original_vulnerabilities, [], identities_1
        )

        actual_merged_2 = merge.merge_vulnerabilities(
            new_vulnerabilities, [], identities_2
        )

        actual_merged_3 = merge.merge_vulnerabilities(
            [], original_vulnerabilities, identities_1
        )

        actual_merged_4 = merge.merge_vulnerabilities(
            [], new_vulnerabilities, identities_2
        )

        self.assertEqual(original_vulnerabilities, actual_merged)
        self.assertEqual(new_vulnerabilities, actual_merged_2)
        self.assertEqual(original_vulnerabilities, actual_merged_3)
        self.assertEqual(new_vulnerabilities, actual_merged_4)

    def test_merge_replace_ref(self) -> None:
        sections = helper.load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]
        original_sbom = sections["merge.input_1"]
        new_sbom = sections["merge.input_2"]
        goal_sbom = sections["test_merge_replace_ref_goal"]
        merged_sbom = merge.merge([original_sbom, new_sbom])

        self.assertEqual(merged_sbom, goal_sbom)

    def test_merge_with_only_vex(self) -> None:
        vulnerabilities = helper.load_sections_for_test_sbom()[
            "merge_vulnerabilities_tests"
        ]["test_merge_vulnerabilities"]
        original_vulnerabilities = vulnerabilities["original_vulnerabilities"]
        new_vulnerabilities = vulnerabilities["new_vulnerabilities"]
        merged_vulnerabilities = vulnerabilities["merged_vulnerabilities"]

        actual_merged = merge.merge(
            [
                {"vulnerabilities": original_vulnerabilities},
                {"vulnerabilities": new_vulnerabilities},
            ]
        )

        self.assertEqual(actual_merged["vulnerabilities"], merged_vulnerabilities)


if __name__ == "__main__":
    unittest.main()
