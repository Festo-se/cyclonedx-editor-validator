# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from cdxev import merge
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

    def test_merge_same_vulnerabilities(self) -> None:
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
            original_vulnerabilities, original_vulnerabilities, identities_1
        )

        actual_merged_2 = merge.merge_vulnerabilities(
            new_vulnerabilities, new_vulnerabilities, identities_2
        )

        self.assertEqual(original_vulnerabilities, actual_merged)
        self.assertEqual(new_vulnerabilities, actual_merged_2)

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


# TODO write tests that verify the replacement of refs!!

if __name__ == "__main__":
    unittest.main()
