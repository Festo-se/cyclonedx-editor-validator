import json
import unittest

from cdxev import mergeVex
from tests.auxiliary.sbomFunctionsTests import compare_sboms

path_to_folder_with_test_sboms = "tests/auxiliary/test_mergeVex_sboms/"


class TestMergeVexSboms(unittest.TestCase):
    def test_check_if_refs_are_in_sbom(self) -> None:
        with open(
            path_to_folder_with_test_sboms + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex = json.load(my_file)
        with open(
            path_to_folder_with_test_sboms + "bom.json", "r", encoding="utf-8-sig"
        ) as my_file:
            sbom = json.load(my_file)
        self.assertTrue(mergeVex.check_if_refs_are_in_sbom(vex, sbom), True)

    def test_get_refs_from(self) -> None:
        with open(
            path_to_folder_with_test_sboms + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex = json.load(my_file)
        with open(
            path_to_folder_with_test_sboms + "bom.json", "r", encoding="utf-8-sig"
        ) as my_file:
            sbom = json.load(my_file)
        self.assertEqual(
            mergeVex.get_refs_from_sbom(sbom),
            [
                "some program",
                "11231231",
                "first_component",
                "ref_first_component@1.3.3",
            ],
        )
        self.assertEqual(
            mergeVex.get_refs_from_vex(vex),
            ["11231231", "ref_first_component@1.3.3"],
        )

    def test_merge_vex_sboms_no_vul(self) -> None:
        with open(
            path_to_folder_with_test_sboms + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex = json.load(my_file)
        with open(
            path_to_folder_with_test_sboms + "bom.json", "r", encoding="utf-8-sig"
        ) as my_file:
            sbom = json.load(my_file)
        with open(
            path_to_folder_with_test_sboms + "goal.json", "r", encoding="utf-8-sig"
        ) as my_file:
            goal = json.load(my_file)
        self.assertTrue(compare_sboms(mergeVex.merge_vex(sbom, vex), goal))

    def test_merge_vex_sboms_same_vul(self) -> None:
        with open(
            path_to_folder_with_test_sboms + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex = json.load(my_file)
        with open(
            path_to_folder_with_test_sboms + "goal.json", "r", encoding="utf-8-sig"
        ) as my_file:
            goal = json.load(my_file)
        self.assertTrue(compare_sboms(mergeVex.merge_vex(goal, vex), goal))

    def test_compare_sboms(self) -> None:
        with open(
            path_to_folder_with_test_sboms + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex = json.load(my_file)
        with open(
            path_to_folder_with_test_sboms + "goal.json", "r", encoding="utf-8-sig"
        ) as my_file:
            goal = json.load(my_file)
        self.assertTrue(compare_sboms(mergeVex.merge_vex(goal, vex), goal))

    def test_merge_vex_sboms_merge(self) -> None:
        with open(
            path_to_folder_with_test_sboms + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex = json.load(my_file)
        with open(
            path_to_folder_with_test_sboms + "goal_one_deleted.json",
            "r",
            encoding="utf-8-sig",
        ) as my_file:
            sbom = json.load(my_file)
        with open(
            path_to_folder_with_test_sboms + "goal.json", "r", encoding="utf-8-sig"
        ) as my_file:
            goal = json.load(my_file)
        self.assertTrue(compare_sboms(mergeVex.merge_vex(sbom, vex), goal))


if __name__ == "__main__":
    unittest.main()
