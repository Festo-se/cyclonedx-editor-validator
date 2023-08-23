import json
import unittest

from cdxev import merge_vex
from tests.auxiliary.sbomFunctionsTests import compare_sboms

path_to_folder_with_test_sboms = "tests/auxiliary/test_merge_vex_sboms/"


class TestMergeVex(unittest.TestCase):
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
        self.assertTrue(compare_sboms(merge_vex.merge_vex(sbom, vex), goal))

    def test_merge_vex_sboms_same_vul(self) -> None:
        with open(
            path_to_folder_with_test_sboms + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex = json.load(my_file)
        with open(
            path_to_folder_with_test_sboms + "goal.json", "r", encoding="utf-8-sig"
        ) as my_file:
            goal = json.load(my_file)
        self.assertTrue(compare_sboms(merge_vex.merge_vex(goal, vex), goal))

    def test_compare_sboms(self) -> None:
        with open(
            path_to_folder_with_test_sboms + "vex.json", "r", encoding="utf-8-sig"
        ) as my_file:
            vex = json.load(my_file)
        with open(
            path_to_folder_with_test_sboms + "goal.json", "r", encoding="utf-8-sig"
        ) as my_file:
            goal = json.load(my_file)
        self.assertTrue(compare_sboms(merge_vex.merge_vex(goal, vex), goal))

    def test_merge_affected(self) -> None:
        with open(
            path_to_folder_with_test_sboms + "auxiliar_vulnerability.json",
            "r",
            encoding="utf-8-sig",
        ) as my_file:
            auxiliar_file = json.load(my_file)
        first_vex = auxiliar_file["vex_1"]
        second_vex = auxiliar_file["vex_2"]
        vex_merged = auxiliar_file["vex_3"]
        self.assertTrue(
            compare_sboms(merge_vex.merge_vex(first_vex, second_vex), vex_merged)
        )

    def test_merge_different_vul(self) -> None:
        with open(
            path_to_folder_with_test_sboms + "auxiliar_vulnerability.json",
            "r",
            encoding="utf-8-sig",
        ) as my_file:
            auxiliar_file = json.load(my_file)
        first_vex = auxiliar_file["vex_1"]
        second_vex = auxiliar_file["vex_two_vul"]
        vex_merged = auxiliar_file["vex_two_vul_merged_vex_1"]
        self.assertTrue(
            compare_sboms(merge_vex.merge_vex(second_vex, first_vex), vex_merged)
        )

    def test_merge_not_unique_vul(self) -> None:
        with open(
            path_to_folder_with_test_sboms + "auxiliar_vulnerability.json",
            "r",
            encoding="utf-8-sig",
        ) as my_file:
            auxiliar_file = json.load(my_file)
        first_vex_to_merge = {}
        first_vex = auxiliar_file["vex_1"]
        second_vex = auxiliar_file["vex_two_vul"]
        vex_merged = auxiliar_file["vex_two_vul_merged_vex_1"]
        first_vex_to_merge["vulnerabilities"] = [
            first_vex["vulnerabilities"][0],
            vex_merged["vulnerabilities"][1],
        ]
        self.assertTrue(
            compare_sboms(
                merge_vex.merge_vex(second_vex, first_vex_to_merge), vex_merged
            )
        )

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
        self.assertTrue(compare_sboms(merge_vex.merge_vex(sbom, vex), goal))


if __name__ == "__main__":
    unittest.main()
