# CycloneDX Editor Validator
# Copyright (C) 2023  Festo SE & Co. KG

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import json
import unittest

from cdxev import merge_vex
from tests.auxiliary.sbomFunctionsTests import compare_sboms

path_to_folder_with_test_sboms = "tests/auxiliary/test_merge_vex_sboms/"


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
        self.assertTrue(merge_vex.check_if_refs_are_in_sbom(vex, sbom), True)

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
            merge_vex.get_refs_from_sbom(sbom),
            [
                "some program",
                "11231231",
                "first_component",
                "ref_first_component@1.3.3",
            ],
        )
        self.assertEqual(
            merge_vex.get_refs_from_vex(vex),
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
