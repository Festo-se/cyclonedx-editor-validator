# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import unittest

from cdxev import merge
from cdxev.auxiliary import sbomFunctions as sbF
from cdxev.auxiliary.identity import ComponentIdentity
from tests.auxiliary import helper as helper

path_to_folder_with_test_sboms = "tests/auxiliary/test_merge_sboms/"

with open(
    path_to_folder_with_test_sboms + "ratings_lists_for_tests.json",
    "r",
    encoding="utf-8-sig",
) as my_file:
    ratings_dict = json.load(my_file)

with open(
    path_to_folder_with_test_sboms + "sections_for_test_sbom.json",
    "r",
    encoding="utf-8-sig",
) as my_file:
    dictionary_with_stuff = json.load(my_file)


def load_governing_program() -> dict:
    with open(
        path_to_folder_with_test_sboms + "governing_program.json",
        "r",
        encoding="utf-8-sig",
    ) as my_file:
        sbom = json.load(my_file)
    return sbom


def load_sections_for_test_sbom() -> dict:
    with open(
        path_to_folder_with_test_sboms + "sections_for_test_sbom.json",
        "r",
        encoding="utf-8-sig",
    ) as my_file:
        sbom = json.load(my_file)
    return sbom


def load_governing_program_merged_sub_program() -> dict:
    with open(
        path_to_folder_with_test_sboms + "merged_sbom.json",
        "r",
        encoding="utf-8-sig",
    ) as my_file:
        sbom = json.load(my_file)
    return sbom


def load_sub_program() -> dict:
    with open(
        path_to_folder_with_test_sboms + "sub_program.json",
        "r",
        encoding="utf-8-sig",
    ) as my_file:
        sbom = json.load(my_file)
    return sbom


def load_additional_sbom_dict() -> dict:
    with open(
        path_to_folder_with_test_sboms + "additional_sboms.json",
        "r",
        encoding="utf-8-sig",
    ) as my_file:
        sbom = json.load(my_file)
    return sbom


class TestCompareVulnerabilities(unittest.TestCase):
    def test_empty_dic(self) -> None:
        self.assertFalse(sbF.compare_vulnerabilities({}, {}))

    def test_equal_id(self) -> None:
        self.assertTrue(
            sbF.compare_vulnerabilities(
                {"id": "id1", "stuff": ["item3", "item4"]},
                {"id": "id1", "stuff": ["item1", "item2"]},
            )
        )

    def test_different_id(self) -> None:
        self.assertFalse(
            sbF.compare_vulnerabilities(
                {"id": "id2", "stuff": ["item3", "item4"]},
                {"id": "id1", "stuff": ["item1", "item2"]},
            )
        )


class TestVulnerabilitiesIsIn(unittest.TestCase):
    def test_not_in_list(self) -> None:
        self.assertFalse(
            sbF.vulnerability_is_in(
                {"id": "id5", "stuff": ["item3", "item4"]},
                [
                    {"id": "id1", "stuff": ["item3", "item4"]},
                    {"id": "id2", "stuff": ["item1", "item2"]},
                    {"id": "id3", "stuff": ["item3", "item4"]},
                    {"id": "id4", "stuff": ["item1", "item2"]},
                ],
            )
        )

    def test_in_list(self) -> None:
        self.assertTrue(
            sbF.vulnerability_is_in(
                {"id": "id4", "stuff": ["item3", "item4"]},
                [
                    {"id": "id1", "stuff": ["item3", "item4"]},
                    {"id": "id2", "stuff": ["item1", "item2"]},
                    {"id": "id3", "stuff": ["item3", "item4"]},
                    {"id": "id4", "stuff": ["item1", "item2"]},
                ],
            )
        )

    def test_copy_ratings(self) -> None:
        self.assertTrue(
            helper.compare_list_content(
                sbF.copy_ratings(ratings_dict["ratings1"]), ratings_dict["ratings1"]
            )
        )
        self.assertTrue(
            helper.compare_list_content(
                sbF.copy_ratings(ratings_dict["ratings2"]), ratings_dict["ratings2"]
            )
        )
        self.assertTrue(
            helper.compare_list_content(
                sbF.copy_ratings(ratings_dict["ratings3"]), ratings_dict["ratings3"]
            )
        )

    def test_merge_sboms_ratings(self) -> None:
        self.assertEqual(
            merge.merge_ratings(ratings_dict["ratings1"], ratings_dict["ratings2"]),
            ratings_dict["merged_ratings_1_and_ratings_2"],
        )
        self.assertTrue(
            helper.compare_list_content(
                merge.merge_ratings(
                    ratings_dict["ratings3"], ratings_dict["ratings4"], 0
                ),
                ratings_dict["merged_ratings_3_and_ratings_4_flag_0"],
            )
        )
        self.assertTrue(
            helper.compare_list_content(
                merge.merge_ratings(
                    ratings_dict["ratings3"], ratings_dict["ratings4"], 1
                ),
                ratings_dict["merged_ratings_3_and_ratings_4_flag_1"],
            )
        )
        self.assertTrue(
            helper.compare_list_content(
                merge.merge_ratings(
                    ratings_dict["ratings3"], ratings_dict["ratings4"], 2
                ),
                ratings_dict["merged_ratings_3_and_ratings4_flag_2"],
            )
        )


class TestCompareSboms(unittest.TestCase):
    def test_equal(self) -> None:
        with open(
            path_to_folder_with_test_sboms + "governing_program.json",
            "r",
            encoding="utf-8-sig",
        ) as my_file:
            sbom1 = json.load(my_file)
        self.assertTrue(helper.compare_sboms(sbom1, sbom1))

    def test_unequal(self) -> None:
        sbom1 = load_governing_program()
        sbom2 = load_sub_program()
        self.assertFalse(helper.compare_sboms(sbom1, sbom2))


class TestTimeFunctions(unittest.TestCase):
    def test_compare_time_flag_from_vulnerabilities(self) -> None:
        self.assertEqual(
            sbF.compare_time_flag_from_vulnerabilities(
                {"published": "2022-10-12T00:14Z"},
                {"published": "2022-10-12T00:15Z"},
            ),
            2,
        )
        self.assertEqual(
            sbF.compare_time_flag_from_vulnerabilities(
                {"published": "2022-10-12T00:15Z"},
                {"published": "2022-10-12T00:14Z"},
            ),
            1,
        )
        self.assertEqual(
            sbF.compare_time_flag_from_vulnerabilities(
                {"published": "2022-10-12T00:15Z"},
                {"published": "2022-10-12T00:15Z"},
            ),
            0,
        )
        self.assertEqual(
            sbF.compare_time_flag_from_vulnerabilities(
                {"published": "2022-10-12T00:14Z", "updated": "2022-11-12T00:15Z"},
                {"published": "2022-10-12T00:15Z", "updated": "2022-11-12T00:14Z"},
            ),
            1,
        )
        self.assertEqual(
            sbF.compare_time_flag_from_vulnerabilities(
                {"published": "2022-10-12T00:15Z", "updated": "2022-11-12T00:14Z"},
                {"published": "2022-10-12T00:14Z", "updated": "2022-11-12T00:15Z"},
            ),
            2,
        )
        self.assertEqual(
            sbF.compare_time_flag_from_vulnerabilities(
                {"published": "2022-10-12T00:15Z", "updated": "2022-11-12T00:14Z"},
                {"published": "2022-10-12T00:14Z", "updated": "2022-11-12T00:14Z"},
            ),
            0,
        )
        self.assertEqual(
            sbF.compare_time_flag_from_vulnerabilities(
                {"published": "2022-10-12T00:14Z"},
                {"published": "2022-10-12T00:15Z", "updated": "2022-11-12T00:14Z"},
            ),
            2,
        )
        self.assertEqual(
            sbF.compare_time_flag_from_vulnerabilities(
                {"published": "2022-10-12T00:15Z", "updated": "2022-11-12T00:14Z"},
                {
                    "published": "2022-10-12T00:14Z",
                },
            ),
            1,
        )
        self.assertEqual(
            sbF.compare_time_flag_from_vulnerabilities(
                {"published": "2022-10-12T00:15Z", "updated": "2022-10-12T00:14Z"},
                {
                    "published": "2022-10-12T00:14Z",
                },
            ),
            0,
        )


class TestMergeSboms(unittest.TestCase):
    def test_no_vulnerabilities(self) -> None:
        sbom1 = load_governing_program()
        sbom2 = load_sub_program()
        sbom_merged = load_governing_program_merged_sub_program()
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_vulnerabilities_in_the_second(self) -> None:
        sbom1 = load_governing_program()
        sbom2 = load_sub_program()
        dictionary_with_stuff = load_sections_for_test_sbom()
        sbom2["vulnerabilities"] = dictionary_with_stuff[
            "sub_program_with_vulnerabilities"
        ]
        sbom_merged = load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = dictionary_with_stuff[
            "sub_program_with_vulnerabilities"
        ]
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_vulnerabilities_in_the_first(self) -> None:
        sbom1 = load_governing_program()
        dictionary_with_stuff = load_sections_for_test_sbom()
        sbom1["vulnerabilities"] = dictionary_with_stuff[
            "governing_program_with_vulnerabilities"
        ]
        sbom2 = load_sub_program()
        dictionary_with_stuff = load_sections_for_test_sbom()
        sbom_merged = load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = dictionary_with_stuff[
            "merged_governing_program_with_vul_without"
        ]
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_vulnerabilities_same_component(self) -> None:
        dictionary_with_stuff = load_sections_for_test_sbom()
        sbom1 = load_governing_program()
        sbom1["vulnerabilities"] = dictionary_with_stuff[
            "governing_program_with_vulnerabilities"
        ]
        sbom2 = load_sub_program()
        sbom2["components"][2]["version"] = "2.24.0"
        sbom2["vulnerabilities"] = dictionary_with_stuff[
            "sub_program_with_vulnerabilities_equal_mbed_tls"
        ]
        sbom_merged = load_governing_program_merged_sub_program()
        sbom_merged["dependencies"] = dictionary_with_stuff["dependencies_tls_equal"]
        sbom_merged["compositions"] = dictionary_with_stuff["compositions_tls_equal"]
        sbom_merged["components"] = [
            component
            for component in sbom_merged["components"]
            if component["bom-ref"] != "sp_fifteenth_component"
        ]
        sbom_merged["vulnerabilities"] = dictionary_with_stuff[
            "vulnerabilities_tls_equal"
        ]
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_vulnerabilities_different_component(self) -> None:
        sbom1 = load_governing_program()
        dictionary_with_stuff = load_sections_for_test_sbom()
        sbom1["vulnerabilities"] = dictionary_with_stuff[
            "governing_program_with_vulnerabilities"
        ]
        sbom2 = load_sub_program()
        dictionary_with_stuff = load_sections_for_test_sbom()
        sbom2["vulnerabilities"] = dictionary_with_stuff[
            "sub_program_with_vulnerabilities"
        ]
        sbom_merged = load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = dictionary_with_stuff[
            "merged_governing_program_with_vul_tls_unequal"
        ]
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

        # in the compare function, the order of the affected in the list is also compared

    def test_vulnerabilities_merge_two_affected(self) -> None:
        dictionary_with_stuff = load_sections_for_test_sbom()
        sbom1 = load_governing_program()
        sbom1["vulnerabilities"] = dictionary_with_stuff[
            "governing_program_with_vulnerabilities"
        ]
        sbom2 = load_sub_program()
        sbom2["vulnerabilities"] = dictionary_with_stuff[
            "sub_program_with_vulnerabilities_several_affect_references"
        ]
        sbom_merged = load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = dictionary_with_stuff[
            "merged_with_vulnerabilities_several_affect_references"
        ]
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_merge_sboms_same_sbom(self) -> None:
        dictionary_with_stuff = load_sections_for_test_sbom()
        sbom1 = load_governing_program()
        sbom1["vulnerabilities"] = dictionary_with_stuff[
            "governing_program_with_vulnerabilities"
        ]
        sbom2 = load_sub_program()
        sbom2["vulnerabilities"] = dictionary_with_stuff[
            "sub_program_with_vulnerabilities_several_affect_references"
        ]
        sbom_merged = load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = dictionary_with_stuff[
            "merged_with_vulnerabilities_several_affect_references"
        ]
        sbom3 = load_governing_program()
        sbom3["vulnerabilities"] = dictionary_with_stuff[
            "governing_program_with_vulnerabilities"
        ]
        sbom4 = load_sub_program()
        sbom4["components"][2]["version"] = "2.24.0"
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom1]), sbom1))
        self.assertTrue(helper.compare_sboms(merge.merge([sbom2, sbom2]), sbom2))
        self.assertTrue(helper.compare_sboms(merge.merge([sbom3, sbom3]), sbom3))
        self.assertTrue(helper.compare_sboms(merge.merge([sbom4, sbom4]), sbom4))
        self.assertTrue(
            helper.compare_sboms(merge.merge([sbom_merged, sbom_merged]), sbom_merged)
        )

    def test_get_component_by_ref(self) -> None:
        sbom = load_sub_program()
        self.assertEqual(
            sbF.get_component_by_ref("not existing ref", sbom["components"]), {}
        )

    def test_different_ratings(self) -> None:
        dictionary_with_stuff = load_sections_for_test_sbom()
        sbom1 = load_governing_program()
        sbom1["vulnerabilities"] = dictionary_with_stuff[
            "governing_program_with_vulnerabilities"
        ]
        sbom2 = load_sub_program()
        sbom2["vulnerabilities"] = dictionary_with_stuff[
            "sub_program_with_vulnerabilities_new_ratings"
        ]
        sbom_merged = load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = dictionary_with_stuff["merged_new_ratings"]
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_with_only_published(self) -> None:
        dictionary_with_stuff = load_sections_for_test_sbom()
        sbom1 = load_governing_program()
        sbom1["vulnerabilities"] = dictionary_with_stuff[
            "governing_program_with_vulnerabilities_published"
        ]
        sbom2 = load_sub_program()
        sbom2["vulnerabilities"] = dictionary_with_stuff[
            "sub_program_with_vulnerabilities_published"
        ]
        sbom_merged = load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = dictionary_with_stuff["merged_published"]
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_with_updated(self) -> None:
        dictionary_with_stuff = load_sections_for_test_sbom()
        sbom1 = load_governing_program()
        sbom1["vulnerabilities"] = dictionary_with_stuff[
            "governing_program_with_vulnerabilities_updated"
        ]
        sbom2 = load_sub_program()
        sbom2["vulnerabilities"] = dictionary_with_stuff[
            "sub_program_with_vulnerabilities_updated"
        ]
        sbom_merged = load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = dictionary_with_stuff["merged_updated"]
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_same_bom_ref_different_component(self) -> None:
        sbom1 = load_governing_program()
        sbom2 = load_sub_program()
        sbom2["components"].append(sbom1["components"][1].copy())
        sbom2["components"][-1]["name"] = "some_new_name"
        merged_bom = merge.merge([sbom1, sbom2])
        self.assertEqual(
            merged_bom["components"][-1]["bom-ref"], "gp_first_component-copy_1"
        )

    def test_no_composition_in_sboms(self) -> None:
        sbom1 = load_governing_program()
        sbom2 = load_sub_program()
        sbom1.pop("compositions")
        sbom2.pop("compositions")
        sbom_merged = load_governing_program_merged_sub_program()
        merged_sbom = merge.merge([sbom1, sbom2])
        sbom_merged.pop("compositions")
        self.assertTrue(helper.compare_sboms(merged_sbom, sbom_merged))

    def test_one_loop_for_renaming(self) -> None:
        sbom1 = load_additional_sbom_dict()["sub_sub_program"]
        sbom2 = load_additional_sbom_dict()["sub_sub_program_2"]
        goal_sbom = load_additional_sbom_dict()["merged_sub_sub_programs"]
        merged_bom = merge.merge([sbom1, sbom2])
        self.assertTrue(helper.compare_sboms(merged_bom, goal_sbom))


class TestCompareComponents(unittest.TestCase):
    def test_equal(self) -> None:
        self.assertTrue(
            sbF.compare_components(
                {
                    "name": "Name1",
                    "version": "1.0",
                    "group": "group1",
                    "purl": "purl1",
                    "cpe": "cpe1",
                    "swid": "swid1",
                },
                {
                    "name": "Name1",
                    "version": "1.0",
                    "group": "group1",
                    "purl": "purl1",
                    "cpe": "cpe1",
                    "swid": "swid1",
                },
            )
        )
        self.assertTrue(
            sbF.compare_components(
                {
                    "name": "Name1",
                    "version": "1.0",
                    "group": "group1",
                    "purl": "purl1",
                    "cpe": "cpe1",
                    "swid": "swid1",
                },
                {
                    "name": "Name2",
                    "version": "2.0",
                    "group": "group2",
                    "purl": "purl1",
                    "cpe": "cpe1",
                    "swid": "swid1",
                },
            )
        )
        self.assertTrue(
            sbF.compare_components(
                {
                    "name": "Name1",
                    "version": "1.0",
                    "group": "group1",
                    "cpe": "cpe1",
                    "swid": "swid1",
                },
                {
                    "name": "Name2",
                    "version": "2.0",
                    "group": "group2",
                    "cpe": "cpe1",
                    "swid": "swid1",
                },
            )
        )
        self.assertTrue(
            sbF.compare_components(
                {"name": "Name1", "version": "1.0", "group": "group1", "swid": "swid1"},
                {"name": "Name2", "version": "2.0", "group": "group2", "swid": "swid1"},
            )
        )
        self.assertTrue(
            sbF.compare_components(
                {"name": "Name1", "version": "1.0", "group": "group1", "purl": "purl1"},
                {
                    "name": "Name1",
                    "version": "1.0",
                    "group": "group1",
                    "cpe": "cpe1",
                    "swid": "swid1",
                },
            )
        )
        self.assertTrue(
            sbF.compare_components(
                {
                    "name": "Name1",
                    "version": "1.0",
                    "group": "group1",
                    "purl": "purl1",
                    "cpe": "cpe1",
                    "swid": "swid1",
                },
                {
                    "name": "Name1",
                    "version": "1.0",
                    "group": "group1",
                    "purl": "purl1",
                    "cpe": "cpe1",
                    "swid": "swid1",
                },
            )
        )
        self.assertTrue(
            sbF.compare_components(
                {
                    "name": "Name2",
                    "version": "1.0",
                    "group": "group1",
                    "purl": "purl1",
                    "cpe": "cpe1",
                    "swid": "swid1",
                },
                {"name": "Name1", "version": "1.0", "group": "group1", "cpe": "cpe1"},
            )
        )

    def test_unequal(self) -> None:
        self.assertFalse(
            sbF.compare_components(
                {
                    "name": "Name1",
                    "version": "1.0",
                    "group": "group1",
                    "purl": "purl1",
                    "cpe": "cpe1",
                    "swid": "swid1",
                },
                {
                    "name": "Name1",
                    "version": "1.0",
                    "group": "group1",
                    "purl": "purl2",
                    "cpe": "cpe1",
                    "swid": "swid1",
                },
            )
        )
        self.assertFalse(
            sbF.compare_components(
                {
                    "name": "Name1",
                    "version": "1.0",
                    "group": "group1",
                    "purl": "purl1",
                    "cpe": "cpe1",
                    "swid": "swid1",
                },
                {
                    "name": "Name1",
                    "version": "1.0",
                    "group": "group1",
                    "purl": "purl1",
                    "cpe": "cpe1",
                    "swid": "swid2",
                },
            )
        )
        self.assertFalse(
            sbF.compare_components(
                {
                    "name": "Name1",
                    "version": "1.0",
                    "group": "group1",
                    "purl": "purl1",
                    "cpe": "cpe2",
                    "swid": "swid1",
                },
                {
                    "name": "Name1",
                    "version": "1.0",
                    "group": "group1",
                    "purl": "purl1",
                    "cpe": "cpe1",
                    "swid": "swid1",
                },
            )
        )
        self.assertFalse(
            sbF.compare_components(
                {
                    "name": "Name1",
                    "version": "2.0",
                    "group": "group1",
                    "cpe": "cpe2",
                    "swid": "swid1",
                },
                {"name": "Name1", "version": "1.0", "group": "group1", "purl": "purl1"},
            )
        )
        self.assertFalse(
            sbF.compare_components(
                {"name": "Name1", "version": "1.0", "group": "group1"},
                {"name": "Name1", "version": "1.0", "group": "group2"},
            )
        )


class TestMergeSeveralSboms(unittest.TestCase):
    def test_merge_3_sboms(self) -> None:
        governing_program = load_governing_program()
        sub_program = load_sub_program()
        sub_sub_program = load_additional_sbom_dict()["sub_sub_program"]
        goal_sbom = load_additional_sbom_dict()["merge_goverment_sub_sub_sub"]
        merged_bom = merge.merge([governing_program, sub_program, sub_sub_program])
        self.assertTrue(helper.compare_sboms(merged_bom, goal_sbom))

    def test_merge_4_sboms(self) -> None:
        governing_program = load_governing_program()
        sub_program = load_sub_program()
        sub_sub_program = load_additional_sbom_dict()["sub_sub_program"]
        goal_sbom = load_additional_sbom_dict()[
            "merge_goverment_sub_sub_sub_and_sub_sub_2"
        ]
        sub_sub_program_2 = load_additional_sbom_dict()["sub_sub_program_2"]
        merged_bom = merge.merge(
            [governing_program, sub_program, sub_sub_program, sub_sub_program_2]
        )
        self.assertTrue(helper.compare_sboms(merged_bom, goal_sbom))


class TestReplaceBomRefs(unittest.TestCase):
    def test_replace_licenses(self) -> None:
        sbom = load_governing_program_merged_sub_program()
        sbom["dependencies"] = dictionary_with_stuff["dependencies_tls_equal"]
        sbom["compositions"] = dictionary_with_stuff["compositions_tls_equal"]
        sbom["components"] = [
            component
            for component in sbom["components"]
            if component["bom-ref"] != "sp_fifteenth_component"
        ]
        sbom["vulnerabilities"] = dictionary_with_stuff["vulnerabilities_tls_equal"]
        list_of_bom_refs = sbF.get_ref_from_components(sbom.get("components", []))
        sbom_bom_refs_replaced = load_additional_sbom_dict()[
            "sbom_with_bom_refs_replaced"
        ]
        list_of_bom_refs.append(sbom["metadata"]["component"]["bom-ref"])
        for bom_ref in list_of_bom_refs:
            new_reference = bom_ref + "_replaced"
            merge.replace_ref_in_sbom(new_reference, bom_ref, sbom)
        self.assertTrue(helper.compare_sboms(sbom, sbom_bom_refs_replaced))

    def test_new_license_already_exists(self) -> None:
        sbom = load_governing_program_merged_sub_program()
        self.assertFalse(
            merge.replace_ref_in_sbom("gp_first_component-copy", "sub_program", sbom)
        )


class TestMergeComponents(unittest.TestCase):
    list_of_component_names = [
        "component_1",
        "component_2",
        "component_3",
        "component_4",
        "component_1_sub_1",
        "component_2_sub_1",
        "component_2_sub_2",
        "component_2_sub_1_sub_1",
        "component_4_sub_1",
        "component_4_sub_1_sub_1",
        "component_4_sub_1_sub_2",
    ]

    def test_merge_components(self) -> None:
        sub_sub_program = load_additional_sbom_dict()["sub_sub_program"]
        sub_program = load_sub_program()
        merge.replace_ref_in_sbom(
            "gp_first_component-copy", "sp_first_component", sub_program
        )
        merge.merge_components(sub_program, sub_sub_program)

    def test_renaming_same_component_in_other_sbom(self) -> None:
        sub_sub_program = load_additional_sbom_dict()["sub_sub_program"]
        sub_sub_program_sub_sub = load_additional_sbom_dict()[
            "sub_sub_program_sub_program"
        ]
        sub_sub_program_sub_program_modified = load_additional_sbom_dict()[
            "sub_sub_program_sub_program_modified"
        ]
        merge.merge_components(sub_sub_program, sub_sub_program_sub_sub)
        self.assertTrue(
            helper.compare_sboms(
                sub_sub_program_sub_program_modified, sub_sub_program_sub_sub
            )
        )

    def test_filter_component(self) -> None:
        # considered test cases:
        # - top level component present, sub component not
        # - top level component not present, sublevel component present
        #   sub_sub component not present
        # - top level not present, sub_sub present
        components = helper.create_components(self.list_of_component_names)

        component_1 = components["component_1"]
        component_2 = components["component_2"]
        component_3 = components["component_3"]
        component_4 = components["component_4"]
        component_1_sub_1 = components["component_1_sub_1"]
        component_2_sub_1 = components["component_2_sub_1"]
        component_2_sub_2 = components["component_2_sub_2"]
        component_2_sub_1_sub_1 = components["component_2_sub_1_sub_1"]
        component_4_sub_1 = components["component_4_sub_1"]
        component_4_sub_1_sub_1 = components["component_4_sub_1_sub_1"]
        component_4_sub_1_sub_2 = components["component_4_sub_1_sub_2"]

        present_components = [
            ComponentIdentity.create(component_1, allow_unsafe=True),
            ComponentIdentity.create(component_3, allow_unsafe=True),
            ComponentIdentity.create(component_2_sub_1, allow_unsafe=True),
            ComponentIdentity.create(component_4_sub_1_sub_2, allow_unsafe=True),
        ]

        component_1["components"] = [component_1_sub_1]

        component_2["components"] = [component_2_sub_1, component_2_sub_2]
        component_2_sub_1["components"] = [component_2_sub_1_sub_1]

        component_4["components"] = [component_4_sub_1]
        component_4_sub_1["components"] = [
            component_4_sub_1_sub_1,
            component_4_sub_1_sub_2,
        ]

        new_components = [component_1, component_2, component_4]

        kept_components: list[dict] = []
        dropped_components: list[dict] = []
        add_to_existing: dict[ComponentIdentity, dict] = {}

        merge.filter_component(
            present_components,
            new_components,
            kept_components,
            dropped_components,
            add_to_existing,
        )

        add_to_existing_expected = {
            ComponentIdentity.create(component_1, allow_unsafe=True): [
                component_1_sub_1
            ],
            ComponentIdentity.create(component_2_sub_1, allow_unsafe=True): [
                component_2_sub_1_sub_1
            ],
        }

        add_to_existing_identical = True
        for key in add_to_existing_expected.keys():
            if add_to_existing_expected[key] != add_to_existing[key]:
                add_to_existing_identical = False

        kept_components_expected = [
            component_2,
            component_4_sub_1_sub_1,
            component_4_sub_1,
            component_2_sub_1_sub_1,
            component_2_sub_2,
            component_1_sub_1,
            component_4,
        ]

        kept_components_identical = True
        for comp in kept_components:
            if comp not in kept_components_expected:
                kept_components_identical = False

        self.assertTrue(len(dropped_components) == 3)
        self.assertTrue(
            len(add_to_existing.keys()) == len(add_to_existing_expected.keys())
        )
        self.assertTrue(len(kept_components) == len(kept_components_expected))
        self.assertTrue(add_to_existing_identical)
        self.assertTrue(kept_components_identical)

    def test_merge_hierarchical(self) -> None:
        components = helper.create_components(self.list_of_component_names)
        component_1 = copy.deepcopy(components["component_1"])
        component_2 = copy.deepcopy(components["component_2"])
        component_3 = copy.deepcopy(components["component_3"])
        component_4 = copy.deepcopy(components["component_4"])
        component_1_sub_1 = copy.deepcopy(components["component_1_sub_1"])
        component_2_sub_1 = copy.deepcopy(components["component_2_sub_1"])
        component_2_sub_2 = copy.deepcopy(components["component_2_sub_2"])
        component_2_sub_1_sub_1 = copy.deepcopy(components["component_2_sub_1_sub_1"])
        component_4_sub_1 = copy.deepcopy(components["component_4_sub_1"])
        component_4_sub_1_sub_1 = copy.deepcopy(components["component_4_sub_1_sub_1"])
        component_4_sub_1_sub_2 = copy.deepcopy(components["component_4_sub_1_sub_2"])

        present_components = [
            ComponentIdentity.create(component_1, allow_unsafe=True),
            ComponentIdentity.create(component_3, allow_unsafe=True),
            ComponentIdentity.create(component_2_sub_1, allow_unsafe=True),
            ComponentIdentity.create(component_4_sub_1_sub_2, allow_unsafe=True),
        ]

        present_components = [
            copy.deepcopy(component_1),
            copy.deepcopy(component_3),
            copy.deepcopy(component_2_sub_1),
            copy.deepcopy(component_4_sub_1_sub_2),
        ]
        component_1["components"] = [component_1_sub_1]

        component_2["components"] = [component_2_sub_1, component_2_sub_2]
        component_2_sub_1["components"] = [component_2_sub_1_sub_1]

        component_4["components"] = [component_4_sub_1]
        component_4_sub_1["components"] = [
            component_4_sub_1_sub_1,
            component_4_sub_1_sub_2,
        ]

        new_components = [component_1, component_2, component_4]

        merged_components = merge.merge_components(
            {"components": present_components},
            {"components": new_components},
            hierarchical=True,
        )

        # create expected result
        components_expected = helper.create_components(self.list_of_component_names)

        components_expected["component_1"]["components"] = [
            components_expected["component_1_sub_1"]
        ]

        components_expected["component_2"]["components"] = [
            components_expected["component_2_sub_2"]
        ]
        components_expected["component_2_sub_1"]["components"] = [
            components_expected["component_2_sub_1_sub_1"]
        ]

        components_expected["component_4"]["components"] = [
            components_expected["component_4_sub_1"]
        ]
        components_expected["component_4_sub_1"]["components"] = [
            components_expected["component_4_sub_1_sub_1"],
        ]

        expected_components = [
            components_expected["component_1"],
            components_expected["component_3"],
            components_expected["component_2_sub_1"],
            components_expected["component_4_sub_1_sub_2"],
            components_expected["component_2"],
            components_expected["component_4"],
        ]

        self.assertEqual(merged_components, expected_components)


class TestMergeCompositions(unittest.TestCase):
    def test_only_first_sbom_contains_compositions(self) -> None:
        governing_program = load_governing_program()
        sub_program = load_sub_program()
        sub_program.pop("compositions")
        merged_sbom = merge.merge([governing_program, sub_program])
        goal_sbom = load_governing_program_merged_sub_program()
        goal_sbom["compositions"] = governing_program["compositions"]
        self.assertTrue(helper.compare_sboms(merged_sbom, goal_sbom))

    def test_only_second_sbom_contains_compositions(self) -> None:
        compositions_2 = [
            {"aggregate": "incomplete", "assemblies": ["first_ref", "second_ref"]}
        ]
        compositions_1 = []
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


if __name__ == "__main__":
    unittest.main()
