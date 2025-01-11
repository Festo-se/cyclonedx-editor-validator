# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import unittest
import copy

from cdxev import merge
from cdxev.auxiliary import sbomFunctions as sbF
from cdxev.auxiliary.identity import ComponentIdentity
from tests.auxiliary import helper as helper
from cdxev.auxiliary.identity import ComponentIdentity

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


class TestMergeSboms(unittest.TestCase):
    def test_no_vulnerabilities(self) -> None:
        sbom1 = load_governing_program()
        sbom2 = load_sub_program()
        sbom_merged = load_governing_program_merged_sub_program()
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_vulnerabilities_in_the_second(self) -> None:
        sbom1 = load_governing_program()
        sbom2 = load_sub_program()
        vulnerabilities = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]
        original_vulnerabilities = vulnerabilities["original_vulnerabilities"]

        sbom2["vulnerabilities"] = original_vulnerabilities
        sbom_merged = load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = original_vulnerabilities
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_vulnerabilities_in_the_first(self) -> None:
        sbom1 = load_governing_program()
        vulnerabilities = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]
        original_vulnerabilities = vulnerabilities["original_vulnerabilities"]

        sbom1["vulnerabilities"] = original_vulnerabilities
        sbom2 = load_sub_program()
        sbom_merged = load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = original_vulnerabilities
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_merge_sboms_same_sbom(self) -> None:
        vulnerabilities = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]
        original_vulnerabilities = vulnerabilities["original_vulnerabilities"]
        new_vulnerabilities = vulnerabilities["new_vulnerabilities"]
        merged_vulnerabilities = vulnerabilities["merged_vulnerabilities"]

        sbom1 = load_governing_program()
        sbom1["vulnerabilities"] = new_vulnerabilities
        sbom2 = load_sub_program()
        sbom2["vulnerabilities"] = original_vulnerabilities
        sbom_merged = load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = merged_vulnerabilities
        sbom3 = load_governing_program()
        sbom3["vulnerabilities"] = original_vulnerabilities
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

    def test_no_composition_in_sboms(self) -> None:
        sbom1 = load_governing_program()
        sbom2 = load_sub_program()
        sbom1.pop("compositions")
        sbom2.pop("compositions")
        sbom_merged = load_governing_program_merged_sub_program()
        merged_sbom = merge.merge([sbom1, sbom2])
        sbom_merged.pop("compositions")
        self.assertTrue(helper.compare_sboms(merged_sbom, sbom_merged))


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

    def test_replace_ref_in_component(self) -> None:
        component = {
            "type": "library",
            "bom-ref": "sub_program",
            "supplier": {"name": "Company Legal"},
            "group": "com.company.governing",
            "name": "sub_program",
            "copyright": "Company Legal 2022, all rights reserved",
            "version": "T5.0.3.96",
        }
        component_2 = {"bom-ref": "value"}
        component_3: dict = {}
        reference = "sub_program"
        new_reference = "new"
        component_list: list[dict] = [component, component_2, {}]
        component_list_copy = copy.deepcopy(component_list)

        merge.replace_ref_in_components(component_list, "...", new_reference)
        self.assertEqual(component_list, component_list_copy)

        merge.replace_ref_in_components(
            [component, component_2, component_3], reference, new_reference
        )
        self.assertEqual(component["bom-ref"], new_reference)
        self.assertEqual(component_2["bom-ref"], "value")

    def test_replace_ref_in_dependencies(self) -> None:
        dependencies = [
            {"ref": "sp_second_component", "dependsOn": []},
            {
                "ref": "sp_fourth_component",
                "dependsOn": ["sp_second_component", "sp_second_component", "other"],
            },
        ]
        dependencies_copy = copy.deepcopy(dependencies)

        reference = "sp_second_component"
        new_reference = "new"

        merge.replace_ref_in_dependencies(dependencies, "...", new_reference)
        self.assertEqual(dependencies, dependencies_copy)

        merge.replace_ref_in_dependencies(dependencies, reference, new_reference)
        self.assertEqual(dependencies[0]["ref"], new_reference)
        self.assertEqual(dependencies[1]["ref"], "sp_fourth_component")
        self.assertEqual(
            dependencies[1]["dependsOn"], [new_reference, new_reference, "other"]
        )

    def test_replace_ref_in_compositions(self) -> None:
        compositions = [
            {
                "aggregate": "complete",
                "assemblies": [
                    "sp_first_component",
                    "sp_second_component",
                    "sp_fourth_component",
                ],
            },
            {
                "aggregate": "incomplete",
                "assemblies": [
                    "sp_fifth_component",
                    "sp_sixth_component",
                    "sp_second_component",
                    "sp_second_component",
                ],
            },
        ]
        compositions_copy = copy.deepcopy(compositions)
        reference = "sp_second_component"
        new_reference = "new"

        merge.replace_ref_in_compositions(compositions, "...", new_reference)
        self.assertEqual(compositions, compositions_copy)

        compositions_copy[0]["assemblies"][1] = new_reference  # type:ignore
        compositions_copy[1]["assemblies"][2] = new_reference  # type:ignore
        compositions_copy[1]["assemblies"][3] = new_reference  # type:ignore

        merge.replace_ref_in_compositions(compositions, reference, new_reference)
        self.assertEqual(compositions, compositions_copy)

    def test_replace_ref_in_vulnerabilities(self) -> None:
        vulnerabilities = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]["original_vulnerabilities"]
        vulnerabilities_replaced = load_sections_for_test_sbom()[
            "vulnerabilities_ref_product_3_replaced"
        ]
        reference = "product 3"
        new_reference = "new"
        merge.replace_ref_in_vulnerabilities(vulnerabilities, reference, new_reference)
        self.assertEqual(vulnerabilities, vulnerabilities_replaced)

    def test_get_ref_components_mapping(self) -> None:
        components = [
            {"name": "comp 1", "version": "1.0.0", "bom-ref": "com-1"},
            {"name": "comp 3", "version": "1.0.0", "bom-ref": "com-2"},
            {"name": "comp 3", "version": "1.0.0", "bom-ref": "com-3"},
        ]
        ref_mapping = merge.get_ref_components_mapping(components)
        self.assertEqual(
            ref_mapping,
            {
                "com-1": ComponentIdentity.create(components[0], allow_unsafe=True),
                "com-2": ComponentIdentity.create(components[1], allow_unsafe=True),
                "com-3": ComponentIdentity.create(components[2], allow_unsafe=True),
            },
        )

    def test_make_bom_refs_unique(self) -> None:
        sbom_1 = load_sections_for_test_sbom()["sbom_replace_references_1"]
        sbom_2 = load_sections_for_test_sbom()["sbom_replace_references_2"]
        sbom_3 = load_sections_for_test_sbom()["sbom_replace_references_3"]
        sbom_4 = load_sections_for_test_sbom()["sbom_replace_references_4"]

        sbom_2_replaced = load_sections_for_test_sbom()[
            "sbom_replace_references_2_replaced"
        ]
        sbom_3_replaced = load_sections_for_test_sbom()[
            "sbom_replace_references_3_replaced"
        ]
        sbom_4_replaced = load_sections_for_test_sbom()[
            "sbom_replace_references_4_replaced"
        ]

        sbom_1_copy = copy.deepcopy(sbom_1)
        merge.make_bom_refs_unique([sbom_1, sbom_2, sbom_3, sbom_4])

        self.assertEqual(sbom_1, sbom_1_copy)
        self.assertEqual(sbom_2_replaced, sbom_2)
        self.assertEqual(sbom_3_replaced, sbom_3)
        self.assertEqual(sbom_4_replaced, sbom_4)

    def test_make_bom_ref_unique_several_loops(self) -> None:
        components_1 = {
            "components": [
                {
                    "name": "comp 1",
                    "version": "1.0.0",
                    "bom-ref": "COORDINATES[comp 1@2.0.0]",
                }
            ]
        }
        components_2 = {
            "components": [
                {
                    "name": "comp 1",
                    "version": "2.0.0",
                    "bom-ref": "COORDINATES[comp 1@2.0.0]",
                },
                {
                    "name": "comp 3",
                    "version": "1.0.0",
                    "bom-ref": "COORDINATES[comp 1@2.0.0]-1",
                },
                {
                    "name": "comp 3",
                    "version": "1.0.0",
                    "bom-ref": "COORDINATES[comp 1@2.0.0]-2",
                },
            ]
        }
        merge.make_bom_refs_unique([components_1, components_2])

        self.assertEqual(
            components_2["components"][0]["bom-ref"], "COORDINATES[comp 1@2.0.0]-3"
        )

    def test_unify_bom_refs(self) -> None:
        sbom_1 = load_sections_for_test_sbom()["sbom_unify_references_1"]
        sbom_2 = load_sections_for_test_sbom()["sbom_unify_references_2"]
        sbom_3 = copy.deepcopy(sbom_1)
        sbom_3["vulnerabilities"] = copy.deepcopy(sbom_2["vulnerabilities"])
        merge.replace_ref_in_vulnerabilities(
            sbom_3["vulnerabilities"], "comp 3 -", "comp 3"
        )
        merge.replace_ref_in_vulnerabilities(
            sbom_3["vulnerabilities"], "comp 2 -", "comp 2"
        )
        merge.replace_ref_in_vulnerabilities(
            sbom_3["vulnerabilities"], "comp 1 -", "comp 1"
        )
        sbom_3["components"][2] = copy.deepcopy(sbom_2["components"][2])
        sbom_3["components"][2]["bom-ref"] = "comp 3"

        sbom_3_expected = copy.deepcopy(sbom_1)
        sbom_3_expected["components"][2] = copy.deepcopy(sbom_2["components"][2])
        sbom_3_expected["vulnerabilities"] = copy.deepcopy(sbom_2["vulnerabilities"])
        merge.replace_ref_in_components(
            sbom_3_expected["components"], "comp 3", "comp 3 -"
        )
        merge.replace_ref_in_compositions(
            sbom_3_expected["compositions"], "comp 3", "comp 3 -"
        )
        merge.replace_ref_in_dependencies(
            sbom_3_expected["dependencies"], "comp 3", "comp 3 -"
        )

        merge.replace_ref_in_vulnerabilities(
            sbom_3_expected["vulnerabilities"], "comp 1 -", "comp 1"
        )

        merge.replace_ref_in_vulnerabilities(
            sbom_3_expected["vulnerabilities"], "comp 2 -", "comp 2"
        )

        sbom_2_expected = copy.deepcopy(sbom_1)
        sbom_2_expected["vulnerabilities"] = copy.deepcopy(
            sbom_3_expected["vulnerabilities"]
        )

        sbom_2_expected["components"][2] = copy.deepcopy(sbom_2["components"][2])
        merge.replace_ref_in_components(
            sbom_2_expected["components"], "comp 3", "comp 3 -"
        )
        merge.replace_ref_in_compositions(
            sbom_2_expected["compositions"], "comp 3", "comp 3 -"
        )
        merge.replace_ref_in_dependencies(
            sbom_2_expected["dependencies"], "comp 3", "comp 3 -"
        )
        merge.replace_ref_in_vulnerabilities(
            sbom_2_expected["vulnerabilities"], "comp 3", "comp 3 -"
        )

        merge.unify_bom_refs([sbom_1, sbom_2, sbom_3])

        self.assertEqual(sbom_1, sbom_1)
        self.assertEqual(sbom_2, sbom_2_expected)
        self.assertEqual(sbom_3, sbom_3_expected)


class TestMergeComponents(unittest.TestCase):
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
        components = load_sections_for_test_sbom()["hierarchical_components"]
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

        kept_components_expected = load_sections_for_test_sbom()[
            "test_filter_component_kept_components_expected"
        ]
        new_components = load_sections_for_test_sbom()[
            "test_filter_component_new_components"
        ]
        components["component_1"]["components"] = [components["component_1_sub_1"]]

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

    def test_individual_merge_cases(self) -> None:
        test_cases = load_sections_for_test_sbom()["singled_out_test_cases"]

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
        new_components = load_sections_for_test_sbom()[
            "test_merge_hierarchical_new_components"
        ]
        present_components = load_sections_for_test_sbom()[
            "test_merge_hierarchical_present_components"
        ]

        merged_components = merge.merge_components(
            {"components": present_components},
            {"components": new_components},
            hierarchical=True,
        )

        expected_components = load_sections_for_test_sbom()["hierarchical_expected"]

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


class TestVulnerabilities(unittest.TestCase):
    def test_get_ids_from_vulnerability(self) -> None:
        vulnerability = {
            "id": "CVE-2021-39182",
            "references": [
                {"id": "CVE-2021-39182"},
                {"id": "GHSA-35m5-8cvj-8783"},
                {"id": "SNYK-PYTHON-ENROCRYPT-1912876"},
            ],
        }

        ids = merge.get_ids_from_vulnerability(vulnerability)
        self.assertEqual(
            ids,
            [
                "CVE-2021-39182",
                "GHSA-35m5-8cvj-8783",
                "SNYK-PYTHON-ENROCRYPT-1912876",
            ],
        )

    def test_compare_version_range(self) -> None:
        self.assertTrue(
            merge.compare_version_range(
                "vers:tomee/>=1.0.0-beta1|<=1.7.5|>=7.0.0|<=7.0.7|>=7.1.0|<=7.1.2|>=8.0.0",
                "vers:tomee/>=1.0.0-beta1|<=1.7.5|>=7.0.0|<=7.0.7|>=7.1.0|<=7.1.2|>=8.0.0",
            )
        )

        self.assertFalse(
            merge.compare_version_range(
                "vers:pypi/>=1.0.0-beta1|<=1.7.5|>=7.0.0|<=7.0.7|>=7.1.0|<=7.1.2|>=8.0.0",
                "vers:pypi/>=1.0.0-beta1|<=1.7.5|>=7.0.0|<=7.0.7|>=7.1.0|<=7.1.2",
            )
        )

        self.assertTrue(
            merge.compare_version_range(
                "vers:pypi/>=1.0.0-beta1|<=1.7.5|>=7.0.0|<=7.0.7|>=7.1.0|<=7.1.2|>=8.0.0",
                "vers:pypi/>=1.0.0-beta1|<=7.0.7|>=7.1.0|<=7.1.2|>=8.0.0|<=1.7.5|>=7.0.0",
            )
        )

    def test_version_is_in_version_range(self) -> None:
        self.assertTrue(
            merge.version_is_in_version_range("8.0.0", "vers:cargo/<9.0.14")
        )
        self.assertFalse(
            merge.version_is_in_version_range("10.0.0", "vers:cargo/<9.0.14")
        )

    def test_compare_affects_version_object(self) -> None:
        self.assertEqual(
            merge.compare_affects_versions_object(
                {"range": "vers:cargo/>9.0.14"}, {"range": "vers:cargo/<9.0.14"}
            ),
            3,
        )
        self.assertEqual(
            merge.compare_affects_versions_object(
                {
                    "range": "vers:pypi/>=1.0.0|<=1.7.5|>=7.0.0|<=7.0.7|>=7.1.0|<=7.1.2|>=8.0.0"
                },
                {
                    "range": "vers:pypi/>=1.0.0|<=7.0.7|>=7.1.0|<=7.1.2|>=8.0.0|<=1.7.5|>=7.0.0"
                },
            ),
            1,
        )
        self.assertEqual(
            merge.compare_affects_versions_object(
                {"version": "9.0.14", "range": "vers:cargo/<9.0.14"},
                {"version": "9.0.0", "range": "vers:cargo/<9.0.14"},
            ),
            0,
        )
        self.assertEqual(
            merge.compare_affects_versions_object(
                {"version": "8.0.0", "range": "vers:cargo/<9.0.14"},
                {"version": "8.0.0", "range": "vers:cargo/>9.0.14"},
            ),
            1,
        )

        self.assertEqual(
            merge.compare_affects_versions_object(
                {"range": "vers:cargo/<9.0.14"}, {"version": "8.0.0"}
            ),
            2,
        )

        self.assertEqual(
            merge.compare_affects_versions_object(
                {"version": "8.0.0"}, {"range": "vers:cargo/<9.0.14"}
            ),
            -1,
        )

        self.assertEqual(
            merge.compare_affects_versions_object(
                {"range": "vers:cargo/<9.0.14"},
                {"version": "8.0.0", "range": "vers:cargo/<9.0.14"},
            ),
            2,
        )

        self.assertEqual(
            merge.compare_affects_versions_object(
                {"version": "8.0.0", "range": "vers:cargo/<9.0.14"},
                {"range": "vers:cargo/<9.0.14"},
            ),
            -1,
        )

    def test_get_new_affects_versions(self) -> None:
        lists = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_get_new_affects_versions"
        ]
        kept_versions = merge.get_new_affects_versions(
            lists["original_versions_list"],
            lists["new_versions_list"],
            "vuln_id",
            "ref",
        )

        self.assertEqual(
            kept_versions,
            [
                {"version": "2.7", "status": "be kept"},
                {
                    "range": "vers:generic/>=2.5|<=4.1|!=2.6|!=4.0",
                    "status": "2.6 removed",
                },
            ],
        )

    def test_join_affect_versions_with_same_references(self) -> None:
        lists = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "extract_new_affects"
        ]["original_affects"]
        joined_lists = merge.join_affect_versions_with_same_references(lists)

        self.assertEqual(joined_lists["product 2"], lists[2]["versions"])
        self.assertEqual(
            joined_lists["product 1"],
            lists[0]["versions"] + lists[1]["versions"] + lists[3]["versions"],
        )

    def test_extract_new_affects(self) -> None:
        lists = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "extract_new_affects"
        ]
        kept_affects = merge.extract_new_affects(
            lists["original_affects"], lists["new_affects"], "vuln_id"
        )

        self.assertEqual(
            kept_affects,
            [
                {
                    "ref": "product 1",
                    "versions": [
                        {"version": "1.4", "status": "affected"},
                        {"version": "2.2", "status": "affected"},
                        {"range": "vers:generic/>=1.1|<=1.2", "status": "affected"},
                    ],
                },
                {
                    "ref": "product 3",
                    "versions": [{"version": "1.4", "status": "affected"}],
                },
                {
                    "ref": "product 1",
                    "versions": [
                        {"range": "vers:generic/>=2.9|<=5.1", "status": "affected"}
                    ],
                },
            ],
        )

        vulnerabilities = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]
        original_vulnerabilities = vulnerabilities["original_vulnerabilities"]

        actual_merged = merge.extract_new_affects(
            original_vulnerabilities[2]["affects"],
            original_vulnerabilities[2]["affects"],
            "vuln_id",
        )

        self.assertEqual(actual_merged, [])

    def test_vulnerability_identity_Class(self) -> None:
        identity = merge.VulnerabilityIdentity("id", ["ref 1", "ref 2"])
        self.assertEqual(identity.__str__(), "id_|_ref 1_|_ref 2")
        self.assertEqual(identity.aliases, ["ref 1", "ref 2"])
        self.assertTrue(identity.id_is_in("id"))
        self.assertTrue(identity.one_of_ids_is_in(["ll", "ref 2", ".l"]))
        self.assertFalse(identity.id_is_in("id 2"))
        self.assertFalse(identity.one_of_ids_is_in(["ll", "ref 22", ".l"]))
        self.assertEqual(
            identity,
            merge.VulnerabilityIdentity.from_vulnerability(
                {
                    "id": "id",
                    "references": [{"id": "ref 1"}, {"id": "ref 2"}],
                },
            ),
        )
        self.assertEqual(
            merge.VulnerabilityIdentity.from_string("id_|_ref 1_|_ref 2_|_ref 3"),
            merge.VulnerabilityIdentity("id", ["id", "ref 1", "ref 2", "ref 3"]),
        )
        self.assertTrue(
            merge.VulnerabilityIdentity.from_string("id_|_ref 1_|_ref 2_|_ref 3")
            == merge.VulnerabilityIdentity("id", ["id", "ref 1", "ref 2", "ref 3"])
        )
        self.assertTrue(
            merge.VulnerabilityIdentity.from_string("id_|_ref 1_|_ref 2_|_ref 3")
            == merge.VulnerabilityIdentity("", ["id", "ref 1", "ref 2", "ref 3"])
        )
        self.assertTrue(
            merge.VulnerabilityIdentity.from_string("id2_|_ref 11_|_ref 22_|_ref 3")
            == merge.VulnerabilityIdentity("", ["id", "ref 1", "ref 2", "ref 3"])
        )

    def test_get_identities_for_vulnerabilities(self) -> None:
        vulnerabilities = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "get_identities_for_vulnerabilities"
        ]
        identities = merge.get_identities_for_vulnerabilities(vulnerabilities)
        self.assertEqual(len(identities.keys()), 3)
        self.assertEqual(
            identities[json.dumps(vulnerabilities[0], sort_keys=True)],
            identities[json.dumps(vulnerabilities[1], sort_keys=True)],
        )
        self.assertEqual(
            identities[json.dumps(vulnerabilities[2], sort_keys=True)].aliases,
            merge.get_ids_from_vulnerability(vulnerabilities[2]),
        )

    def test_identities_for_vulnerabilities(self) -> None:
        vulnerabilities = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_identities_for_vulnerabilities"
        ]
        identities = merge.get_identities_for_vulnerabilities(vulnerabilities)
        self.assertEqual(
            set(identities[json.dumps(vulnerabilities[0], sort_keys=True)].aliases),
            set(
                [
                    "ref 1",
                    "ref 2",
                    "ref 3",
                    "ref 4",
                    "ref 5",
                    "ref 6",
                    "ref 7",
                    "ref 8",
                    "ref 9",
                    "ref 10",
                ]
            ),
        )

    def test_collect_affects_of_vulnerabilities(self) -> None:
        lists = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "collect_affects_of_vulnerabilities"
        ]
        identities = merge.get_identities_for_vulnerabilities(lists)
        collected = merge.collect_affects_of_vulnerabilities(lists, identities)

        vuln_id = identities[json.dumps(lists[0], sort_keys=True)].string()
        self.assertEqual(
            collected[vuln_id],
            [
                {
                    "ref": "product 1",
                    "versions": [
                        {"version": "2.4", "status": "affected"},
                        {"version": "2.6", "status": "affected"},
                        {"range": "vers:generic/>=2.9|<=4.1", "status": "affected"},
                    ],
                },
                {
                    "ref": "product 2",
                    "versions": [{"version": "3.4", "status": "affected"}],
                },
                {
                    "ref": "product 2",
                    "versions": [
                        {"version": "2.4", "status": "affected"},
                        {"version": "2.6", "status": "affected"},
                        {"range": "vers:generic/>=2.9|<=4.1", "status": "affected"},
                    ],
                },
            ],
        )

    def test_merge_vulnerabilities(self) -> None:
        vulnerabilities = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]
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
        vulnerabilities = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]
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
        vulnerabilities = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]
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
        sections = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]
        original_sbom = sections["merge.input_1"]
        new_sbom = sections["merge.input_2"]
        goal_sbom = sections["test_merge_replace_ref_goal"]

        merged_sbom = merge.merge_2_sboms(original_sbom, new_sbom)

        self.assertEqual(merged_sbom, goal_sbom)


# TODO write tests that verify the replacement of refs!!

if __name__ == "__main__":
    unittest.main()
