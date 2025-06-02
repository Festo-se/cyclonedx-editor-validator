import json
import unittest
from copy import deepcopy
from typing import Sequence

from cdxev.auxiliary import sbomFunctions as sbF
from cdxev.auxiliary.identity import ComponentIdentity
from tests.auxiliary.helper import load_sections_for_test_sbom, load_sub_program


class TestComponentFunctions(unittest.TestCase):
    def test_extract_components(self) -> None:
        example_list: Sequence[dict] = [
            {
                "bom-ref": "first_level_1",
                "components": [
                    {
                        "bom-ref": "second_level_1",
                    },
                    {
                        "bom-ref": "second_level_2",
                        "components": [
                            {
                                "bom-ref": "third_level_1",
                            },
                            {
                                "bom-ref": "third_level_2",
                            },
                        ],
                    },
                ],
            },
            {
                "bom-ref": "first_level_2",
                "components": [
                    {
                        "bom-ref": "second_level_3",
                        "components": [
                            {
                                "bom-ref": "third_level_3",
                                "components": [
                                    {
                                        "bom-ref": "fourth_level_1",
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "bom-ref": "second_level_4",
                    },
                ],
            },
            {
                "bom-ref": "first_level_3",
                "components": [
                    {
                        "bom-ref": "second_level_5",
                    }
                ],
            },
        ]
        components = sbF.extract_components(example_list)
        list_of_references = []
        for comp in components:
            list_of_references.append(comp["bom-ref"])
        self.assertEqual(
            set(list_of_references),
            set(
                [
                    "first_level_1",
                    "first_level_2",
                    "first_level_3",
                    "second_level_1",
                    "second_level_2",
                    "second_level_3",
                    "second_level_4",
                    "second_level_5",
                    "third_level_1",
                    "third_level_2",
                    "third_level_3",
                    "fourth_level_1",
                ]
            ),
        )

    def test_extract_cyclonedx_components(self) -> None:
        example_list: Sequence[dict] = [
            {
                "name": "first_level_1",
                "bom-ref": "first_level_1",
                "components": [
                    {
                        "name": "second_level_1",
                        "bom-ref": "second_level_1",
                    },
                    {
                        "name": "second_level_2",
                        "bom-ref": "second_level_2",
                        "components": [
                            {
                                "name": "third_level_1",
                                "bom-ref": "third_level_1",
                            },
                            {
                                "name": "third_level_2",
                                "bom-ref": "third_level_2",
                            },
                        ],
                    },
                ],
            },
            {
                "name": "first_level_2",
                "bom-ref": "first_level_2",
                "components": [
                    {
                        "name": "second_level_3",
                        "bom-ref": "second_level_3",
                        "components": [
                            {
                                "name": "third_level_3",
                                "bom-ref": "third_level_3",
                                "components": [
                                    {
                                        "name": "fourth_level_1",
                                        "bom-ref": "fourth_level_1",
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "name": "second_level_4",
                        "bom-ref": "second_level_4",
                    },
                ],
            },
            {
                "name": "first_level_3",
                "bom-ref": "first_level_3",
                "components": [
                    {
                        "name": "second_level_5",
                        "bom-ref": "second_level_5",
                    }
                ],
            },
        ]
        sbom_dict = {"components": example_list}
        sbom = sbF.deserialize(sbom_dict)
        components = sbF.extract_cyclonedx_components(sbom.components)
        bom_refs = []
        for component in components:
            bom_refs.append(component.bom_ref.value)
        self.assertEqual(
            set(bom_refs),
            set(
                [
                    "first_level_1",
                    "first_level_2",
                    "first_level_3",
                    "second_level_1",
                    "second_level_2",
                    "second_level_3",
                    "second_level_4",
                    "second_level_5",
                    "third_level_1",
                    "third_level_2",
                    "third_level_3",
                    "fourth_level_1",
                ]
            ),
        )

    def test_get_component_by_ref(self) -> None:
        sbom = load_sub_program()
        self.assertEqual(
            sbF.get_component_by_ref("not existing ref", sbom["components"]), {}
        )


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


class TestReplaceBomRefs(unittest.TestCase):
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
        component_list_copy = deepcopy(component_list)

        sbF.replace_ref_in_components(component_list, "...", new_reference)
        self.assertEqual(component_list, component_list_copy)

        sbF.replace_ref_in_components(
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
        dependencies_copy = deepcopy(dependencies)

        reference = "sp_second_component"
        new_reference = "new"

        sbF.replace_ref_in_dependencies(dependencies, "...", new_reference)
        self.assertEqual(dependencies, dependencies_copy)

        sbF.replace_ref_in_dependencies(dependencies, reference, new_reference)
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
        compositions_copy = deepcopy(compositions)
        reference = "sp_second_component"
        new_reference = "new"

        sbF.replace_ref_in_compositions(compositions, "...", new_reference)
        self.assertEqual(compositions, compositions_copy)

        compositions_copy[0]["assemblies"][1] = new_reference  # type:ignore
        compositions_copy[1]["assemblies"][2] = new_reference  # type:ignore
        compositions_copy[1]["assemblies"][3] = new_reference  # type:ignore

        sbF.replace_ref_in_compositions(compositions, reference, new_reference)
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
        sbF.replace_ref_in_vulnerabilities(vulnerabilities, reference, new_reference)
        self.assertEqual(vulnerabilities, vulnerabilities_replaced)

    def test_get_ref_components_mapping(self) -> None:
        components = [
            {"name": "comp 1", "version": "1.0.0", "bom-ref": "com-1"},
            {"name": "comp 3", "version": "1.0.0", "bom-ref": "com-2"},
            {"name": "comp 3", "version": "1.0.0", "bom-ref": "com-3"},
        ]
        ref_mapping = sbF.get_ref_components_mapping(components)
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

        sbom_1_copy = deepcopy(sbom_1)
        sbF.make_bom_refs_unique([sbom_1, sbom_2, sbom_3, sbom_4])

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
        sbF.make_bom_refs_unique([components_1, components_2])

        self.assertEqual(
            components_2["components"][0]["bom-ref"], "COORDINATES[comp 1@2.0.0]-3"
        )

    def test_unify_bom_refs(self) -> None:
        sbom_1 = load_sections_for_test_sbom()["sbom_unify_references_1"]
        sbom_2 = load_sections_for_test_sbom()["sbom_unify_references_2"]
        sbom_3 = deepcopy(sbom_1)
        sbom_3["vulnerabilities"] = deepcopy(sbom_2["vulnerabilities"])
        sbF.replace_ref_in_vulnerabilities(
            sbom_3["vulnerabilities"], "comp 3 -", "comp 3"
        )
        sbF.replace_ref_in_vulnerabilities(
            sbom_3["vulnerabilities"], "comp 2 -", "comp 2"
        )
        sbF.replace_ref_in_vulnerabilities(
            sbom_3["vulnerabilities"], "comp 1 -", "comp 1"
        )
        sbom_3["components"][2] = deepcopy(sbom_2["components"][2])
        sbom_3["components"][2]["bom-ref"] = "comp 3"

        sbom_3_expected = deepcopy(sbom_1)
        sbom_3_expected["components"][2] = deepcopy(sbom_2["components"][2])
        sbom_3_expected["vulnerabilities"] = deepcopy(sbom_2["vulnerabilities"])
        sbF.replace_ref_in_components(
            sbom_3_expected["components"], "comp 3", "comp 3 -"
        )
        sbF.replace_ref_in_compositions(
            sbom_3_expected["compositions"], "comp 3", "comp 3 -"
        )
        sbF.replace_ref_in_dependencies(
            sbom_3_expected["dependencies"], "comp 3", "comp 3 -"
        )

        sbF.replace_ref_in_vulnerabilities(
            sbom_3_expected["vulnerabilities"], "comp 1 -", "comp 1"
        )

        sbF.replace_ref_in_vulnerabilities(
            sbom_3_expected["vulnerabilities"], "comp 2 -", "comp 2"
        )

        sbom_2_expected = deepcopy(sbom_1)
        sbom_2_expected["vulnerabilities"] = deepcopy(
            sbom_3_expected["vulnerabilities"]
        )

        sbom_2_expected["components"][2] = deepcopy(sbom_2["components"][2])
        sbF.replace_ref_in_components(
            sbom_2_expected["components"], "comp 3", "comp 3 -"
        )
        sbF.replace_ref_in_compositions(
            sbom_2_expected["compositions"], "comp 3", "comp 3 -"
        )
        sbF.replace_ref_in_dependencies(
            sbom_2_expected["dependencies"], "comp 3", "comp 3 -"
        )
        sbF.replace_ref_in_vulnerabilities(
            sbom_2_expected["vulnerabilities"], "comp 3", "comp 3 -"
        )

        sbF.unify_bom_refs([sbom_1, sbom_2, sbom_3])

        self.assertEqual(sbom_1, sbom_1)
        self.assertEqual(sbom_2, sbom_2_expected)
        self.assertEqual(sbom_3, sbom_3_expected)


class TestVulnerabilities(unittest.TestCase):
    def test_compare_version_range(self) -> None:
        self.assertTrue(
            sbF.compare_version_range(
                "vers:tomee/>=1.0.0-beta1|<=1.7.5|>=7.0.0|<=7.0.7|>=7.1.0|<=7.1.2|>=8.0.0",
                "vers:tomee/>=1.0.0-beta1|<=1.7.5|>=7.0.0|<=7.0.7|>=7.1.0|<=7.1.2|>=8.0.0",
            )
        )

        self.assertFalse(
            sbF.compare_version_range(
                "vers:pypi/>=1.0.0-beta1|<=1.7.5|>=7.0.0|<=7.0.7|>=7.1.0|<=7.1.2|>=8.0.0",
                "vers:pypi/>=1.0.0-beta1|<=1.7.5|>=7.0.0|<=7.0.7|>=7.1.0|<=7.1.2",
            )
        )

        self.assertFalse(
            sbF.compare_version_range(
                "No v range",
                "1",
            )
        )

        self.assertTrue(
            sbF.compare_version_range(
                "vers:pypi/>=1.0.0-beta1|<=1.7.5|>=7.0.0|<=7.0.7|>=7.1.0|<=7.1.2|>=8.0.0",
                "vers:pypi/>=1.0.0-beta1|<=7.0.7|>=7.1.0|<=7.1.2|>=8.0.0|<=1.7.5|>=7.0.0",
            )
        )

    def test_version_is_in_version_range(self) -> None:
        self.assertTrue(sbF.version_is_in_version_range("8.0.0", "vers:cargo/<9.0.14"))
        self.assertFalse(
            sbF.version_is_in_version_range("10.0.0", "vers:cargo/<9.0.14")
        )

    def test_compare_affects_version_object(self) -> None:
        self.assertEqual(
            sbF.compare_affects_versions_object(
                {"range": "vers:cargo/>9.0.14"}, {"range": "vers:cargo/<9.0.14"}
            ),
            3,
        )
        self.assertEqual(
            sbF.compare_affects_versions_object(
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
            sbF.compare_affects_versions_object(
                {"version": "9.0.14", "range": "vers:cargo/<9.0.14"},
                {"version": "9.0.0", "range": "vers:cargo/<9.0.14"},
            ),
            0,
        )
        self.assertEqual(
            sbF.compare_affects_versions_object(
                {"version": "8.0.0", "range": "vers:cargo/<9.0.14"},
                {"version": "8.0.0", "range": "vers:cargo/>9.0.14"},
            ),
            1,
        )

        self.assertEqual(
            sbF.compare_affects_versions_object(
                {"range": "vers:cargo/<9.0.14"}, {"version": "8.0.0"}
            ),
            2,
        )

        self.assertEqual(
            sbF.compare_affects_versions_object(
                {"version": "8.0.0"}, {"range": "vers:cargo/<9.0.14"}
            ),
            -1,
        )

        self.assertEqual(
            sbF.compare_affects_versions_object(
                {"range": "vers:cargo/<9.0.14"},
                {"version": "8.0.0", "range": "vers:cargo/<9.0.14"},
            ),
            2,
        )

        self.assertEqual(
            sbF.compare_affects_versions_object(
                {"version": "8.0.0", "range": "vers:cargo/<9.0.14"},
                {"range": "vers:cargo/<9.0.14"},
            ),
            -1,
        )

    def test_get_new_affects_versions(self) -> None:
        lists = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_get_new_affects_versions"
        ]
        kept_versions = sbF.get_new_affects_versions(
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
        joined_lists = sbF.join_affect_versions_with_same_references(lists)

        self.assertEqual(joined_lists["product 2"], lists[2]["versions"])
        self.assertEqual(
            joined_lists["product 1"],
            lists[0]["versions"] + lists[1]["versions"] + lists[3]["versions"],
        )

    def test_extract_new_affects(self) -> None:
        lists = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "extract_new_affects"
        ]
        kept_affects = sbF.extract_new_affects(
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

        actual_merged = sbF.extract_new_affects(
            original_vulnerabilities[2]["affects"],
            original_vulnerabilities[2]["affects"],
            "vuln_id",
        )

        self.assertEqual(actual_merged, [])

    def test_get_identities_for_vulnerabilities(self) -> None:
        vulnerabilities = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "get_identities_for_vulnerabilities"
        ]
        identities = sbF.get_identities_for_vulnerabilities(vulnerabilities)
        self.assertEqual(len(identities.keys()), 3)
        self.assertEqual(
            identities[json.dumps(vulnerabilities[0], sort_keys=True)],
            identities[json.dumps(vulnerabilities[1], sort_keys=True)],
        )
        self.assertEqual(
            identities[json.dumps(vulnerabilities[2], sort_keys=True)].aliases,
            sbF.VulnerabilityIdentity.get_ids_from_vulnerability(vulnerabilities[2]),
        )

    def test_identities_for_vulnerabilities(self) -> None:
        vulnerabilities = load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_identities_for_vulnerabilities"
        ]
        identities = sbF.get_identities_for_vulnerabilities(vulnerabilities)
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
        identities = sbF.get_identities_for_vulnerabilities(lists)
        collected = sbF.collect_affects_of_vulnerabilities(lists, identities)

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


if __name__ == "__main__":
    unittest.main()
