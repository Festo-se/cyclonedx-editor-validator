# SPDX-License-Identifier: GPL-3.0-or-later

import json
import os
import unittest
from pathlib import Path

from cdxev import build_public_bom as b_p_b

path_to_sbom = (
    "tests/auxiliary/test_build_public_bom_sboms/"
    "Acme_Application_9.1.1_20220217T101458.cdx.json"
)

path_to_nested_comp_sbom = (
    "tests/auxiliary/test_build_public_bom_sboms/sbom_nested_components.json"
)


path_to_public_sbom = (
    "tests/auxiliary/test_build_public_bom_sboms/internal_removed_sbom.json"
)

path_to_public_sbom_nested = (
    "tests/auxiliary/test_build_public_bom_sboms/"
    "expected_sbom_deleted_nested_component.json"
)

path_to_docu_sbom_dic = (
    "tests/auxiliary/test_build_public_bom_sboms/"
    "sboms_for_documentation_examples.json"
)

path_to_public_docu_sbom_dic = (
    "tests/auxiliary/test_build_public_bom_sboms/"
    "public_sboms_for_documentation_examples.json"
)


relative_path_to_example_schema_1 = (
    "tests/auxiliary/test_build_public_bom_sboms/schema/example_schema_1.json"
)
path_to_example_schema_1 = Path(os.path.abspath(relative_path_to_example_schema_1))

relative_path_to_example_schema_2 = (
    "tests/auxiliary/test_build_public_bom_sboms/schema/example_schema_2.json"
)
path_to_example_schema_2 = Path(os.path.abspath(relative_path_to_example_schema_2))


relative_path_to_documentation_schema_1 = (
    "tests/auxiliary/test_build_public_bom_sboms/schema/documentation_schema_1.json"
)
path_to_documentation_schema_1 = Path(
    os.path.abspath(relative_path_to_documentation_schema_1)
)

relative_path_to_documentation_schema_2 = (
    "tests/auxiliary/test_build_public_bom_sboms/schema/documentation_schema_2.json"
)
path_to_documentation_schema_2 = Path(
    os.path.abspath(relative_path_to_documentation_schema_2)
)

relative_path_to_documentation_schema_3 = (
    "tests/auxiliary/test_build_public_bom_sboms/schema/documentation_schema_3.json"
)
path_to_documentation_schema_3 = Path(
    os.path.abspath(relative_path_to_documentation_schema_3)
)

relative_path_to_documentation_schema_4 = (
    "tests/auxiliary/test_build_public_bom_sboms/schema/documentation_schema_4.json"
)
path_to_documentation_schema_4 = Path(
    os.path.abspath(relative_path_to_documentation_schema_4)
)


def get_sbom(pathsbom: str) -> dict:
    with open(pathsbom, "r") as read_file:
        sbom = json.load(read_file)
    return sbom


def dumpsbom(sbom: dict, name: str = "watchsbom.json") -> None:
    with open(name, "w") as write_file:
        json.dump(sbom, write_file, indent=4)


class TestCreateInternalValidator(unittest.TestCase):
    def test_valid_schema(self) -> None:
        validator = b_p_b.create_internal_validator(path_to_example_schema_1)
        with path_to_example_schema_1.open() as schema_f:
            schema_internal = json.load(schema_f)
        self.assertTrue(validator.is_valid(schema_internal))


class TestMergeDependencyForRemovedComponent(unittest.TestCase):
    dependencies = [
        {"ref": "component 1", "dependsOn": ["Component 2", "Component 3"]},
        {"ref": "Component 2", "dependsOn": ["Component 3", "Component 4"]},
        {
            "ref": "component 3",
            "dependsOn": [
                "Component 4",
            ],
        },
    ]
    dependencies_without_component_2 = [
        {"ref": "component 1", "dependsOn": ["Component 3", "Component 4"]},
        {
            "ref": "component 3",
            "dependsOn": [
                "Component 4",
            ],
        },
    ]

    def test_resolve_dependencies(self) -> None:
        resolved_dependencies = b_p_b.merge_dependency_for_removed_component(
            "Component 2", self.dependencies
        )
        self.assertEqual(self.dependencies_without_component_2, resolved_dependencies)


class TestRemoveInternalInformationFromProperties(unittest.TestCase):
    component = {
        "properties": [
            {"name": "internal:component:status", "value": "public"},
            {"name": "something:component:status", "value": "public"},
        ]
    }
    component_cleared = {
        "properties": [{"name": "something:component:status", "value": "public"}]
    }

    def test_remove_several_component(self) -> None:
        b_p_b.remove_internal_information_from_properties(self.component)
        self.assertEqual(self.component, self.component_cleared)


class TestCreateExternalBom(unittest.TestCase):
    def test_build_public_group_is_internal(self) -> None:
        sbom = get_sbom(path_to_sbom)
        public_sbom = get_sbom(path_to_public_sbom)
        external_bom = b_p_b.build_public_bom(sbom, path_to_example_schema_1)
        self.assertDictEqual(public_sbom, external_bom)

    def test_build_public_group_is_internal_name_contained_is_public(self) -> None:
        sbom = get_sbom(path_to_sbom)
        public_sbom = get_sbom(path_to_sbom)
        public_sbom["metadata"]["component"]["properties"] = [
            {"name": "notinternal:stuff", "value": "something"}
        ]
        public_sbom["components"][1]["properties"] = [
            {"name": "the Other", "value": "something"},
            {"name": "not:internal:stuff", "value": "should be in"},
        ]
        public_sbom["components"][2]["properties"] = []
        public_sbom["components"][3]["properties"] = []
        public_sbom["components"][5]["properties"] = []
        public_sbom["components"][6]["properties"] = []
        external_bom = b_p_b.build_public_bom(sbom, path_to_example_schema_2)
        public_sbom.pop("compositions")
        external_bom.pop("compositions")
        self.assertDictEqual(public_sbom, external_bom)

    def test_build_public_from_documentation_1(self) -> None:
        sbom = get_sbom(path_to_docu_sbom_dic)["sbom_for_docu_schema_1_and_2"]
        public_sbom = get_sbom(path_to_public_docu_sbom_dic)["public_sbom_schema_1"]
        external_bom = b_p_b.build_public_bom(sbom, path_to_documentation_schema_1)
        self.assertDictEqual(external_bom, public_sbom)

    def test_build_public_from_documentation_2(self) -> None:
        sbom = get_sbom(path_to_docu_sbom_dic)["sbom_for_docu_schema_1_and_2"]
        public_sbom = get_sbom(path_to_public_docu_sbom_dic)["public_sbom_schema_2"]
        external_bom = b_p_b.build_public_bom(sbom, path_to_documentation_schema_2)
        self.assertDictEqual(external_bom, public_sbom)

    def test_build_public_from_documentation_3(self) -> None:
        sbom = get_sbom(path_to_docu_sbom_dic)["sbom_for_docu_schema_3"]
        public_sbom = get_sbom(path_to_public_docu_sbom_dic)["public_sbom_schema_3"]
        external_bom = b_p_b.build_public_bom(sbom, path_to_documentation_schema_3)
        self.assertDictEqual(external_bom, public_sbom)

    def test_build_public_from_documentation_4(self) -> None:
        sbom = get_sbom(path_to_docu_sbom_dic)["sbom_for_docu_schema_4"]
        public_sbom = get_sbom(path_to_public_docu_sbom_dic)["public_sbom_schema_4"]
        external_bom = b_p_b.build_public_bom(sbom, path_to_documentation_schema_4)
        self.assertDictEqual(external_bom, public_sbom)

    def test_build_public_no_schema(self) -> None:
        sbom = get_sbom(path_to_sbom)
        public_sbom = get_sbom(path_to_sbom)
        public_sbom["metadata"]["component"]["properties"].pop(1)
        public_sbom["components"][1]["properties"].pop(1)
        public_sbom["components"][1]["properties"].pop(2)
        public_sbom["components"][6]["properties"].pop(0)
        public_sbom["components"][3]["properties"].pop(0)
        public_sbom["components"][2]["properties"].pop(0)
        public_sbom["components"][5]["properties"].pop(0)
        external_bom = b_p_b.build_public_bom(sbom, None)

        public_sbom["compositions"] = [
            {
                "aggregate": "incomplete",
                "assemblies": [
                    "comp1",
                    "sub_comp1",
                    "comp2",
                    "comp3",
                    "comp4",
                    "internalcomp1",
                    "internalcomp2",
                    "internalcomp3",
                ],
            }
        ]
        self.assertDictEqual(external_bom, public_sbom)

    def test_deletion_of_orphaned_bom_refs(self) -> None:
        sbom = get_sbom(path_to_sbom)
        public_sbom = get_sbom(path_to_sbom)
        public_sbom["metadata"]["component"]["properties"].pop(1)
        public_sbom["components"][1]["properties"].pop(1)
        public_sbom["components"][1]["properties"].pop(2)
        public_sbom["components"][6]["properties"].pop(0)
        public_sbom["components"][3]["properties"].pop(0)
        public_sbom["components"][2]["properties"].pop(0)
        public_sbom["components"][5]["properties"].pop(0)
        sbom["compositions"][0]["assemblies"].append("orphaned bom-ref 1")
        sbom["compositions"][0]["assemblies"].append("orphaned bom-ref 2")
        external_bom = b_p_b.build_public_bom(sbom, None)
        public_sbom["compositions"] = [
            {
                "aggregate": "incomplete",
                "assemblies": [
                    "comp1",
                    "sub_comp1",
                    "comp2",
                    "comp3",
                    "comp4",
                    "internalcomp1",
                    "internalcomp2",
                    "internalcomp3",
                    "orphaned bom-ref 1",
                    "orphaned bom-ref 2",
                ],
            }
        ]
        self.assertDictEqual(external_bom, public_sbom)

    def test_build_public_delete_nested_components(self) -> None:
        sbom = get_sbom(path_to_sbom)
        sbom["components"][0]["group"] = "com.acme.internal"
        public_sbom = get_sbom(path_to_sbom)
        public_sbom["components"][0] = public_sbom["components"][0]["components"][0]
        public_sbom["compositions"][0]["assemblies"].pop(0)
        public_sbom["dependencies"][0]["dependsOn"].pop(0)
        public_sbom["dependencies"][0]["dependsOn"].append("sub_comp1")
        public_sbom["dependencies"][0]["dependsOn"].append("comp4")
        public_sbom["dependencies"].pop(1)
        public_sbom["metadata"]["component"]["properties"].pop(1)
        public_sbom["components"][1]["properties"].pop(1)
        public_sbom["components"][1]["properties"].pop(2)
        public_sbom["components"][2]["properties"].pop(0)
        public_sbom["components"][3]["properties"].pop(0)
        public_sbom["components"][5]["properties"].pop(0)
        public_sbom["components"][6]["properties"].pop(0)
        external_bom = b_p_b.build_public_bom(sbom, path_to_documentation_schema_1)
        self.assertDictEqual(external_bom, public_sbom)

    def test_build_public_clear_component_func(self) -> None:
        component = {
            "properties": [
                {"name": "internal:stuff", "value": "gone"},
                {"name": "stuff", "value": "not gone"},
            ],
            "components": [
                {
                    "properties": [{"name": "internal:stuff", "value": "gone"}],
                    "components": [
                        {"properties": [{"name": "internal:stuff", "value": "gone"}]}
                    ],
                }
            ],
        }
        expected_component = component
        expected_component["properties"].pop(1)
        expected_component["components"][0]["properties"].pop(0)
        expected_component["components"][0]["components"][0]["properties"].pop(0)
        component = b_p_b.clear_component(component)
        self.assertDictEqual(component, expected_component)
