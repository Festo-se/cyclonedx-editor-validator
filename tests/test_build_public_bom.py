# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import os
import unittest
from pathlib import Path

from cdxev import build_public_bom as b_p_b

path_to_sbom = (
    "tests/auxiliary/test_build_public_bom_sboms/"
    "Acme_Application_9.1.1_20220217T101458.cdx.json"
)

path_to_public_sbom = (
    "tests/auxiliary/test_build_public_bom_sboms/internal_removed_sbom.json"
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
        public_sbom["components"][2].pop("properties")
        public_sbom["components"][3].pop("properties")
        public_sbom["components"][5].pop("properties")
        public_sbom["components"][6].pop("properties")
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
        public_sbom["components"][2].pop("properties")
        public_sbom["components"][3].pop("properties")
        public_sbom["components"][5].pop("properties")
        public_sbom["components"][6].pop("properties")
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
        public_sbom["components"][2].pop("properties")
        public_sbom["components"][3].pop("properties")
        public_sbom["components"][5].pop("properties")
        public_sbom["components"][6].pop("properties")
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

    def test_no_component(self) -> None:
        component = {}
        expected_component = [{}]
        validator = b_p_b.create_internal_validator(path_to_documentation_schema_1)
        public_component = b_p_b.remove_component_tagged_internal(component, validator)
        self.assertEqual(expected_component, public_component[1])

    def test_no_nested_components(self) -> None:
        component = {"components": []}
        expected_component = [{}]
        validator = b_p_b.create_internal_validator(path_to_documentation_schema_1)
        public_component = b_p_b.remove_component_tagged_internal(component, validator)
        self.assertEqual(expected_component, public_component[1])

    def test_no_public_components(self) -> None:
        component = {
            "group": "com.acme.internal",
            "components": [{"group": "com.acme.internal"}],
        }
        expected_component = []
        validator = b_p_b.create_internal_validator(path_to_documentation_schema_1)
        public_component = b_p_b.remove_component_tagged_internal(component, validator)
        self.assertEqual(expected_component, public_component[1])

    def test_rearange_nested_component(self) -> None:
        sbom = get_sbom(path_to_sbom)
        component = sbom["components"][0]
        component["group"] = "com.acme.internal"
        expected_component = [component["components"][0]]
        validator = b_p_b.create_internal_validator(path_to_documentation_schema_1)
        public_component = b_p_b.remove_component_tagged_internal(component, validator)
        self.assertEqual(expected_component, public_component[1])

    def test_rearange_multiple_nested_components(self) -> None:
        sbom = get_sbom(path_to_sbom)
        component = sbom["components"][0]
        component["group"] = "com.acme.internal"
        component["components"].append(component["components"][0])
        component["components"][1]["bom-ref"] = "sub_comp2"
        expected_component = [component["components"][0], component["components"][1]]
        validator = b_p_b.create_internal_validator(path_to_documentation_schema_1)
        public_component = b_p_b.remove_component_tagged_internal(component, validator)
        self.assertEqual(expected_component, public_component[1])

    def test_delete_nested_components(self) -> None:
        sbom = get_sbom(path_to_sbom)
        component = sbom["components"][0]
        component["components"][0]["components"] = [
            {"bom-ref": "sub_sub_com1", "group": "com.acme.internal"},
            {"bom-ref": "sub_sub_com2", "group": "com.acme.public"},
        ]
        expected_component = [copy.deepcopy(component)]
        expected_component[0]["components"][0]["components"].pop(0)
        validator = b_p_b.create_internal_validator(path_to_documentation_schema_1)
        public_component = b_p_b.remove_component_tagged_internal(component, validator)
        self.assertEqual(expected_component, public_component[1])

    def test_delete_last_nested_components(self) -> None:
        sbom = get_sbom(path_to_sbom)
        component = sbom["components"][0]
        expected_component = [copy.deepcopy(component)]
        component["components"][0]["components"] = [
            {"bom-ref": "sub_sub_com1", "group": "com.acme.internal"}
        ]
        validator = b_p_b.create_internal_validator(path_to_documentation_schema_1)
        public_component = b_p_b.remove_component_tagged_internal(component, validator)
        self.assertEqual(expected_component, public_component[1])

    def test_delete_internal_properties(self) -> None:
        component = {
            "name": "test",
            "properties": [
                {"name": "internal:stuff", "value": "should be gone"},
                {"name": "stuff", "value": "still there"},
            ],
        }
        b_p_b.remove_internal_information_from_properties(component)
        expected = {
            "name": "test",
            "properties": [{"name": "stuff", "value": "still there"}],
        }
        self.assertEqual(component, expected)

    def test_not_delete_internal_properties(self) -> None:
        component = {
            "name": "test",
            "properties": [
                {"name": "stuff:internal", "value": "still there"},
                {"name": "stuff", "value": "still there"},
            ],
        }
        expected = copy.deepcopy(component)
        b_p_b.remove_internal_information_from_properties(component)
        self.assertEqual(component, expected)

    def test_empty_properties(self) -> None:
        component = {"name": "test", "properties": []}
        expected = {"name": "test"}
        b_p_b.remove_internal_information_from_properties(component)
        self.assertEqual(component, expected)

    def test_no_properties_key(self) -> None:
        component = {"name": "test"}
        expected = copy.deepcopy(component)
        b_p_b.remove_internal_information_from_properties(component)
        self.assertEqual(component, expected)

    def test_only_internal_properties(self) -> None:
        component = {
            "name": "test",
            "properties": [{"name": "internal:stuff", "value": "gone"}],
        }
        expected = {"name": "test"}
        b_p_b.remove_internal_information_from_properties(component)
        self.assertEqual(component, expected)

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
        b_p_b.clear_component(component)
        self.assertDictEqual(component, expected_component)

    def test_build_public_metadata_warning(self) -> None:
        sbom = get_sbom(path_to_sbom)
        metadata = sbom.get("metadata", [])
        metadata["component"]["group"] = "com.acme.internal"
        with self.assertLogs() as log:
            b_p_b.build_public_bom(sbom, path_to_documentation_schema_1)
        expected_message = "metadata.component not removed"
        self.assertTrue(expected_message, log.output)

    def test_build_public_no_metadata_(self) -> None:
        sbom = {"components": [{"bom-ref": "comp1", "group": "com.acme.internal"}]}
        expected = {}
        public_sbom = b_p_b.build_public_bom(sbom, path_to_documentation_schema_1)
        self.assertEqual(expected, public_sbom)

    def test_build_public_no_components(self) -> None:
        sbom = {"components": []}
        expected = {}
        public_sbom = b_p_b.build_public_bom(sbom, path_to_documentation_schema_1)
        self.assertEqual(expected, public_sbom)

    def test_remove_external_references(self) -> None:
        regex_pattern = r"https://internal\.acme\.com/.*"
        component = {
            "externalReferences": [
                {"type": "url", "url": "https://internal.acme.com/some_internal_url"},
                {"type": "url", "url": "https://external.acme.com/some_external_url"},
                {"type": "url", "url": "https://another.acme.com/some_other_url"},
            ]
        }
        expected = {
            "externalReferences": [
                {"type": "url", "url": "https://external.acme.com/some_external_url"},
                {"type": "url", "url": "https://another.acme.com/some_other_url"},
            ]
        }
        b_p_b.validate_external_references(regex_pattern, component)
        self.assertEqual(expected, component)

    def test_no_external_references(self) -> None:
        regex_pattern = ""
        component = {"bom-ref": "comp1"}
        expected = {"bom-ref": "comp1"}
        b_p_b.validate_external_references(regex_pattern, component)
        self.assertEqual(expected, component)

    def test_empty_external_references(self) -> None:
        regex_pattern = ""
        component = {"bom-ref": "comp1", "externalReferences": []}
        expected = {"bom-ref": "comp1"}
        b_p_b.validate_external_references(regex_pattern, component)
        self.assertEqual(expected, component)

    def test_no_pattern_external_references(self) -> None:
        regex_pattern = None
        component = {"bom-ref": "comp1", "externalReferences": []}
        expected = {"bom-ref": "comp1"}
        b_p_b.validate_external_references(regex_pattern, component)
        self.assertEqual(expected, component)
