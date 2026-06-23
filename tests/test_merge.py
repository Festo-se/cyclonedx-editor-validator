# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import unittest
from itertools import chain, combinations
from pathlib import Path
from unittest.mock import patch

from cdxev import merge
from cdxev.auxiliary.identity import ComponentIdentity, VulnerabilityIdentity
from cdxev.auxiliary.sbom_functions import add_merged_metadata_component_to_dependencies
from cdxev.validator.validate import validate_sbom
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
    def _load_reference_sbom(self, spec_version: str) -> dict:
        with open(
            "tests/auxiliary/test_validate_sboms/"
            "Acme_Application_9.1.1_ec7781220ec7781220ec778122012345_20220217T101458.cdx.json",
            "r",
            encoding="utf_8_sig",
        ) as f:
            sbom = json.load(f)
        sbom["specVersion"] = spec_version
        return sbom

    def test_no_vulnerabilities(self) -> None:
        sbom1 = helper.load_governing_program()
        sbom2 = helper.load_sub_program()
        sbom_merged = helper.load_governing_program_merged_sub_program()
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_merge_sbom_with_itself_vulnerabilities(self) -> None:
        sbom1 = helper.load_governing_program()
        sbom2 = helper.load_governing_program()
        sbom_merged = helper.load_governing_program()
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_merge_sbom_with_duplicate_component(self) -> None:
        sbom1 = helper.load_governing_program()
        sbom2 = helper.load_sub_program()
        sbom2["components"].append(sbom2["components"][0])
        sbom2["components"].append(sbom2["components"][1])
        sbom_merged = helper.load_governing_program_merged_sub_program()
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_vulnerabilities_in_the_second(self) -> None:
        sbom1 = helper.load_governing_program()
        sbom2 = helper.load_sub_program()
        vulnerabilities = helper.load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]
        original_vulnerabilities = vulnerabilities["original_vulnerabilities"]

        sbom2["vulnerabilities"] = original_vulnerabilities
        sbom_merged = helper.load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = original_vulnerabilities
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_vulnerabilities_in_the_first(self) -> None:
        sbom1 = helper.load_governing_program()
        vulnerabilities = helper.load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]
        original_vulnerabilities = vulnerabilities["original_vulnerabilities"]

        sbom1["vulnerabilities"] = original_vulnerabilities
        sbom2 = helper.load_sub_program()
        sbom_merged = helper.load_governing_program_merged_sub_program()
        sbom_merged["vulnerabilities"] = original_vulnerabilities
        self.assertTrue(helper.compare_sboms(merge.merge([sbom1, sbom2]), sbom_merged))

    def test_merge_sboms_same_sbom(self) -> None:
        vulnerabilities = helper.load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]
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
        self.assertTrue(helper.compare_sboms(merge.merge([sbom_merged, sbom_merged]), sbom_merged))

    def test_no_composition_in_sboms(self) -> None:
        sbom1 = helper.load_governing_program()
        sbom2 = helper.load_sub_program()
        sbom1.pop("compositions")
        sbom2.pop("compositions")
        sbom_merged = helper.load_governing_program_merged_sub_program()
        merged_sbom = merge.merge([sbom1, sbom2])
        sbom_merged.pop("compositions")
        self.assertTrue(helper.compare_sboms(merged_sbom, sbom_merged))

    def test_merge_metadata_component_is_independent_of_components_key(self) -> None:
        sbom_1 = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "bom-ref": "app",
                    "type": "application",
                    "name": "Acme Application",
                    "version": "1.0.0",
                }
            },
        }

        sbom_2 = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "bom-ref": "second",
                    "type": "application",
                    "name": "Second app",
                    "version": "1.0.0",
                }
            },
        }

        expected = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "bom-ref": "app",
                    "type": "application",
                    "name": "Acme Application",
                    "version": "1.0.0",
                }
            },
            "components": [
                {
                    "bom-ref": "second",
                    "type": "application",
                    "name": "Second app",
                    "version": "1.0.0",
                }
            ],
            "dependencies": [{"ref": "app", "dependsOn": ["second"]}],
        }

        self.assertEqual(merge.merge([copy.deepcopy(sbom_1), copy.deepcopy(sbom_2)]), expected)

        sbom_2_with_empty_components = copy.deepcopy(sbom_2)
        sbom_2_with_empty_components["components"] = []
        self.assertEqual(
            merge.merge([copy.deepcopy(sbom_1), sbom_2_with_empty_components]),
            expected,
        )

    def test_merge_metadata_component_updates_dependencies(self) -> None:
        sbom_1 = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "bom-ref": "app",
                    "type": "application",
                    "name": "Acme Application",
                    "version": "1.0.0",
                }
            },
            "dependencies": [{"ref": "app", "dependsOn": ["existing"]}],
        }

        sbom_2 = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "bom-ref": "second",
                    "type": "application",
                    "name": "Second app",
                    "version": "1.0.0",
                }
            },
        }

        merged = merge.merge([copy.deepcopy(sbom_1), copy.deepcopy(sbom_2)])
        self.assertEqual(
            merged["dependencies"],
            [{"ref": "app", "dependsOn": ["existing", "second"]}],
        )

    def test_merge_metadata_component_without_bom_ref_does_not_update_dependencies(self) -> None:
        merged_sbom = {
            "metadata": {"component": {"bom-ref": "app"}},
            "dependencies": [{"ref": "app", "dependsOn": ["existing"]}],
        }
        added_sbom_without_bom_ref = {
            "metadata": {"component": {"name": "Second app", "version": "1.0.0"}}
        }

        add_merged_metadata_component_to_dependencies(merged_sbom, added_sbom_without_bom_ref)

        self.assertEqual(
            merged_sbom["dependencies"],
            [{"ref": "app", "dependsOn": ["existing"]}],
        )


class TestMergeTools(unittest.TestCase):
    def _load_reference_sbom(self, spec_version: str) -> dict:
        with open(
            "tests/auxiliary/test_validate_sboms/"
            "Acme_Application_9.1.1_ec7781220ec7781220ec778122012345_20220217T101458.cdx.json",
            "r",
            encoding="utf_8_sig",
        ) as f:
            sbom = json.load(f)
        sbom["specVersion"] = spec_version
        return sbom

    def _assert_sbom_valid_for_spec(self, sbom: dict) -> None:
        with patch("cdxev.validator.validate.logger"):
            errors = validate_sbom(
                sbom=sbom,
                input_format="json",
                file=Path("bom.json"),
                report_format="stdout",
                report_path=Path("."),
                schema_type="custom",
                filename_regex=".*",
                schema_path=None,
            )
        self.assertEqual(errors, 0)

    def test_merge_tools_old_into_new_with_schema_validation(self) -> None:
        original_sbom = self._load_reference_sbom("1.7")
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.3")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = [
            {"name": "legacy-tool", "vendor": "acme", "version": "1.0.0"}
        ]

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )
        tools = merged["metadata"]["tools"]

        self.assertIsInstance(tools, dict)
        self.assertIn("components", tools)
        self.assertEqual(tools["components"][0]["name"], "legacy-tool")
        self.assertEqual(tools["components"][0]["publisher"], "acme")
        self.assertEqual(tools["components"][0]["version"], "1.0.0")
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_new_into_old_with_schema_validation(self) -> None:
        original_sbom = self._load_reference_sbom("1.3")
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "modern-tool",
                    "publisher": "acme",
                    "version": "2.0.0",
                }
            ],
            "services": [
                {
                    "name": "scanner-service",
                    "organization": "acme",
                }
            ],
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )
        tools = merged["metadata"]["tools"]

        self.assertIsInstance(tools, list)
        self.assertTrue(any(tool.get("name") == "modern-tool" for tool in tools))
        self.assertTrue(any(tool.get("name") == "scanner-service" for tool in tools))
        self.assertTrue(any(tool.get("vendor") == "acme" for tool in tools))
        self.assertTrue(any(tool.get("version") == "2.0.0" for tool in tools))
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_new_into_new_with_components_and_services(self) -> None:
        original_sbom = self._load_reference_sbom("1.7")
        original_sbom.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "governing-tool",
                    "publisher": "acme",
                    "version": "3.0.0",
                }
            ],
            "services": [
                {
                    "name": "governing-service",
                    "provider": {"name": "acme"},
                }
            ],
        }

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "sub-tool",
                    "publisher": "contoso",
                    "version": "1.1.0",
                }
            ],
            "services": [
                {
                    "name": "sub-service",
                    "provider": {"name": "contoso"},
                }
            ],
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )
        tools = merged["metadata"]["tools"]

        self.assertIsInstance(tools, dict)
        self.assertIn("components", tools)
        self.assertIn("services", tools)
        self.assertTrue(any(tool.get("name") == "governing-tool" for tool in tools["components"]))
        self.assertTrue(any(tool.get("name") == "sub-tool" for tool in tools["components"]))
        self.assertTrue(any(tool.get("name") == "governing-service" for tool in tools["services"]))
        self.assertTrue(any(tool.get("name") == "sub-service" for tool in tools["services"]))
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_new_into_new_keeps_services_with_different_endpoints(self) -> None:
        original_sbom = self._load_reference_sbom("1.7")
        original_sbom.setdefault("metadata", {})["tools"] = {
            "services": [
                {
                    "name": "scanner-service",
                    "provider": {"name": "acme"},
                    "endpoints": ["https://acme.example/api"],
                }
            ]
        }

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "services": [
                {
                    "name": "scanner-service",
                    "provider": {"name": "acme"},
                    "endpoints": ["https://contoso.example/api"],
                }
            ]
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        services = merged["metadata"]["tools"].get("services", [])
        self.assertEqual(len(services), 2)
        self.assertNotEqual(services[0]["endpoints"], services[1]["endpoints"])
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_new_into_new_keeps_components_with_different_description(self) -> None:
        original_sbom = self._load_reference_sbom("1.7")
        original_sbom.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "modern-tool",
                    "publisher": "acme",
                    "version": "2.0.0",
                }
            ]
        }

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "modern-tool",
                    "publisher": "acme",
                    "version": "2.0.0",
                    "description": "same identity, extra metadata",
                }
            ]
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        components = merged["metadata"]["tools"].get("components", [])
        self.assertEqual(len(components), 2)
        self.assertTrue(any(component.get("description") for component in components))
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_new_into_new_collapses_identical_components(self) -> None:
        original_sbom = self._load_reference_sbom("1.7")
        original_sbom.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "modern-tool",
                    "publisher": "acme",
                    "version": "2.0.0",
                }
            ]
        }

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "modern-tool",
                    "publisher": "acme",
                    "version": "2.0.0",
                }
            ]
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        components = merged["metadata"]["tools"].get("components", [])
        self.assertEqual(len(components), 1)
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_old_into_old_with_schema_validation(self) -> None:
        original_sbom = self._load_reference_sbom("1.3")
        original_sbom.setdefault("metadata", {})["tools"] = [
            {"name": "governing-legacy-tool", "vendor": "acme", "version": "1.0.0"}
        ]

        sbom_to_be_merged = self._load_reference_sbom("1.3")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = [
            {"name": "sub-legacy-tool", "vendor": "contoso", "version": "2.0.0"}
        ]

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )
        tools = merged["metadata"]["tools"]

        self.assertIsInstance(tools, list)
        self.assertTrue(any(tool.get("name") == "governing-legacy-tool" for tool in tools))
        self.assertTrue(any(tool.get("name") == "sub-legacy-tool" for tool in tools))
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_old_into_old_keeps_near_duplicate_tool_with_extra_metadata(self) -> None:
        original_sbom = self._load_reference_sbom("1.3")
        original_sbom.setdefault("metadata", {})["tools"] = [
            {
                "name": "legacy-tool",
                "vendor": "acme",
                "version": "1.0.0",
                "hashes": [{"alg": "MD5", "content": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
            }
        ]

        sbom_to_be_merged = self._load_reference_sbom("1.3")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = [
            {
                "name": "legacy-tool",
                "vendor": "acme",
                "version": "1.0.0",
                "hashes": [{"alg": "MD5", "content": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],
            }
        ]

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        tools = merged["metadata"]["tools"]
        self.assertEqual(len(tools), 2)
        self.assertNotEqual(tools[0]["hashes"], tools[1]["hashes"])
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_array_to_dict_does_not_insert_empty_version(self) -> None:
        original_sbom = self._load_reference_sbom("1.7")
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.3")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = [{"name": "legacy-tool"}]

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        tool = merged["metadata"]["tools"]["components"][0]
        self.assertEqual(tool["name"], "legacy-tool")
        self.assertNotIn("version", tool)
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_new_into_old_logs_lossy_service_downgrade(self) -> None:
        original_sbom = self._load_reference_sbom("1.3")
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "services": [{"name": "scanner-service", "organization": "acme"}]
        }

        with patch("cdxev.merge.logger") as logger_mock:
            merged = merge.merge_2_sboms(
                copy.deepcopy(original_sbom),
                copy.deepcopy(sbom_to_be_merged),
            )

        self.assertIsInstance(merged["metadata"]["tools"], list)
        self.assertTrue(logger_mock.warning.called)
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_new_into_old_maps_provider_name_to_vendor(self) -> None:
        original_sbom = self._load_reference_sbom("1.3")
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "services": [{"name": "scanner-service", "provider": {"name": "acme"}}]
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        tools = merged["metadata"]["tools"]
        self.assertIsInstance(tools, list)
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0]["name"], "scanner-service")
        self.assertEqual(tools[0]["vendor"], "acme")
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_new_into_old_warns_on_provider_detail_loss(self) -> None:
        original_sbom = self._load_reference_sbom("1.3")
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "services": [
                {
                    "name": "scanner-service",
                    "provider": {
                        "name": "acme",
                        "url": "https://acme.example/provider",
                    },
                }
            ]
        }

        with patch("cdxev.merge.logger") as logger_mock:
            merged = merge.merge_2_sboms(
                copy.deepcopy(original_sbom),
                copy.deepcopy(sbom_to_be_merged),
            )

        self.assertEqual(merged["metadata"]["tools"][0].get("vendor"), "acme")
        self.assertTrue(logger_mock.warning.called)
        self.assertTrue(
            any(
                "provider" in str(call.args[0]).lower() and "drops" in str(call.args[0]).lower()
                for call in logger_mock.warning.call_args_list
            )
        )
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_new_into_old_logs_component_type_loss(self) -> None:
        original_sbom = self._load_reference_sbom("1.3")
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "framework",
                    "name": "modern-tool",
                    "publisher": "acme",
                    "version": "2.0.0",
                }
            ]
        }

        with patch("cdxev.merge.logger") as logger_mock:
            merged = merge.merge_2_sboms(
                copy.deepcopy(original_sbom),
                copy.deepcopy(sbom_to_be_merged),
            )

        self.assertFalse(any("type" in tool for tool in merged["metadata"]["tools"]))
        self.assertTrue(logger_mock.warning.called)
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_new_into_old_warns_on_component_metadata_loss(self) -> None:
        original_sbom = self._load_reference_sbom("1.4")
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "modern-tool",
                    "publisher": "acme",
                    "description": "tool description",
                    "externalReferences": [
                        {
                            "type": "website",
                            "url": "https://example.com/tool",
                        }
                    ],
                }
            ]
        }

        with patch("cdxev.merge.logger") as logger_mock:
            merged = merge.merge_2_sboms(
                copy.deepcopy(original_sbom),
                copy.deepcopy(sbom_to_be_merged),
            )

        self.assertEqual(merged["metadata"]["tools"][0]["name"], "modern-tool")
        self.assertNotIn("description", merged["metadata"]["tools"][0])
        self.assertIn("externalReferences", merged["metadata"]["tools"][0])
        self.assertTrue(logger_mock.warning.called)
        self.assertTrue(
            any(
                "drops component metadata fields" in str(call.args[0]).lower()
                and "description" in str(call.args[0]).lower()
                for call in logger_mock.warning.call_args_list
            )
        )
        self.assertFalse(
            any(
                "drops component metadata fields" in str(call.args[0]).lower()
                and "externalreferences" in str(call.args[0]).lower()
                for call in logger_mock.warning.call_args_list
            )
        )
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_1_6_governing_legacy_array_upgrades_to_object_format(self) -> None:
        original_sbom = self._load_reference_sbom("1.6")
        original_sbom.setdefault("metadata", {})["tools"] = [
            {"name": "governing-legacy-tool", "vendor": "acme", "version": "1.0.0"}
        ]

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "incoming-modern-tool",
                    "publisher": "contoso",
                    "version": "2.0.0",
                }
            ],
            "services": [{"name": "incoming-service", "provider": {"name": "contoso"}}],
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        tools = merged["metadata"]["tools"]
        self.assertIsInstance(tools, dict)
        self.assertIn("components", tools)
        self.assertIn("services", tools)
        self.assertTrue(
            any(
                component.get("name") == "governing-legacy-tool"
                for component in tools["components"]
            )
        )
        self.assertTrue(
            any(
                component.get("name") == "incoming-modern-tool"
                for component in tools["components"]
            )
        )
        self.assertTrue(
            any(service.get("name") == "incoming-service" for service in tools["services"])
        )
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_1_4_governing_array_with_incoming_object_stays_array(self) -> None:
        original_sbom = self._load_reference_sbom("1.4")
        original_sbom.setdefault("metadata", {})["tools"] = [
            {"name": "governing-legacy-tool", "vendor": "acme", "version": "1.0.0"}
        ]

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "incoming-modern-tool",
                    "publisher": "contoso",
                    "version": "2.0.0",
                }
            ]
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        tools = merged["metadata"]["tools"]
        self.assertIsInstance(tools, list)
        self.assertTrue(any(tool.get("name") == "governing-legacy-tool" for tool in tools))
        self.assertTrue(any(tool.get("name") == "incoming-modern-tool" for tool in tools))
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_new_into_old_preserves_external_references(self) -> None:
        original_sbom = self._load_reference_sbom("1.4")
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "modern-tool",
                    "publisher": "acme",
                    "externalReferences": [
                        {
                            "type": "website",
                            "url": "https://example.com/tool",
                        }
                    ],
                }
            ]
        }

        with patch("cdxev.merge.logger") as logger_mock:
            merged = merge.merge_2_sboms(
                copy.deepcopy(original_sbom),
                copy.deepcopy(sbom_to_be_merged),
            )

        tools = merged["metadata"]["tools"]
        self.assertIsInstance(tools, list)
        self.assertEqual(tools[0]["name"], "modern-tool")
        self.assertIn("externalReferences", tools[0])
        self.assertFalse(
            any(
                "drops component metadata fields" in str(call.args[0]).lower()
                and "externalreferences" in str(call.args[0]).lower()
                for call in logger_mock.warning.call_args_list
            )
        )
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_nameless_legacy_tool_is_skipped_when_target_is_1_6(self) -> None:
        original_sbom = self._load_reference_sbom("1.6")
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.3")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = [
            {"vendor": "acme", "version": "1.0.0"},
            {"name": "kept-tool", "vendor": "acme", "version": "2.0.0"},
        ]

        with patch("cdxev.merge.logger") as logger_mock:
            merged = merge.merge_2_sboms(
                copy.deepcopy(original_sbom),
                copy.deepcopy(sbom_to_be_merged),
            )

        components = merged["metadata"]["tools"].get("components", [])
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["name"], "kept-tool")
        self.assertTrue(
            any(
                "without a usable name" in str(call.args[0]).lower()
                for call in logger_mock.warning.call_args_list
            )
        )
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_new_into_old_outputs_only_legacy_tool_keys(self) -> None:
        original_sbom = self._load_reference_sbom("1.4")
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "framework",
                    "name": "modern-tool",
                    "publisher": "acme",
                    "version": "2.0.0",
                    "hashes": [{"alg": "MD5", "content": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
                    "externalReferences": [
                        {
                            "type": "website",
                            "url": "https://example.com/tool",
                        }
                    ],
                    "description": "tool description",
                    "bom-ref": "tool-ref",
                }
            ]
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        tool = merged["metadata"]["tools"][0]
        allowed_legacy_keys = {"name", "vendor", "version", "hashes", "externalReferences"}
        self.assertTrue(set(tool).issubset(allowed_legacy_keys))
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_1_7_duplicate_bom_ref_is_renamed_to_unique(self) -> None:
        original_sbom = self._load_reference_sbom("1.7")
        original_sbom.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "governing-tool",
                    "publisher": "acme",
                    "version": "1.0.0",
                    "bom-ref": "tool-ref",
                }
            ]
        }

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "incoming-tool",
                    "publisher": "contoso",
                    "version": "1.0.0",
                    "bom-ref": "tool-ref",
                }
            ]
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        components = merged["metadata"]["tools"].get("components", [])
        self.assertEqual(len(components), 2)
        refs = [component.get("bom-ref") for component in components]
        self.assertEqual(len(set(refs)), 2)
        self.assertTrue(any(ref == "tool-ref" for ref in refs))
        self.assertTrue(any(ref and ref.startswith("tool-ref-tool-") for ref in refs))
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_dict_dedup_keeps_distinct_services(self) -> None:
        original_sbom = self._load_reference_sbom("1.7")
        original_sbom.setdefault("metadata", {})["tools"] = {
            "services": [
                {
                    "name": "scanner-service",
                    "provider": {"name": "acme"},
                }
            ]
        }

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "services": [
                {
                    "name": "scanner-service",
                    "provider": {"name": "contoso"},
                }
            ]
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        services = merged["metadata"]["tools"].get("services", [])
        self.assertEqual(len(services), 2)

    def test_merge_tools_dict_dedup_keeps_services_with_provider_variant_metadata(self) -> None:
        original_sbom = self._load_reference_sbom("1.7")
        original_sbom.setdefault("metadata", {})["tools"] = {
            "services": [
                {
                    "name": "scanner-service",
                    "provider": {
                        "name": "acme",
                    },
                }
            ]
        }

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "services": [
                {
                    "name": "scanner-service",
                    "provider": {
                        "name": "acme",
                        "url": "https://acme.example/provider",
                    },
                }
            ]
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        services = merged["metadata"]["tools"].get("services", [])
        self.assertEqual(len(services), 2)

    def test_merge_tools_old_into_old_keeps_near_duplicate_with_extra_metadata(self) -> None:
        original_sbom = self._load_reference_sbom("1.3")
        original_sbom.setdefault("metadata", {})["tools"] = [
            {
                "name": "legacy-tool",
                "vendor": "acme",
                "version": "1.0.0",
                "hashes": [{"alg": "MD5", "content": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
            }
        ]

        sbom_to_be_merged = self._load_reference_sbom("1.3")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = [
            {
                "name": "legacy-tool",
                "vendor": "acme",
                "version": "1.0.0",
                "hashes": [{"alg": "MD5", "content": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],
            }
        ]

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        tools = merged["metadata"]["tools"]
        self.assertEqual(len(tools), 2)
        self.assertNotEqual(tools[0]["hashes"], tools[1]["hashes"])
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_new_into_new_keeps_near_duplicate_component_with_extra_metadata(
        self,
    ) -> None:
        original_sbom = self._load_reference_sbom("1.7")
        original_sbom.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "modern-tool",
                    "publisher": "acme",
                    "version": "2.0.0",
                }
            ]
        }

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "modern-tool",
                    "publisher": "acme",
                    "version": "2.0.0",
                    "description": "same identity, extra metadata",
                }
            ]
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        components = merged["metadata"]["tools"].get("components", [])
        self.assertEqual(len(components), 2)
        self.assertTrue(any(component.get("description") for component in components))
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_old_into_new_dedup_handles_type_default(self) -> None:
        governing_tools = {
            "components": [
                {
                    "name": "legacy-tool",
                    "publisher": "acme",
                    "version": "1.0.0",
                }
            ]
        }
        tools_to_be_merged = [
            {
                "name": "legacy-tool",
                "vendor": "acme",
                "version": "1.0.0",
            }
        ]

        merged_tools = merge.merge_tools(governing_tools, tools_to_be_merged)

        self.assertIsInstance(merged_tools, dict)
        components = merged_tools.get("components", [])
        self.assertEqual(len(components), 1)

    def test_merge_tools_new_into_old_without_governing_tools_uses_old_format(self) -> None:
        original_sbom = self._load_reference_sbom("1.3")
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "modern-tool",
                    "publisher": "acme",
                    "version": "2.0.0",
                }
            ]
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        tools = merged["metadata"]["tools"]
        self.assertIsInstance(tools, list)
        self.assertTrue(any(tool.get("name") == "modern-tool" for tool in tools))
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_new_into_new_without_governing_tools_uses_dict_format(self) -> None:
        original_sbom = self._load_reference_sbom("1.6")
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "modern-tool",
                    "publisher": "acme",
                    "version": "2.0.0",
                }
            ]
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        tools = merged["metadata"]["tools"]
        self.assertIsInstance(tools, dict)
        self.assertIn("components", tools)
        self.assertEqual(tools["components"][0]["name"], "modern-tool")
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_absent_in_both_sboms_keeps_tools_absent(self) -> None:
        original_sbom = self._load_reference_sbom("1.6")
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {}).pop("tools", None)

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        self.assertIsNone(merge.merge_tools(None, None))
        self.assertNotIn("tools", merged["metadata"])
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_malformed_spec_version_warns_and_defaults_to_array(self) -> None:
        original_sbom = self._load_reference_sbom("1.6")
        # Simulate a malformed specVersion that will fail to parse
        original_sbom["specVersion"] = "1.x"
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [{"type": "application", "name": "tool", "publisher": "acme"}]
        }

        # Capture logger warnings
        with patch("cdxev.merge.logger") as logger_mock:
            merged = merge.merge_2_sboms(
                copy.deepcopy(original_sbom),
                copy.deepcopy(sbom_to_be_merged),
            )

        # Should default to array format (pre-1.5) and log a warning
        tools = merged["metadata"]["tools"]
        self.assertIsInstance(
            tools, list, "When specVersion parse fails, tools should default to array format"
        )
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0]["name"], "tool")
        # Verify warning was logged for the parse failure
        self.assertTrue(
            logger_mock.warning.called, "Expected warning to be logged for malformed specVersion"
        )

    def test_merge_tools_missing_spec_version_warns_and_defaults_to_array(self) -> None:
        original_sbom = self._load_reference_sbom("1.6")
        # Remove specVersion entirely
        original_sbom.pop("specVersion", None)
        original_sbom.setdefault("metadata", {}).pop("tools", None)

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [{"type": "application", "name": "tool-2", "publisher": "acme"}]
        }

        with patch("cdxev.merge.logger") as logger_mock:
            merged = merge.merge_2_sboms(
                copy.deepcopy(original_sbom),
                copy.deepcopy(sbom_to_be_merged),
            )

        # Should default to array format (pre-1.5) and log a warning
        tools = merged["metadata"]["tools"]
        self.assertIsInstance(
            tools, list, "When specVersion is missing, tools should default to array format"
        )
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0]["name"], "tool-2")
        self.assertTrue(
            logger_mock.warning.called, "Expected warning to be logged for missing specVersion"
        )

    def test_merge_tools_collapses_components_with_normalized_identity_fields(self) -> None:
        original_sbom = self._load_reference_sbom("1.7")
        original_sbom.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": " Modern-Tool ",
                    "publisher": " Acme ",
                    "version": "2.0.0",
                }
            ]
        }

        sbom_to_be_merged = self._load_reference_sbom("1.7")
        sbom_to_be_merged.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "modern-tool",
                    "publisher": "acme",
                    "version": "2.0.0",
                }
            ]
        }

        merged = merge.merge_2_sboms(
            copy.deepcopy(original_sbom),
            copy.deepcopy(sbom_to_be_merged),
        )

        components = merged["metadata"]["tools"].get("components", [])
        self.assertEqual(len(components), 1)
        self._assert_sbom_valid_for_spec(merged)

    def test_merge_tools_does_not_mutate_inputs(self) -> None:
        governing_tools = {
            "components": [
                {
                    "type": "application",
                    "name": "governing-tool",
                    "publisher": "acme",
                    "version": "1.0.0",
                }
            ]
        }
        tools_to_be_merged = [
            {
                "name": "merged-tool",
                "vendor": "contoso",
                "version": "2.0.0",
            }
        ]
        governing_snapshot = copy.deepcopy(governing_tools)
        merged_snapshot = copy.deepcopy(tools_to_be_merged)

        merged_tools = merge.merge_tools(governing_tools, tools_to_be_merged)

        self.assertEqual(governing_tools, governing_snapshot)
        self.assertEqual(tools_to_be_merged, merged_snapshot)
        self.assertEqual(len(merged_tools["components"]), 2)

    def test_merge_tools_target_object_does_not_mutate_legacy_array_inputs(self) -> None:
        governing_tools = [{"name": "legacy-governing", "vendor": "acme", "version": "1.0.0"}]
        tools_to_be_merged = {
            "components": [
                {
                    "type": "application",
                    "name": "incoming-modern",
                    "publisher": "contoso",
                    "version": "2.0.0",
                }
            ]
        }
        governing_snapshot = copy.deepcopy(governing_tools)
        merged_snapshot = copy.deepcopy(tools_to_be_merged)

        merged_tools = merge.merge_tools(
            governing_tools,
            tools_to_be_merged,
            target_format="object",
        )

        self.assertEqual(governing_tools, governing_snapshot)
        self.assertEqual(tools_to_be_merged, merged_snapshot)
        self.assertIsInstance(merged_tools, dict)
        self.assertIn("components", merged_tools)
        self.assertEqual(len(merged_tools["components"]), 2)


class TestMergeToolsBomRefUniqueness(unittest.TestCase):
    def _make_sbom(
        self,
        *,
        metadata_component: dict | None = None,
        components: list[dict] | None = None,
        tools: dict | list | None = None,
        dependencies: list[dict] | None = None,
        compositions: list[dict] | None = None,
        vulnerabilities: list[dict] | None = None,
        spec_version: str = "1.6",
    ) -> dict:
        sbom: dict = {
            "$schema": f"http://cyclonedx.org/schema/bom-{spec_version}.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": spec_version,
            "metadata": {},
            "components": components or [],
        }

        if metadata_component is not None:
            sbom["metadata"]["component"] = metadata_component
        if tools is not None:
            sbom["metadata"]["tools"] = tools
        if dependencies is not None:
            sbom["dependencies"] = dependencies
        if compositions is not None:
            sbom["compositions"] = compositions
        if vulnerabilities is not None:
            sbom["vulnerabilities"] = vulnerabilities

        return sbom

    def _collect_all_entity_refs(self, sbom: dict) -> list[str]:
        refs: list[str] = []

        def _add_ref(component: dict) -> None:
            ref = component.get("bom-ref")
            if isinstance(ref, str) and ref:
                refs.append(ref)

        metadata_component = sbom.get("metadata", {}).get("component")
        if isinstance(metadata_component, dict):
            _add_ref(metadata_component)

        for component in sbom.get("components", []):
            if not isinstance(component, dict):
                continue
            _add_ref(component)
            nested = component.get("components", [])
            if isinstance(nested, list):
                for subcomponent in merge.extract_components(nested):
                    if isinstance(subcomponent, dict):
                        _add_ref(subcomponent)

        tools = sbom.get("metadata", {}).get("tools")
        if isinstance(tools, dict):
            for key in ("components", "services"):
                values = tools.get(key, [])
                if not isinstance(values, list):
                    continue
                for value in values:
                    if isinstance(value, dict):
                        _add_ref(value)

        return refs

    def test_tool_ref_collides_with_component_ref_is_made_unique(self) -> None:
        sbom_1 = self._make_sbom(
            components=[
                {
                    "bom-ref": "shared-ref",
                    "type": "library",
                    "name": "component-a",
                    "version": "1.0.0",
                }
            ]
        )
        sbom_2 = self._make_sbom(
            tools={
                "components": [
                    {
                        "bom-ref": "shared-ref",
                        "type": "application",
                        "name": "tool-a",
                        "version": "1.0.0",
                    }
                ]
            }
        )

        merged = merge.merge([copy.deepcopy(sbom_1), copy.deepcopy(sbom_2)])

        refs = self._collect_all_entity_refs(merged)
        self.assertEqual(len(refs), len(set(refs)))
        self.assertEqual(merged["components"][0]["bom-ref"], "shared-ref")

    def test_tool_ref_collides_with_metadata_component_ref_is_made_unique(self) -> None:
        sbom_1 = self._make_sbom(
            metadata_component={
                "bom-ref": "meta-ref",
                "type": "application",
                "name": "app-a",
                "version": "1.0.0",
            }
        )
        sbom_2 = self._make_sbom(
            tools={
                "components": [
                    {
                        "bom-ref": "meta-ref",
                        "type": "application",
                        "name": "tool-a",
                        "version": "1.0.0",
                    }
                ]
            }
        )

        merged = merge.merge([copy.deepcopy(sbom_1), copy.deepcopy(sbom_2)])

        refs = self._collect_all_entity_refs(merged)
        self.assertEqual(len(refs), len(set(refs)))
        self.assertEqual(merged["metadata"]["component"]["bom-ref"], "meta-ref")

    def test_tool_ref_collides_with_nested_component_ref_is_made_unique(self) -> None:
        sbom_1 = self._make_sbom(
            components=[
                {
                    "bom-ref": "root-ref",
                    "type": "application",
                    "name": "root",
                    "version": "1.0.0",
                    "components": [
                        {
                            "bom-ref": "nested-ref",
                            "type": "library",
                            "name": "nested",
                            "version": "1.0.0",
                        }
                    ],
                }
            ]
        )
        sbom_2 = self._make_sbom(
            tools={
                "components": [
                    {
                        "bom-ref": "nested-ref",
                        "type": "application",
                        "name": "tool-a",
                        "version": "1.0.0",
                    }
                ]
            }
        )

        merged = merge.merge([copy.deepcopy(sbom_1), copy.deepcopy(sbom_2)])

        refs = self._collect_all_entity_refs(merged)
        self.assertEqual(len(refs), len(set(refs)))
        self.assertEqual(merged["components"][0]["components"][0]["bom-ref"], "nested-ref")

    def test_renamed_ref_is_updated_in_dependencies_and_vulnerabilities(self) -> None:
        # This test forces renaming of a regular component ref by colliding it
        # with a tool ref; dependencies/affects then must follow the new component ref.
        sbom_1 = self._make_sbom(
            tools={
                "components": [
                    {
                        "bom-ref": "shared-ref",
                        "type": "application",
                        "name": "tool-a",
                        "version": "1.0.0",
                    }
                ]
            },
            dependencies=[{"ref": "tool-root", "dependsOn": []}],
        )
        sbom_2 = self._make_sbom(
            components=[
                {
                    "bom-ref": "shared-ref",
                    "type": "library",
                    "name": "component-a",
                    "version": "1.0.0",
                }
            ],
            dependencies=[{"ref": "root", "dependsOn": ["shared-ref"]}],
            vulnerabilities=[
                {
                    "id": "CVE-0000-0100",
                    "affects": [{"ref": "shared-ref"}],
                }
            ],
        )

        merged = merge.merge([copy.deepcopy(sbom_1), copy.deepcopy(sbom_2)])

        component_ref = merged["components"][0]["bom-ref"]
        self.assertNotEqual(component_ref, "shared-ref")

        dependency = merged["dependencies"][0]
        self.assertIn(component_ref, dependency.get("dependsOn", []))
        self.assertNotIn("shared-ref", dependency.get("dependsOn", []))

        affects_refs = [
            affect.get("ref")
            for vulnerability in merged.get("vulnerabilities", [])
            for affect in vulnerability.get("affects", [])
        ]
        self.assertIn(component_ref, affects_refs)
        self.assertNotIn("shared-ref", affects_refs)

    def test_multiple_tools_across_inputs_sharing_one_ref_all_unique(self) -> None:
        sbom_1 = self._make_sbom(
            tools={
                "components": [
                    {
                        "bom-ref": "tool-ref",
                        "type": "application",
                        "name": "tool-a",
                        "version": "1.0.0",
                    }
                ]
            }
        )
        sbom_2 = self._make_sbom(
            tools={
                "components": [
                    {
                        "bom-ref": "tool-ref",
                        "type": "application",
                        "name": "tool-b",
                        "version": "1.0.0",
                    }
                ]
            }
        )
        sbom_3 = self._make_sbom(
            tools={
                "components": [
                    {
                        "bom-ref": "tool-ref",
                        "type": "application",
                        "name": "tool-c",
                        "version": "1.0.0",
                    }
                ]
            }
        )

        merged = merge.merge([copy.deepcopy(sbom_1), copy.deepcopy(sbom_2), copy.deepcopy(sbom_3)])
        tool_refs = [
            component.get("bom-ref")
            for component in merged.get("metadata", {}).get("tools", {}).get("components", [])
        ]

        self.assertEqual(len(tool_refs), 3)
        self.assertEqual(len(set(tool_refs)), 3)

    def test_shared_identity_tool_and_component_converge_to_same_ref(self) -> None:
        sbom_1 = self._make_sbom(
            components=[
                {
                    "bom-ref": "component-ref",
                    "type": "application",
                    "name": "same-identity",
                    "version": "1.0.0",
                }
            ]
        )
        sbom_2 = self._make_sbom(
            tools={
                "components": [
                    {
                        "bom-ref": "tool-ref",
                        "type": "application",
                        "name": "same-identity",
                        "version": "1.0.0",
                    }
                ]
            }
        )

        merged = merge.merge([copy.deepcopy(sbom_1), copy.deepcopy(sbom_2)])

        component_ref = merged["components"][0]["bom-ref"]
        tool_ref = merged["metadata"]["tools"]["components"][0]["bom-ref"]
        self.assertEqual(component_ref, tool_ref)
        self.assertNotIn(tool_ref, {"component-ref", "tool-ref"} - {component_ref})

    def test_same_ref_different_identity_tool_and_component_are_split(self) -> None:
        sbom_1 = self._make_sbom(
            components=[
                {
                    "bom-ref": "shared-ref",
                    "type": "application",
                    "name": "component-a",
                    "version": "1.0.0",
                }
            ]
        )
        sbom_2 = self._make_sbom(
            tools={
                "components": [
                    {
                        "bom-ref": "shared-ref",
                        "type": "application",
                        "name": "component-b",
                        "version": "1.0.0",
                    }
                ]
            }
        )

        merged = merge.merge([copy.deepcopy(sbom_1), copy.deepcopy(sbom_2)])

        component_ref = merged["components"][0]["bom-ref"]
        tool_ref = merged["metadata"]["tools"]["components"][0]["bom-ref"]
        self.assertNotEqual(component_ref, tool_ref)

    def test_no_collision_leaves_tool_refs_unchanged(self) -> None:
        sbom_1 = self._make_sbom(
            tools={
                "components": [
                    {
                        "bom-ref": "tool-ref-a",
                        "type": "application",
                        "name": "tool-a",
                        "version": "1.0.0",
                    }
                ]
            }
        )
        sbom_2 = self._make_sbom(
            tools={
                "components": [
                    {
                        "bom-ref": "tool-ref-b",
                        "type": "application",
                        "name": "tool-b",
                        "version": "1.0.0",
                    }
                ]
            }
        )

        merged = merge.merge([copy.deepcopy(sbom_1), copy.deepcopy(sbom_2)])
        refs = {
            component.get("bom-ref")
            for component in merged.get("metadata", {}).get("tools", {}).get("components", [])
        }
        self.assertEqual(refs, {"tool-ref-a", "tool-ref-b"})

    def test_legacy_array_tools_without_bom_refs_are_unaffected(self) -> None:
        sbom_1 = self._make_sbom(
            tools=[
                {
                    "name": "legacy-tool-a",
                    "vendor": "acme",
                    "version": "1.0.0",
                }
            ],
            spec_version="1.4",
        )
        sbom_2 = self._make_sbom(
            tools=[
                {
                    "name": "legacy-tool-b",
                    "vendor": "contoso",
                    "version": "2.0.0",
                }
            ],
            spec_version="1.4",
        )

        merged = merge.merge([copy.deepcopy(sbom_1), copy.deepcopy(sbom_2)])

        self.assertIsInstance(merged.get("metadata", {}).get("tools"), list)
        names = [tool.get("name") for tool in merged["metadata"]["tools"]]
        self.assertIn("legacy-tool-a", names)
        self.assertIn("legacy-tool-b", names)


class TestMergeSeveralSboms(unittest.TestCase):
    def test_merge_3_sboms_vulnerability_identity_after_intermediate_merge(self) -> None:
        sbom_1 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-2023-7158",
                    "analysis": {"state": "not_affected"},
                    "affects": [
                        {
                            "ref": "vtep_application",
                            "versions": [{"status": "unaffected", "version": "1.10.0"}],
                        }
                    ],
                }
            ],
        }

        sbom_2 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-2023-7158",
                    "analysis": {"state": "not_affected"},
                    "affects": [
                        {
                            "ref": "vtep_bootloader",
                            "versions": [{"status": "unaffected", "version": "5.1.0"}],
                        }
                    ],
                }
            ],
        }

        sbom_3 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-2023-7158",
                    "analysis": {"state": "not_affected"},
                    "affects": [
                        {
                            "ref": "vtep_bootselector",
                            "versions": [{"status": "unaffected", "version": "1.0.0"}],
                        }
                    ],
                }
            ],
        }

        merged_bom = merge.merge([sbom_1, sbom_2, sbom_3])
        vulnerabilities = merged_bom.get("vulnerabilities", [])

        self.assertEqual(len(vulnerabilities), 1)
        refs = {affected.get("ref") for affected in vulnerabilities[0].get("affects", [])}
        self.assertSetEqual(
            refs,
            {"vtep_application", "vtep_bootloader", "vtep_bootselector"},
        )

    def test_merge_3_sboms_alias_only_match(self) -> None:
        sbom_1 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-A",
                    "references": [{"id": "GHSA-shared"}],
                    "analysis": {"state": "not_affected"},
                    "affects": [{"ref": "comp-a", "versions": [{"status": "affected"}]}],
                }
            ],
        }
        sbom_2 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-B",
                    "references": [{"id": "GHSA-shared"}],
                    "analysis": {"state": "not_affected"},
                    "affects": [{"ref": "comp-b", "versions": [{"status": "affected"}]}],
                }
            ],
        }
        sbom_3 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-C",
                    "references": [{"id": "GHSA-shared"}],
                    "analysis": {"state": "not_affected"},
                    "affects": [{"ref": "comp-c", "versions": [{"status": "affected"}]}],
                }
            ],
        }

        merged_bom = merge.merge([sbom_1, sbom_2, sbom_3])
        vulnerabilities = merged_bom.get("vulnerabilities", [])

        self.assertEqual(len(vulnerabilities), 1)
        refs = {affected.get("ref") for affected in vulnerabilities[0].get("affects", [])}
        self.assertSetEqual(refs, {"comp-a", "comp-b", "comp-c"})

    def test_merge_3_sboms_distinct_vulns_not_over_merged(self) -> None:
        sbom_1 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-1",
                    "analysis": {"state": "not_affected"},
                    "affects": [{"ref": "comp-1", "versions": [{"status": "affected"}]}],
                }
            ],
        }
        sbom_2 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-2",
                    "analysis": {"state": "not_affected"},
                    "affects": [{"ref": "comp-2", "versions": [{"status": "affected"}]}],
                }
            ],
        }
        sbom_3 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-3",
                    "analysis": {"state": "not_affected"},
                    "affects": [{"ref": "comp-3", "versions": [{"status": "affected"}]}],
                }
            ],
        }

        merged_bom = merge.merge([sbom_1, sbom_2, sbom_3])
        vulnerabilities = merged_bom.get("vulnerabilities", [])

        self.assertEqual(len(vulnerabilities), 3)
        refs = {
            affected.get("ref")
            for vulnerability in vulnerabilities
            for affected in vulnerability.get("affects", [])
        }
        self.assertSetEqual(refs, {"comp-1", "comp-2", "comp-3"})

    def test_merge_3_sboms_empty_id_vulns_preserve_affects(self) -> None:
        sbom_1 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "analysis": {"state": "not_affected"},
                    "affects": [{"ref": "empty-1", "versions": [{"status": "affected"}]}],
                }
            ],
        }
        sbom_2 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "analysis": {"state": "not_affected"},
                    "affects": [{"ref": "empty-2", "versions": [{"status": "affected"}]}],
                }
            ],
        }
        sbom_3 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "analysis": {"state": "not_affected"},
                    "affects": [{"ref": "empty-3", "versions": [{"status": "affected"}]}],
                }
            ],
        }

        merged_bom = merge.merge([sbom_1, sbom_2, sbom_3])
        vulnerabilities = merged_bom.get("vulnerabilities", [])

        self.assertEqual(len(vulnerabilities), 3)
        refs = {
            affected.get("ref")
            for vulnerability in vulnerabilities
            for affected in vulnerability.get("affects", [])
        }
        self.assertSetEqual(refs, {"empty-1", "empty-2", "empty-3"})

    def test_merge_4_sboms_intermediate_mutation(self) -> None:
        sbom_1 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-2023-1111",
                    "analysis": {"state": "not_affected"},
                    "affects": [{"ref": "comp-1", "versions": [{"status": "affected"}]}],
                }
            ],
        }
        sbom_2 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-2023-1111",
                    "analysis": {"state": "not_affected"},
                    "affects": [{"ref": "comp-2", "versions": [{"status": "affected"}]}],
                }
            ],
        }
        sbom_3 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-2023-1111",
                    "analysis": {"state": "not_affected"},
                    "affects": [{"ref": "comp-3", "versions": [{"status": "affected"}]}],
                }
            ],
        }
        sbom_4 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-2023-1111",
                    "analysis": {"state": "not_affected"},
                    "affects": [{"ref": "comp-4", "versions": [{"status": "affected"}]}],
                }
            ],
        }

        merged_bom = merge.merge([sbom_1, sbom_2, sbom_3, sbom_4])
        vulnerabilities = merged_bom.get("vulnerabilities", [])

        self.assertEqual(len(vulnerabilities), 1)
        refs = {affected.get("ref") for affected in vulnerabilities[0].get("affects", [])}
        self.assertSetEqual(refs, {"comp-1", "comp-2", "comp-3", "comp-4"})

    def test_merge_3_sboms_differing_analysis_state(self) -> None:
        sbom_1 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-STATE",
                    "analysis": {"state": "not_affected"},
                    "affects": [{"ref": "state-1", "versions": [{"status": "affected"}]}],
                }
            ],
        }
        sbom_2 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-STATE",
                    "analysis": {"state": "false_positive"},
                    "affects": [{"ref": "state-2", "versions": [{"status": "affected"}]}],
                }
            ],
        }
        sbom_3 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-STATE",
                    "analysis": {"state": "exploitable"},
                    "affects": [{"ref": "state-3", "versions": [{"status": "affected"}]}],
                }
            ],
        }

        merged_bom = merge.merge([sbom_1, sbom_2, sbom_3])
        vulnerabilities = merged_bom.get("vulnerabilities", [])

        self.assertEqual(len(vulnerabilities), 3)
        refs_by_state = {
            vulnerability.get("analysis", {}).get("state", ""): {
                affected.get("ref") for affected in vulnerability.get("affects", [])
            }
            for vulnerability in vulnerabilities
        }
        self.assertDictEqual(
            refs_by_state,
            {
                "not_affected": {"state-1"},
                "false_positive": {"state-2"},
                "exploitable": {"state-3"},
            },
        )

    def _load_reference_sbom(self, spec_version: str) -> dict:
        with open(
            "tests/auxiliary/test_validate_sboms/"
            "Acme_Application_9.1.1_ec7781220ec7781220ec778122012345_20220217T101458.cdx.json",
            "r",
            encoding="utf_8_sig",
        ) as f:
            sbom = json.load(f)
        sbom["specVersion"] = spec_version
        return sbom

    def _assert_sbom_valid_for_spec(self, sbom: dict) -> None:
        with patch("cdxev.validator.validate.logger"):
            errors = validate_sbom(
                sbom=sbom,
                input_format="json",
                file=Path("bom.json"),
                report_format="stdout",
                report_path=Path("."),
                schema_type="custom",
                filename_regex=".*",
                schema_path=None,
            )
        self.assertEqual(errors, 0)

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

    def test_identical_metadata_bomrefs(self) -> None:
        metacomp1 = {
            "bom-ref": "app",
            "type": "application",
            "name": "foo",
        }
        metacomp2 = {
            "bom-ref": "app",
            "type": "application",
            "name": "bar",
        }
        sbom_template = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [],
            "dependencies": [],
        }

        sbom1 = sbom_template.copy()
        sbom1["metadata"] = {"component": metacomp1}
        sbom2 = sbom_template.copy()
        sbom2["metadata"] = {"component": metacomp2}

        result = merge.merge([sbom1, sbom2])

        self.assertNotEqual(
            result["metadata"]["component"]["bom-ref"],
            result["components"][0]["bom-ref"],
        )

    def test_merge_3_sboms_1_6_tools_format_follows_governing_spec(self) -> None:
        sbom_1 = self._load_reference_sbom("1.6")
        sbom_1.setdefault("metadata", {})["tools"] = [
            {"name": "legacy-tool", "vendor": "acme", "version": "1.0.0"}
        ]

        sbom_2 = self._load_reference_sbom("1.3")
        sbom_2.setdefault("metadata", {})["tools"] = [
            {"name": "legacy-tool-2", "vendor": "contoso", "version": "2.0.0"}
        ]

        sbom_3 = self._load_reference_sbom("1.7")
        sbom_3.setdefault("metadata", {})["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "modern-tool",
                    "publisher": "fabrikam",
                    "version": "3.0.0",
                }
            ],
            "services": [
                {
                    "name": "modern-service",
                    "provider": {"name": "fabrikam"},
                }
            ],
        }

        merged = merge.merge([copy.deepcopy(sbom_1), copy.deepcopy(sbom_2), copy.deepcopy(sbom_3)])

        tools = merged.get("metadata", {}).get("tools")
        self.assertIsInstance(tools, dict)
        self.assertIn("components", tools)
        self.assertIn("services", tools)
        self.assertTrue(
            any(component.get("name") == "legacy-tool" for component in tools["components"])
        )
        self.assertTrue(
            any(component.get("name") == "legacy-tool-2" for component in tools["components"])
        )
        self.assertTrue(
            any(component.get("name") == "modern-tool" for component in tools["components"])
        )
        self.assertTrue(
            any(service.get("name") == "modern-service" for service in tools["services"])
        )
        self._assert_sbom_valid_for_spec(merged)


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
            ComponentIdentity.create(components["component_2_sub_1"], allow_unsafe=True),
            ComponentIdentity.create(components["component_4_sub_1_sub_2"], allow_unsafe=True),
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
            ComponentIdentity.create(components["component_2_sub_1"], allow_unsafe=True): [
                components["component_2_sub_1_sub_1"]
            ],
        }

        add_to_existing_identical = True
        for key in add_to_existing_expected.keys():
            if add_to_existing_expected[key] != add_to_existing[key]:
                add_to_existing_identical = False

        self.assertTrue(len(add_to_existing.keys()) == len(add_to_existing_expected.keys()))
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

        expected_components = helper.load_sections_for_test_sbom()["hierarchical_expected"]

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
        compositions_2 = [{"aggregate": "incomplete", "assemblies": ["first_ref", "second_ref"]}]
        compositions_1: list[dict] = []
        merge.merge_compositions(compositions_1, compositions_2)
        self.assertEqual(compositions_1, compositions_2)

    def test_merge_compositions_one_aggregate(self) -> None:
        compositions_1 = [{"aggregate": "incomplete", "assemblies": ["first_ref", "second_ref"]}]
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
                "versions": [{"range": "vers:generic/>=4.5|<=5.0", "status": "affected"}],
            },
        ],
    }

    def calculate_merged_vulnerabilities(
        self, vulnerability_1: dict, vulnerability_2: dict
    ) -> list[dict]:
        vulnerability_identities = {
            json.dumps(vulnerability_1, sort_keys=True): VulnerabilityIdentity.from_vulnerability(
                vulnerability_1
            ),
            json.dumps(vulnerability_2, sort_keys=True): VulnerabilityIdentity.from_vulnerability(
                vulnerability_2
            ),
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
                "versions": [{"range": "vers:generic/<2.6|!=2.4", "status": "unaffected"}],
            }
        ]
        # drops one and removes the other from the range
        self.assertEqual(merged_vulnerabilities, [vulnerability_1, vulnerability_5_merged])

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
        vulnerabilities = helper.load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
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

    def test_merge_only_one_vulnerabilities(self) -> None:
        vulnerabilities = helper.load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]
        original_vulnerabilities = vulnerabilities["original_vulnerabilities"]
        new_vulnerabilities = vulnerabilities["new_vulnerabilities"]

        identities_1 = merge.get_identities_for_vulnerabilities(original_vulnerabilities)

        identities_2 = merge.get_identities_for_vulnerabilities(new_vulnerabilities)

        actual_merged = merge.merge_vulnerabilities(original_vulnerabilities, [], identities_1)

        actual_merged_2 = merge.merge_vulnerabilities(new_vulnerabilities, [], identities_2)

        actual_merged_3 = merge.merge_vulnerabilities([], original_vulnerabilities, identities_1)

        actual_merged_4 = merge.merge_vulnerabilities([], new_vulnerabilities, identities_2)

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
        vulnerabilities = helper.load_sections_for_test_sbom()["merge_vulnerabilities_tests"][
            "test_merge_vulnerabilities"
        ]
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

    def test_get_identities_for_vulnerabilities_no_id_no_references(self) -> None:
        # Regression test: a vulnerability with neither an "id" nor "references"
        # yields an empty alias list and must not raise IndexError.
        vulnerabilities = [{"affects": [{"ref": "product-a"}]}]
        identities = merge.get_identities_for_vulnerabilities(vulnerabilities)
        self.assertEqual(len(identities), 1)
        identity = next(iter(identities.values()))
        self.assertEqual(identity.id, "")
        self.assertEqual(identity.aliases, [])


class TestMergeSimilarComponents(unittest.TestCase):
    """
    Tests for the hierarchical component identity comparison used during merge.

    Keys are prioritized in this order: PURL > SWID > CPE > name/group/version.
    Comparison iterates through key types in that order and stops at the first
    type that is present on BOTH components. The components are considered
    identical when those two keys match, and different when they do not.
    """

    def setUp(self):
        self.component = {
            "type": "library",
            "name": "Library A",
            "version": "1.0.0",
            "purl": "pkg:npm/libA@1.0.0",
            "cpe": "cpe:2.3:a:example:libraryA:1.0.0:*:*:*:*:*:*:*",
            "swid": {
                "tagId": "library_A_1.0.0",
                "name": "Library A",
                "version": "1.0.0",
            },
        }
        self.sbom1 = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "type": "application",
                    "name": "foo",
                    "version": "1.0.0",
                }
            },
            "components": [copy.deepcopy(self.component)],
            "dependencies": [],
        }
        self.sbom2 = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "bom-ref": "bar",
                    "type": "application",
                    "name": "bar",
                    "version": "1.0.0",
                }
            },
            "components": [self.component],
            "dependencies": [],
        }

    def test_identical_components_are_dropped(self) -> None:
        result = merge.merge([self.sbom1, self.sbom2])
        self.assertEqual(
            result["components"],
            [self.sbom1["components"][0], self.sbom2["metadata"]["component"]],
        )

    def test_comps_with_different_purl_considered_different(self) -> None:
        self.component["purl"] = "pkg:npm/newpurl"
        result = merge.merge([self.sbom1, self.sbom2])
        self.assertIn(self.component, result["components"])

    def test_comps_with_different_swid_considered_identical(self) -> None:
        self.component["swid"] = {"tagId": "newtag", "name": "new name"}
        result = merge.merge([self.sbom1, self.sbom2])
        # Same PURL wins over different SWID → component treated as identical → must be dropped.
        self.assertNotIn(self.component, result["components"])

    def test_comps_with_different_cpe_considered_identical(self) -> None:
        self.component["cpe"] = "cpe:2.3:a:example:newcpe:1.0.0:*:*:*:*:*:*:*"
        result = merge.merge([self.sbom1, self.sbom2])
        # Same PURL wins over different CPE → component treated as identical → must be dropped.
        self.assertNotIn(self.component, result["components"])

    def test_comps_with_different_name_considered_identical(self) -> None:
        self.component["name"] = "new name"
        result = merge.merge([self.sbom1, self.sbom2])
        # Same PURL wins over different name → component treated as identical → must be dropped.
        self.assertNotIn(self.component, result["components"])

    def test_comps_with_subset_of_keys_considered_identical(self) -> None:
        # A set of tests where all possible combinations of PURL, SWID, and CPE are deleted
        # from the sbom2 component before the merge. Name/version are always left behind.
        # Even with a subset of keys, the shared remaining key still identifies the components
        # as identical so the sbom2 component is dropped.
        original_component = copy.deepcopy(self.component)
        identifiers = ["cpe", "purl", "swid"]
        for test_case in chain.from_iterable(
            combinations(identifiers, r + 1) for r in range(len(identifiers))
        ):
            with self.subTest(missing_keys=test_case):
                # Use fresh deep copies each iteration: merge mutates both input SBOMs
                # (appends sbom2 metadata to sbom2 components, grows sbom1 components).
                sbom1 = copy.deepcopy(self.sbom1)
                partial_component = copy.deepcopy(original_component)
                for identifier in test_case:
                    del partial_component[identifier]
                sbom2 = copy.deepcopy(self.sbom2)
                sbom2["components"] = [partial_component]
                result = merge.merge([sbom1, sbom2])
                # The partial component shares at least one key with sbom1's component
                # → treated as identical → must be dropped from the merged result.
                self.assertNotIn(partial_component, result["components"])

    # --- SWID-level priority (no PURL on either side) ---

    def test_swid_decisive_when_purl_absent_from_both_same_swid(self) -> None:
        # Without PURL on either component, SWID becomes the deciding key.
        # Same SWID → components are identical and the duplicate is dropped.
        del self.sbom1["components"][0]["purl"]
        del self.component["purl"]
        result = merge.merge([self.sbom1, self.sbom2])
        # Both components are now value-equal → the duplicate must appear exactly once.
        self.assertEqual(result["components"].count(self.component), 1)

    def test_swid_decisive_when_purl_absent_from_both_different_swid(self) -> None:
        # Without PURL on either component, SWID is decisive.
        # Different SWID → components are different, even when CPE and coordinates match.
        del self.sbom1["components"][0]["purl"]
        del self.component["purl"]
        self.component["swid"] = {"tagId": "OTHER_tag", "name": "Library A", "version": "1.0.0"}
        result = merge.merge([self.sbom1, self.sbom2])
        # Different SWID → treated as a distinct component → must be present in the result.
        self.assertIn(self.component, result["components"])

    def test_swid_beats_cpe_same_swid_different_cpe(self) -> None:
        # SWID has higher priority than CPE.
        # When neither component has PURL but both share the same SWID,
        # a different CPE is irrelevant – the components are considered identical.
        del self.sbom1["components"][0]["purl"]
        del self.component["purl"]
        self.component["cpe"] = "cpe:2.3:a:example:OTHER:1.0.0:*:*:*:*:*:*:*"
        result = merge.merge([self.sbom1, self.sbom2])
        # Same SWID wins over different CPE → component treated as identical → must be dropped.
        self.assertNotIn(self.component, result["components"])

    # --- CPE-level priority (no PURL or SWID on either side) ---

    def test_cpe_decisive_when_purl_and_swid_absent_from_both_same_cpe(self) -> None:
        # Without PURL or SWID on either component, CPE becomes the deciding key.
        # Same CPE → components are identical.
        del self.sbom1["components"][0]["purl"]
        del self.sbom1["components"][0]["swid"]
        del self.component["purl"]
        del self.component["swid"]
        result = merge.merge([self.sbom1, self.sbom2])
        # Both components are now value-equal → the duplicate must appear exactly once.
        self.assertEqual(result["components"].count(self.component), 1)

    def test_cpe_decisive_when_purl_and_swid_absent_from_both_different_cpe(self) -> None:
        # Without PURL or SWID on either component, CPE is decisive.
        # Different CPE → components are different, even when name and version match.
        del self.sbom1["components"][0]["purl"]
        del self.sbom1["components"][0]["swid"]
        del self.component["purl"]
        del self.component["swid"]
        self.component["cpe"] = "cpe:2.3:a:example:OTHER:1.0.0:*:*:*:*:*:*:*"
        result = merge.merge([self.sbom1, self.sbom2])
        # Different CPE → treated as a distinct component → must be present in the result.
        self.assertIn(self.component, result["components"])

    # --- Coordinates-level priority (no safe keys on either side) ---

    def test_coordinates_decisive_when_no_safe_keys_shared_same_coords(self) -> None:
        # When no safe key (PURL, SWID, CPE) is present on both components,
        # name/group/version (coordinates) are the final fallback.
        # Same coordinates → components are identical.
        del self.sbom1["components"][0]["purl"]
        del self.sbom1["components"][0]["swid"]
        del self.sbom1["components"][0]["cpe"]
        del self.component["purl"]
        del self.component["swid"]
        del self.component["cpe"]
        result = merge.merge([self.sbom1, self.sbom2])
        # Both components are now value-equal → the duplicate must appear exactly once.
        self.assertEqual(result["components"].count(self.component), 1)

    def test_coordinates_decisive_when_no_safe_keys_shared_different_coords(self) -> None:
        # When no safe key is present, different coordinates → different components.
        del self.sbom1["components"][0]["purl"]
        del self.sbom1["components"][0]["swid"]
        del self.sbom1["components"][0]["cpe"]
        del self.component["purl"]
        del self.component["swid"]
        del self.component["cpe"]
        self.component["version"] = "2.0.0"
        result = merge.merge([self.sbom1, self.sbom2])
        # Different version → treated as a distinct component → must be present in the result.
        self.assertIn(self.component, result["components"])


if __name__ == "__main__":
    unittest.main()
