import json
import unittest

import cdxev.list_command as lc
from cdxev.auxiliary.sbomFunctions import deserialize

path_to_sbom = (
    "tests/auxiliary/test_list_command_sboms/"
    "Acme_Application_9.1.1_20220217T101458.cdx.json"
)


def get_test_sbom(path_sbom: str = path_to_sbom) -> dict:
    with open(path_sbom, "r") as read_file:
        sbom = json.load(read_file)
    return sbom


def extract_license(license: dict) -> str:
    if license.get("expression", ""):
        return license.get("expression", "")
    elif license.get("license", {}).get("id", ""):
        return license.get("license", {}).get("id", "")
    else:
        return license.get("license", {}).get("name", "")


class TestListCommand(unittest.TestCase):
    def test_list_license_information(self) -> None:
        sbom = get_test_sbom()
        deserialized_sbom = deserialize(sbom)
        license_file = lc.list_license_information(deserialized_sbom)
        components = sbom.get("components", [])
        list_file_licenses = license_file[
            license_file.find(
                "This product includes material developed by third parties:\n\n"
            )
            + len("This product includes material developed by third parties:\n")
            + 1 :
        ]
        list_file_licenses_split = list_file_licenses.split("\n\n")

        for component in components:
            found = False
            for license_entry in list_file_licenses_split:
                license_component_name = license_entry[: license_entry.find(":\n")]
                license_component_name = license_component_name.replace("\n", "")
                licenses = license_entry[license_entry.find(":\n") + len(":\n") :]
                license_list = licenses.split("\n")
                license_list = [entry.replace("\n", "") for entry in license_list]

                if component.get("name", "") != license_component_name:
                    continue

                if (
                    component.get("copyright", "")
                    and component.get("copyright", "") not in license_list
                ):
                    continue
                for license in component.get("licenses", []):
                    license_content = extract_license(license)
                    if license_content not in license_list:
                        continue

                found = True

            self.assertTrue(found)

    def test_list_components(self) -> None:
        sbom = get_test_sbom()
        deserialized_sbom = deserialize(sbom)
        license_file = lc.list_components(sbom=deserialized_sbom, format="txt")
        components = sbom.get("components", [])
        component_txt_list = license_file.split("\n\n")
        for component in components:
            found = False
            for component_entry in component_txt_list:
                attribute_text = component_entry.replace("\n", "")
                if not component.get("name", "") in attribute_text:
                    continue

                if not (
                    component.get("version", "") in attribute_text
                    and component.get("supplier", {}).get("name", "") in attribute_text
                ):
                    continue
                found = True

            self.assertTrue(found)

    def test_licenses_csv(self) -> None:
        sbom = get_test_sbom()
        deserialized_sbom = deserialize(sbom)
        license_file = lc.list_license_information(deserialized_sbom, format="csv")
        license_txt_list = license_file.split("\n")

        components = sbom.get("components", [])

        for component in components:
            found = False
            for license_entry in license_txt_list:

                if component.get("name", "") not in license_entry:
                    continue

                if (
                    component.get("copyright", "")
                    and component.get("copyright", "") not in license_entry
                ):
                    continue
                for license in component.get("licenses", []):
                    license_content = extract_license(license)
                    if license_content not in license_entry:
                        continue

                found = True

            self.assertTrue(found)

    def test_component_csv(self) -> None:
        sbom = get_test_sbom()
        deserialized_sbom = deserialize(sbom)
        license_file = lc.list_components(deserialized_sbom, format="csv")
        license_txt_list = license_file.split("\n")

        components = sbom.get("components", [])

        for component in components:
            found = False
            for license_entry in license_txt_list:

                if component.get("name", "") not in license_entry:
                    continue

                if (
                    component.get("version", "") not in license_entry
                    and component.get("copyright", "") not in license_entry
                ):
                    continue

                found = True

            self.assertTrue(found)
