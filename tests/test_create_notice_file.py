import json
import unittest

import cdxev.create_notice_file as noticefile

path_to_sbom = (
    "tests/auxiliary/test_create_notice_file_sboms/"
    "Acme_Application_9.1.1_20220217T101458.cdx.json"
)


def get_test_sbom(path_sbom: str = path_to_sbom) -> dict:
    with open(path_sbom, "r") as read_file:
        sbom = json.load(read_file)
    return sbom


class TestCreatenoticefile(unittest.TestCase):
    def test_extract_license(self) -> None:
        expression = "Example, Inc. Commercial License"
        id = "Apache-1.0"
        name = "Apache 1.0"
        license_expression = {"expression": expression}
        license_id = {"license": {"id": id}}
        license_name = {"license": {"name": name}}
        extracted_expression = noticefile.extract_license(license_expression)
        extracted_id = noticefile.extract_license(license_id)
        extracted_name = noticefile.extract_license(license_name)
        extracted_empty_license = noticefile.extract_license({})

        self.assertEqual(extracted_expression, expression)
        self.assertEqual(extracted_id, id)
        self.assertEqual(extracted_name, name)
        self.assertEqual(extracted_empty_license, "")

    def test_create_notice_file(self) -> None:
        sbom = get_test_sbom()
        notice_file = noticefile.create_notice_file(sbom)
        components = noticefile.extract_components(sbom.get("components", []))
        notice_file_licenses = notice_file[
            notice_file.find(
                "This product includes material developed by third parties: \n"
            )
            + len("This product includes material developed by third parties: \n")
            + 1 :
        ]
        notice_file_licenses_split = notice_file_licenses.split("\n\n")

        for component in components:
            found = False
            for license_entry in notice_file_licenses_split:
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
                    license_content = noticefile.extract_license(license)
                    if license_content not in license_list:
                        continue

                found = True

            self.assertTrue(found)
