from cdxev.auxiliary.sbomFunctions import get_ref_from_components

import json
import os
import unittest
from pathlib import Path


def write_txt_file(content: str, file_name: str = "notice_file.txt") -> None:
    with open(file_name, 'w') as f:
        f.write(content)


def print_license(license: dict) -> str:
    if license.get("expression", ""):
        return license.get("expression", "")
    elif license.get("license", {}).get("id", ""):
        return license.get("license", {}).get("id", "")
    else:
        return license.get("license", {}).get("name", "")

def create_license_list(sbom: dict) -> str:
    product_name = sbom.get("metadata", {}).get("component", {}).get("name", "")
    product_copyright = sbom.get("metadata", {}).get("component", {}).get("copyright", "")
    if sbom.get("metadata", {}).get("licenses", []):
        product_licenses = sbom.get("metadata", {}).get("licenses", [])
    else:
        product_licenses = sbom.get("metadata", {}).get("component", {}).get("licenses", [])


    header = product_name + "\n"

    if product_copyright:
        header += product_copyright + "\n"
    elif product_licenses:
        for license in product_licenses:
            header += print_license(license) + ","
        header.rstrip(",")

    text_body = ""
    for component in sbom.get("components", []):
        text_body += component.get("name", "") + "\n"
        if component.get("copyright", ""):
            text_body += component.get("copyright", "") + "\n"
        for license in component.get("licenses", []):
            if print_license(license):
                text_body += print_license(license) + "\n"
            text_body += "\n"

    return header + "\n\n" + "This product includes material developed by third parties:" + "\n" + text_body







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


def get_test_sbom(pathsbom: str = path_to_sbom) -> dict:
    with open(pathsbom, "r") as read_file:
        sbom = json.load(read_file)
    return sbom


def get_public_sbom(pathsbom: str = path_to_public_sbom) -> dict:
    with open(pathsbom, "r") as read_file:
        sbom = json.load(read_file)
    return sbom


def get_dic_with_documentation_sboms(pathsbom: str = path_to_docu_sbom_dic) -> dict:
    with open(pathsbom, "r") as read_file:
        sbom = json.load(read_file)
    return sbom


def get_dic_with_public_documentation_sboms(
    pathsbom: str = path_to_public_docu_sbom_dic,
) -> dict:
    with open(pathsbom, "r") as read_file:
        sbom = json.load(read_file)
    return sbom


sbom = get_test_sbom()
notice_file = create_license_list(sbom)
write_txt_file(notice_file)