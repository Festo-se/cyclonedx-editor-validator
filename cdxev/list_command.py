import json
import logging
from cdxev.auxiliary.sbomFunctions import deserialize, extract_cyclonedx_components
from cdxev.error import AppError
from cdxev.log import LogMessage

from cyclonedx.model.license import (
    License,
    LicenseExpression,
    DisjunctiveLicense,
)
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component
from typing import Any


logger = logging.getLogger(__name__)


def print_license(license: dict) -> str:
    if license.get("expression", ""):
        return license.get("expression", "")
    elif license.get("license", {}).get("id", ""):
        return license.get("license", {}).get("id", "")
    else:
        return license.get("license", {}).get("name", "")


def extract_string_from_license(license: License) -> str:
    if isinstance(license, DisjunctiveLicense):
        if license.id is not None:
            return license.id
        elif license.name is not None:
            return license.name
        else:
            return ""

    elif isinstance(license, LicenseExpression):
        if license.value is not None:
            return license.value
        else:
            return ""
    else:
        return ""


def extract_license_strings_from_licenses(licenses: list[License]) -> list[str]:
    license_list = []
    for license in licenses:
        license_string = extract_string_from_license(license)
        if license_string:
            license_list.append(license_string)
    return license_list


def extract_metadata_license_information(metadata: BomMetaData) -> dict:
    if metadata.component is not None:
        metadata_component = metadata.component
        software_information: dict[str, Any] = {}
        if metadata_component.name is not None:
            software_information["name"] = metadata_component.name

        if metadata_component.licenses is not None:
            license_list = extract_license_strings_from_licenses(
                metadata_component.licenses
            )
            software_information["licenses"] = license_list

        if metadata_component.copyright is not None:
            software_information["copyright"] = metadata_component.copyright

    else:
        logger.info(
            LogMessage(
                message="SBOM has no metadata.component",
                description=(
                    "The SBOM has no metadata so no information "
                    "about the software could be extracted"
                ),
            )
        )

    return software_information


def extract_components_metadata_information(
    components: list[Component],
) -> list[dict[str, Any]]:
    extracted_components = extract_cyclonedx_components(components)

    list_of_license_information: list[dict[str, Any]] = []

    for component in extracted_components:
        license_information: dict[str, Any] = {}
        not_empty = False
        if component.name is not None:
            license_information["name"] = component.name

        if component.licenses is not None:
            license_list = extract_license_strings_from_licenses(component.licenses)
            license_information["licenses"] = license_list
            not_empty = True
        if component.copyright is not None:
            license_information["copyright"] = component.copyright
            not_empty = True

        if not_empty:
            list_of_license_information.append(license_information)

    return list_of_license_information


def write_list_to_str(str_list: list[str], division_character: str = "\n") -> str:
    string = ""
    if str_list:
        string += str_list[0]
    for index in range(1, len(str_list)):
        string += division_character
        string += str_list[index]
    return string


def write_license_dict_to_txt(info_dict: dict) -> str:
    string = ""

    if info_dict.get("name", ""):
        string += info_dict.get("name", "") + ":"

    if info_dict.get("copyright", ""):
        string += "\n"
        string += info_dict.get("copyright", "")

    if info_dict.get("licenses", ""):
        license_str = write_list_to_str(info_dict.get("licenses", ""))
        string += "\n"
        string += license_str

    if not info_dict.get("licenses", "") and not info_dict.get("copyright", ""):
        string += "\n"
        string += "No license or copyright information available"

    return string


def write_license_dict_to_csv(info_dict: dict) -> str:
    string = ""

    if info_dict.get("name", ""):
        string += info_dict.get("name", "")

    if info_dict.get("copyright", ""):
        string += ","
        string += info_dict.get("copyright", "")

    if info_dict.get("licenses", ""):
        license_str = write_list_to_str(info_dict.get("licenses", ""), ",")
        string += ","
        string += license_str

    return string


def write_license_information_to_txt(
    software_information: dict,
    component_information: list[dict],
    list_metadata: bool = True,
) -> str:

    if list_metadata:
        string = write_license_dict_to_txt(software_information)

        if not component_information:
            return string

        string += "\n\n"
        string += "This product includes material developed by third parties:"
        string += "\n\n"

    else:
        string = ""

    for entry in component_information:
        if entry.get("name", ""):
            string += write_license_dict_to_txt(entry)
            string += "\n\n"

    string.rstrip("\n\n")

    return string


def write_license_information_to_csv(
    software_information: dict,
    component_information: list[dict],
    list_metadata: bool = True,
) -> str:
    string = "Name,Copyright,Licenses"

    if list_metadata:
        string += "\n" + write_license_dict_to_csv(software_information)

    if not component_information:
        return string

    for entry in component_information:
        if entry.get("name", ""):
            string += "\n"
            string += write_license_dict_to_csv(entry)

    return string


def list_license_information(
    sbom: Bom, format: str = "txt", list_metadata: bool = True
) -> str:

    metadata = sbom.metadata

    software_information = extract_metadata_license_information(metadata)
    component_information = extract_components_metadata_information(sbom.components)
    if format == "txt":
        txt_string = write_license_information_to_txt(
            software_information, component_information, list_metadata=list_metadata
        )

    if format == "csv":
        txt_string = write_license_information_to_csv(
            software_information, component_information, list_metadata=list_metadata
        )

    return txt_string


def list_component_information(
    component: Component, division_character: str = "\n"
) -> str:
    string = ""
    if component.name is not None:
        string += component.name
    else:
        return ""

    if component.version is not None:
        string += division_character
        string += component.version

    if component.supplier is not None:
        if component.supplier.name is not None:
            string += division_character
            string += component.supplier.name

    return string


def list_components(sbom: Bom, list_metadata: bool = True, format: str = "txt") -> str:
    if format == "txt":
        division_character = "\n"
        string = ""
        line_break = "\n\n"
    elif format == "csv":
        division_character = ","
        string = "Name,Version,Supplier Name"
        line_break = "\n"

    if list_metadata:
        if sbom.metadata.component is not None:
            string += "\n"
            string += list_component_information(
                sbom.metadata.component, division_character
            )

    if sbom.components is not None:
        components = extract_cyclonedx_components(sbom.components)
        for component in components:
            string += line_break
            string += list_component_information(component, division_character)

    return string


def list_command(
    sbom: dict, operation: str, format: str = "txt", list_metadata: bool = True
) -> None:
    deserialized_bom = deserialize(sbom)

    if operation == "list-licenses":
        license_list = list_license_information(
            sbom=deserialized_bom, format=format, list_metadata=list_metadata
        )
        print(license_list)
    elif operation == "list-components":
        components_list = list_components(
            sbom=deserialized_bom, list_metadata=list_metadata, format=format
        )
        print(components_list)


# "Acme_Application_9.1.1_ec7781220ec7781220ec778122012345_20220217T101458.cdx.json",
with open(
    "C:/Workspace/Github/cyclonedx-editor-validator/tests/auxiliary/test_create_notice_file_sboms/Acme_Application_9.1.1_20220217T101458.cdx.json",
    "r",
) as file:
    data = json.load(file)
# data["components"] = data["components"][4]
# data["components"].pop(4)
# data["components"].pop(4)
# data["components"].pop(4)
# data["components"].pop(4)
# list_license_information(data)
list_command(data, "list-components", format="csv")
print("")
list_command(data, "list-components", format="csv", list_metadata=False)
print("")
print("")
list_command(data, "list-licenses", format="csv")
print("")
list_command(data, "list-licenses", format="csv", list_metadata=False)
print("")
print("txt")
print("")
list_command(data, "list-components", format="txt")
print("")
list_command(data, "list-components", format="txt", list_metadata=False)
print("")
print("")
list_command(data, "list-licenses", format="txt")
print("txt")
list_command(data, "list-licenses", format="txt", list_metadata=False)
