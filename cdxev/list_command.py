import logging
from typing import Any

from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component
from cyclonedx.model.license import DisjunctiveLicense, License, LicenseExpression

from cdxev.auxiliary.sbomFunctions import deserialize, extract_cyclonedx_components
from cdxev.error import AppError
from cdxev.log import LogMessage

logger = logging.getLogger(__name__)


def extract_string_from_license(license: License) -> str:
    if isinstance(license, DisjunctiveLicense):
        if license.id is not None:
            return str(license.id)
        elif license.name is not None:
            return str(license.name)
        else:
            return ""

    elif isinstance(license, LicenseExpression):
        if license.value is not None:
            return str(license.value)
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


def extract_metadata_license_information(metadata: BomMetaData) -> dict[str, Any]:
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
                message="SBOM has no metadata.component.",
                description=(
                    "The SBOM has no metadata so no information "
                    "about the software could be extracted."
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


def write_license_dict_to_txt(info_dict: dict[str, Any]) -> str:
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
        string += "No license or copyright information available."

    return string


def write_license_dict_to_csv(info_dict: dict[str, Any]) -> str:
    string = ""

    string += '"' + info_dict.get("name", "") + '"'

    string += ","
    string += '"' + info_dict.get("copyright", "") + '"'

    license_str = write_list_to_str(info_dict.get("licenses", ""), ",")
    string += ","
    string += '"' + license_str + '"'

    return string


def write_license_information_to_txt(
    software_information: dict[str, Any], component_information: list[dict[str, Any]]
) -> str:

    string = write_license_dict_to_txt(software_information)

    if not component_information:
        return string

    string += "\n\n"
    string += "This product includes material developed by third parties:"
    string += "\n\n"

    for entry in component_information:
        if entry.get("name", ""):
            string += write_license_dict_to_txt(entry)
            string += "\n\n"

    string.rstrip("\n\n")

    return string


def write_license_information_to_csv(
    software_information: dict[str, Any],
    component_information: list[dict[str, Any]],
) -> str:
    string = "Name,Copyright,Licenses"

    string += "\n" + write_license_dict_to_csv(software_information)

    if not component_information:
        return string

    for entry in component_information:
        if entry.get("name", ""):
            string += "\n"
            string += write_license_dict_to_csv(entry)

    return string


def list_license_information(sbom: Bom, format: str = "txt") -> str:

    metadata = sbom.metadata

    software_information = extract_metadata_license_information(metadata)
    component_information = extract_components_metadata_information(sbom.components)
    if format == "txt":
        txt_string = write_license_information_to_txt(
            software_information, component_information
        )

    if format == "csv":
        txt_string = write_license_information_to_csv(
            software_information, component_information
        )

    return txt_string


def list_component_information_csv(
    component: Component, division_character: str = ","
) -> str:
    string = ""
    if component.name is not None:
        string += '"' + component.name + '"'
    else:
        string += '"' + '"'

    if component.version is not None:
        string += division_character
        string += '"' + component.version + '"'
    else:
        string += division_character
        string += '"' + '"'

    if component.supplier is not None and component.supplier.name is not None:
        string += division_character
        string += '"' + component.supplier.name + '"'
    else:
        string += division_character
        string += '"' + '"'

    return string


def list_component_information_txt(
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


def list_components(sbom: Bom, format: str = "txt") -> str:
    if format == "txt":
        string = ""
        line_break = "\n\n"
    elif format == "csv":
        string = "Name,Version,Supplier\n"
        line_break = "\n"

    if sbom.metadata.component is not None:
        if format == "csv":
            string += list_component_information_csv(sbom.metadata.component)
        else:
            string += list_component_information_txt(sbom.metadata.component)
        string += line_break

    if format == "txt":
        string += "This product includes material developed by third parties:"
        string += line_break

    if sbom.components is not None:
        components = extract_cyclonedx_components(sbom.components)
        for component in components:
            if format == "csv":
                string += list_component_information_csv(component)
            else:
                string += list_component_information_txt(component)
            string += line_break

    string = string[: -len(line_break)]

    return string


def list_command(sbom: dict, operation: str, format: str = "txt") -> str:  # type: ignore
    """
    Lists specific content of the SBOM.

    Currently supported are the listing of license information and component information.
    The output can be in txt or csv format.

    :param sbom: The SBOM.
    :param operation: The list operation to be performed, can be either 'licenses' or 'components'.
    :param format: The output format. Can be either 'csv' or 'txt', the default is 'csv'.
    """
    deserialized_bom = deserialize(sbom)

    if operation == "licenses":
        output = list_license_information(sbom=deserialized_bom, format=format)

    elif operation == "components":
        output = list_components(sbom=deserialized_bom, format=format)
    else:
        raise AppError(
            "Operation not supported.",
            f"The operation {operation} is not supported, choose one of 'txt' and 'csv'.",
        )

    return output
