import json
import logging
from cdxev.auxiliary.sbomFunctions import deserialize
from cdxev.error import AppError
from cdxev.log import LogMessage

from cyclonedx.model.license import (
    License,
    LicenseExpression,
    DisjunctiveLicense,
)
from cyclonedx.model.bom import Bom


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


def list_license_information(sbom: dict) -> str:
    deserialized_bom = deserialize(sbom)
    metadata = deserialized_bom.metadata

    product_licenses = [License]
    product_copyright = ""

    header = [str]
    text_body = [str]
    if metadata.component is not None:
        metadata_component = metadata.component

        if metadata_component.name is not None:
            header.append(metadata_component.name)
            header.append("\n")
        else:
            logger.info(
                LogMessage(
                    "SBOM has no metadata.component",
                )
            )

        if metadata_component.licenses is not None:
            product_licenses = metadata_component.licenses
        if metadata_component.copyright is not None:
            product_copyright = metadata_component.copyright

    if not product_licenses and metadata.licenses is not None:
        product_licenses = metadata.licenses


    if product_copyright:
        header.append(product_copyright)
    elif product_licenses:
        for license in product_licenses:
            license_string = extract_string_from_license(license)
            if license_string:
                header.append(license_string)


    return product_name