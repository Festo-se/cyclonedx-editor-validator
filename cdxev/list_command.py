import json
import logging
from cyclonedx.model.bom import Bom
from cdxev.auxiliary.sbomFunctions import deserialize
from cdxev.error import AppError
from cdxev.log import LogMessage

logger = logging.getLogger(__name__)

def print_license(license: dict) -> str:
    if license.get("expression", ""):
        return license.get("expression", "")
    elif license.get("license", {}).get("id", ""):
        return license.get("license", {}).get("id", "")
    else:
        return license.get("license", {}).get("name", "")


def list_license_information(sbom: dict) -> str:
    deserialized_bom = deserialize(sbom)
    metadata = deserialized_bom.metadata

    product_licenses = []
    product_copyright = ""

    header = []
    text_body = []
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
        header += product_copyright + "\n"
    elif product_licenses:
        for license in product_licenses:
            header += print_license(license) + ","
        header.rstrip(",")

    return product_name