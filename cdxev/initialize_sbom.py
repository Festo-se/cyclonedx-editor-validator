# SPDX-License-Identifier: GPL-3.0-or-later

import json
import warnings
from datetime import datetime
from typing import Any, Union

from cyclonedx.model import (  # type: ignore
    ExternalReference,
    ExternalReferenceType,
    Tool,
    XsUri,
)
from cyclonedx.model.bom import Bom, BomMetaData  # type: ignore
from cyclonedx.model.bom_ref import BomRef  # type: ignore
from cyclonedx.model.component import Component, ComponentType  # type: ignore
from cyclonedx.model.contact import (  # type: ignore
    OrganizationalContact,
    OrganizationalEntity,
)
from cyclonedx.model.dependency import Dependency  # type: ignore
from cyclonedx.output.json import JsonV1Dot6  # type: ignore

from cdxev import pkg


def initialize_sbom(
    software_name: Union[str, None],
    version: Union[str, None],
    supplier_name: Union[str, None],
) -> dict[str, Any]:
    """
    Creates an initial SBOM draft to work with, containing the most basic fields.

    param software_name: the name of the software the sbom is for
    param version: the version of the sbom the software is for
    param supplier_name: name of the supplier the software is from

    returns: initial SBOM for the software
    """
    if software_name is None:
        software_name = "Name of the software described in the SBOM"
    if version is None:
        version = "Version of the software"
    if supplier_name is None:
        supplier_name = "The name of the organization supplying the software"

    timestamp = datetime.now()
    copyright = "Copyright of the software"

    metadata_authors = OrganizationalContact(
        name="Name of the author of the SBOM",
        phone="The phone number of the author of the SBOM",
        email="Email author of the SBOM",
    )

    metadata_supplier = OrganizationalEntity(
        name=supplier_name,
    )

    refrence_to_cdxev_tool = ExternalReference(
        url=XsUri("https://github.com/Festo-se/cyclonedx-editor-validator"),
        type=ExternalReferenceType.WEBSITE,
    )

    metadata_component = Component(
        name=software_name,
        type=ComponentType.APPLICATION,
        supplier=metadata_supplier,
        version=version,
        copyright=copyright,
        bom_ref=BomRef("bom-ref of the metadata component"),
    )

    metadata = BomMetaData(
        tools=[
            Tool(
                name=pkg.NAME,
                version=pkg.VERSION,
                vendor=pkg.VENDOR,
                external_references=[refrence_to_cdxev_tool],
            )
        ],
        authors=[metadata_authors],
        component=metadata_component,
        supplier=metadata_supplier,
        timestamp=timestamp,
    )
    with warnings.catch_warnings():
        warnings.simplefilter(
            "ignore"
        )  # ignore warning caused by absence of components
        sbom = Bom(
            version=1,
            metadata=metadata,
            dependencies=[
                Dependency(BomRef("bom-ref of the metadata component"), dependencies=[])
            ],
        )

        my_json_outputter = JsonV1Dot6(sbom)
        serialized_json: dict[str, Any] = json.loads(
            my_json_outputter.output_as_string(indent=4)
        )

    return serialized_json
