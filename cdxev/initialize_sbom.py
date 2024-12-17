# SPDX-License-Identifier: GPL-3.0-or-later

import json
from datetime import datetime
from typing import Any, Union
from uuid import uuid4

from cyclonedx.model import ExternalReference, ExternalReferenceType, XsUri
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.contact import OrganizationalContact, OrganizationalEntity
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.tool import Tool
from cyclonedx.output.json import JsonV1Dot6

from cdxev import pkg


def initialize_sbom(
    software_name: Union[str, None],
    version: Union[str, None],
    supplier: Union[str, None],
    authors: Union[str, None],
) -> dict[str, Any]:
    """
    Creates an initial SBOM draft to work with, containing the most basic fields.

    param software_name: the name of the component.
    param version: the component version.
    param authors: the person(s) who created the BOM.
    param supplier: the name of the organization that supplied the component.

    returns: initial SBOM for the software.
    """
    if software_name is None:
        software_name = "The name of the component described by the SBOM."
    if version is None:
        version = "The component version."
    if authors is None:
        authors = "The person who created the SBOM."
    if supplier is None:
        supplier = "The name of the organization that supplied the component."

    timestamp = datetime.now()
    copyright = (
        "A copyright notice informing users of "
        "the underlying claims to copyright ownership in a published work."
    )

    metadata_authors = OrganizationalContact(
        name=authors,
        phone="The phone number of the contact.",
        email="The email address of the contact.",
    )

    component_supplier = OrganizationalEntity(name=supplier)

    refrence_to_cdxev_tool = ExternalReference(
        url=XsUri("https://github.com/Festo-se/cyclonedx-editor-validator"),
        type=ExternalReferenceType.WEBSITE,
    )

    bom_ref = BomRef(str(uuid4()))

    metadata_component = Component(
        name=software_name,
        type=ComponentType.APPLICATION,
        supplier=component_supplier,
        version=version,
        copyright=copyright,
        bom_ref=bom_ref,
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
        timestamp=timestamp,
    )

    sbom = Bom(
        version=1,
        metadata=metadata,
        dependencies=[Dependency(bom_ref, dependencies=[])],
    )

    my_json_outputter = JsonV1Dot6(sbom)
    serialized_json: dict[str, Any] = json.loads(
        my_json_outputter.output_as_string(indent=4)
    )

    return serialized_json
