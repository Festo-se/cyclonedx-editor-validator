============
init-sbom
============

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: init-sbom

    This command provides a first draft of an SBOM for manual completion.

    The created SBOM is according to the CycloneDX specification version 1.6.

Optional inputs
---------------

    Values for some fields can be provided to the command, those are:

    * The name for one author of the SBOM (metadata.authors[0].name) using the flag `--authors`,
    * The name of the supplier of the software (metadata.component.supplier.name) using the flag `--supplier`,
    * The name of the software (metadata.component.name) using the flag `--name`,
    * The version of the software (metadata.component.version) using the flag `--version`.

Examples::

    # Write an SBOM draft with default content to bom.json
    cdx-ev init-sbom -o bom.json

    # Write an SBOM draft with a submitted software name, version, supplier and author of the SBOM to bom.json
    cdx-ev init-sbom --name "my software" --supplier "acme inc." --version "1.1.1" --author "acme inc"  -o bom.json

The above provided example without passing arguments to `init-sbom` would result in: ::

    {
        "dependencies": [
            {
                "ref": "An optional identifier which can be used to reference the component elsewhere in the SBOM."
            }
        ],
        "metadata": {
            "authors": [
                {
                    "email": "The email address of the contact.",
                    "name": "The person who created the SBOM.",
                    "phone": "The phone number of the contact."
                }
            ],
            "component": {
                "bom-ref": "An optional identifier which can be used to reference the component elsewhere in the SBOM.",
                "copyright": "A copyright notice informing users of the underlying claims to copyright ownership in a published work.",
                "name": "The name of the component described by the SBOM.",
                "supplier": {
                    "name": "The name of the organization that supplied the component."
                },
                "type": "application",
                "version": "The component version."
            },
            "timestamp": "2024-10-27T10:56:40.095452+01:00",
            "tools": [
                {
                    "externalReferences": [
                        {
                            "type": "website",
                            "url": "https://github.com/Festo-se/cyclonedx-editor-validator"
                        }
                    ],
                    "name": "cyclonedx-editor-validator",
                    "vendor": "Festo SE & Co. KG",
                    "version": "0.0.0"
                }
            ]
        },
        "serialNumber": "urn:uuid:1fa01e4f-04f0-4208-9ea3-b53de58fd6a0",
        "version": 1,
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6"
    }
