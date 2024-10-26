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
