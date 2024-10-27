============
list
============

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: list

    This command lists content of the SBOM. It can currently provide a list:

    * of the license information in the SBOM using the ``licenses`` operation,
    * of the components in the SBOM using the ``components`` operation.

    The information can be displayed as a text file or in csv format.


Output Format
-------------

The txt format for license information (derived from the format of `Apache NOTICE files <https://infra.apache.org/licensing-howto.html>`_) has the structure: ::

    Metadata component name:
    Metadata component copyright
    Metadata component license 1
    Metadata component license 2
    ...

    This product includes material developed by third parties:

    component 1 name:
    component 1 copyright
    component 1 license 1
    component 1 license 1
    ...

    component 2 name:
    component 2 copyright
    component 2 license 1
    component 2 license 2
    ...


The txt format for component information has the structure: ::

    Metadata component name
    Metadata component version
    Metadata component supplier name

    This product includes material developed by third parties:

    component 1 name
    component 1 version
    component 1 supplier name

    ...


The csv format for license information has the structure: ::

    Name,Copyright,Licenses
    "Metadata component name","Metadata component copyright","Metadata component license 1;..."
    "component 1 name","component 1 copyright","component 1 license 1;component 1 license 2..."
    "component 2 name","component 2 copyright",""
    ...


The csv format for component information has the structure: ::

    Name,Version,Supplier
    "Metadata component name","Metadata component version","Metadata component supplier name"
    "component 1 name","component 1 version","component 1 supplier name"
    "component 2 name","","component 2 supplier name"
    ...


Examples::

    # List the license information from bom.json
    cdx-ev list licenses bom.json

    # List the components from bom.json
    cdx-ev list components bom.json
