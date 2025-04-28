============
vex
============

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: vex
    :nosubcommands:

    This command provides different operations on VEX/SBOM files with embedded vulnerabilities. The vex-command has the following subcommands:

    * ``list``: returns a list of all vulnerability-IDs.
    * ``trim``: returns a file with filtered vulnerabilities.
    * ``search``: returns a file with a specific vulnerability.
    * ``extract``: extract all vulnerabilities from an SBOM file to a VEX file.

list
-------------
.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: vex list

    This subcommand returns a list of all vulnerability-IDs inside the input file. There are two different options:

    * ``--state default`` (default) returns: ::

        CVE-ID,Description,Status
        CVE-1012-0001,some description of a vulnerability,exploitable
        CVE-1013-0002,some description of a vulnerability 2,not_affected
        CVE-1013-0003,some description of a vulnerability 3,exploitable

    * ``--state lightweight`` returns: ::

        CVE-ID
        CVE-1012-0001
        CVE-1013-0002
        CVE-1013-0003


    The output can be a text file or a CSV (default) file.

Example::

    # Write all vulnerability-IDs to list_vex.json
    cdxev vex list input_file.json --scheme default --format csv --output list_vex.json


trim
-------------
.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: vex trim

    This subcommand returns a JSON file which contains only filtered vulnerabilities. The vulnerabilities can be filtered by any key-value pair.

Example::

    # Writes all vulnerabilities with state "not_affected" to new file
    cdxev vex trim input_file.json key=state value=not_affected --output not_affected_vex.json


search
-------------
.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: vex search

    This subcommand searches a file for a specific vulnerability based on its ID. The command returns a JSON file.

Example::

    # Writes specific vulnerability with based on its ID to new file
    cdxev vex search input_file.json CVE-1013-0002 --output searched_vul.json


extract
-------------
.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: vex extract

    This subcommand extracts all vulnerabilities from an SBOM file and returns it as a VEX file in JSON format.

Example::

    # Writes specific vulnerability with based on its ID to new file
    cdxev vex extract input_file.json --output vex.json
