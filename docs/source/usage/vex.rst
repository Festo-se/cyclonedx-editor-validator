============
vex
============

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: vex

    This command provides different operation on VEX-/SBOM- Files with embedded vulnerabilities. The vex-command has following subcommands:

    * ``list``: returns a list of all vulnerability-IDs
    * ``trim``: returns a file with filtered vulnerabilities
    * ``search``: returns a file with a specific vulnerability
    * ``extract``: extract all vulnerabilities from a SBOM-file to a VEX-file

list
-------------
.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: vex list

    This subcommand returns a list of all vulnerability-IDs inside the input file. There are two different options:

    * ``--state default`` returns: ::
        CVE-ID,Description,Status
        CVE-1012-0001,some description of a vulnerability,exploitable
        CVE-1013-0002,some description of a vulnerability 2,not_affected
        CVE-1013-0003,some description of a vulnerability 3,exploitable

    * ``--state lightweight`` returns: ::
        CVE-ID
        CVE-1012-0001
        CVE-1013-0002
        CVE-1013-0003


    The output can be a .txt file or a .csv file.

Example::

    # Write all vulnerability-IDs to list_vex.json
    cdxev vex list --scheme default --format csv --output list_vex.json input_file.json 


trim
-------------
.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: vex trim

    This subcommand returns a json file which contains only filtered vulnerabilities. The vulnerabilities can be filtered by the state. Following states are supported:
    
    * ``resolved``
    * ``resolved_with_pedigree``
    * ``exploitable``
    * ``in_triage``
    * ``false_positive``
    * ``not_affected``

Example::

    # Writes all vulnerabilities with state "not_affected" to new file
    cdxev vex trim --state not_affected --output not_affected_vex.json input_file.json


search
-------------
.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: vex search

    This subcommand searches a file for a specific vulnerability based on its ID. The command returns a .json file.

Example::

    # Writes specific vulnerability with based on its ID to new file
    cdxev vex search --output searched_vul.json CVE-1013-0002 input_file.json


extract
-------------
.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: vex extract

    This subcommand extracts all vulnerabilities from a SBOM-file and returns it as a VEX-file in .json format

Example::

    # Writes specific vulnerability with based on its ID to new file
    cdxev vex search --output searched_vul.json CVE-1013-0002 input_file.json 