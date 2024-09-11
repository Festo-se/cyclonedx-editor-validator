==============
Usage
==============

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :nosubcommands:

.. toctree::
    :caption: Available commands
    :maxdepth: 1
    :glob:

    *

Exit codes
----------

As the tool should be used in CI/CD, it uses exit codes to indicate possible errors:

- ``0`` = Success
- ``2`` = Usage error, e.g., missing option, invalid argument, etc.
- ``3`` = Generic application error. This can have various reasons ranging from invalid input files to bugs in our code.
- ``4`` = *[Only for validate]* SBOM failed validation.

Output
------

Some commands produce a new SBOM as output. By default, this output will be written to stdout but it can be written to a file, using the command's ``--output`` option.

If the ``--output`` option is specified and set to an existing or non-existing file, the output is written there. If it points to a directory, the output will be written to a file with an auto-generated name in that directory.

.. attention::
    In both cases, existing files with the same name will be overwritten without warning.

The filename is generated according to the template ``<name>_<version>_<timestamp>.cdx.json``, where:

- ``<name>`` is the name of the component in the SBOM's metadata.
- ``<version>`` is the version of the component in the SBOM's metadata.
- ``<timestamp>`` is the timestamp in the SBOM's metadata or, if that doesn't exist, the current time. Either is converted to UTC and formatted as ``YYYYMMDDHHMMSS``.
