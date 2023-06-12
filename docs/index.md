# First steps

[TOC]

## Installation

This tool is published on [PyPi](https://pypi.org/project/cyclonedx-editor-validator/).

    python -m pip install cyclonedx-editor-validator

## Usage

The tool comes with built-in command-line help on its usage. To display these hints, run it with:

    cdx-ev --help              # Lists commands and options
    cdx-ev <command> --help    # Help for a specific command and its options

### Command output

Some commands produce a new SBOM as output. By default, this output will be written to stdout but it can be written to a file, using the command's `--output` option.

If the `--output` option is specified and set to an existing or non-existing file, the output is written there. If it points to a directory, the output will be written to a file with an auto-generated name in that directory. __In both cases, existing files with the same name will be overwritten.__

The filename is generated according to this template `<name>_<version>_<timestamp>.cdx.json`, where:

* `<name>` is the name of the component in the SBOM's metadata.
* `<version>` is the version of the component in the SBOM's metadata.
* `<timestamp>` is the timestamp in the SBOM's metadata or, if that doesn't exist, the current time. Either is converted to UTC and formatted as `YYYYMMDDHHMMSS`.
