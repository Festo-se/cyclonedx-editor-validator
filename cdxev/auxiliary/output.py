import json
import logging
import sys
import typing as t
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from cdxev import pkg
from cdxev.auxiliary.filename_gen import generate_filename

logger = logging.getLogger(__name__)


def write_sbom(
    sbom: dict, destination: t.Optional[Path], update_metadata: bool = True
) -> None:
    """
    Writes a JSON SBOM to a file.

    If the destination is a directory, then a filename for the output file is generated
    automatically and printed to stdout.

    :param sbom: The SBOM to write.
    :param destination: The file to write to. If not specified, write to stdout.
    :p
    :param update_metadata: Update the timestamp and tools metadata of the SBOM before
                                 writing.
    """

    if update_metadata:
        update_serial_number(sbom)
        update_version(sbom)
        update_timestamp(sbom)
        update_tools(sbom)

    file: t.TextIO
    if destination is None:
        # No output file specified.
        file = sys.stdout
    else:
        # Output has been specified but might be a file, directory or non-existent.
        if destination.exists() and destination.is_dir():
            filename = generate_filename(sbom)
            destination = destination.joinpath(filename)
            print("Writing output to: " + filename)
        elif not destination.exists() and not destination.parent.exists():
            # If the destination doesn't exist we should create it as a file. So first we
            # make sure its parent directory exists.
            destination.parent.mkdir(parents=True)
        file = destination.open("w")

    json.dump(sbom, file, indent=4)


def update_timestamp(sbom: dict) -> None:
    """Updates the SBOM timestamp to the current time."""
    metadata = sbom.setdefault("metadata", {})
    metadata["timestamp"] = datetime.now(timezone.utc).isoformat(timespec="seconds")


def update_tools(sbom: dict) -> None:
    """Adds this tool to the list of tools in metadata."""
    metadata: dict = sbom.setdefault("metadata", {})
    tools: list = metadata.setdefault("tools", [])

    this_tool = {
        "name": pkg.NAME,
        "vendor": pkg.VENDOR,
        "version": pkg.VERSION,
    }

    if any(tool for tool in tools if tool == this_tool):
        return

    tools.append(this_tool)


def update_serial_number(sbom: dict) -> None:
    """Generates a new serial number for the SBOM."""
    sbom["serialNumber"] = "urn:uuid:" + str(uuid4())


def update_version(sbom: dict) -> None:
    """Increments or creates the SBOM's version field."""
    version = sbom.setdefault("version", 0)
    version += 1
    sbom["version"] = version
