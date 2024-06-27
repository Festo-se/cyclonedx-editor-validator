# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import re
import typing as t
import unicodedata
from datetime import datetime, timezone

from dateutil.parser import isoparse

logger = logging.getLogger(__name__)


def generate_filename(sbom: dict) -> str:
    """
    Generates a filename for the given SBOM.

    If the SBOM doesn't contain any of the required metadata to generate a unique filename,
    it will default to ``bom.json``.

    :param dict sbom: The SBOM to generate a filename for.

    :return: The filename.
    """
    name = sbom.get("metadata", {}).get("component", {}).get("name", "")
    name = _sanitize(name)
    version = sbom.get("metadata", {}).get("component", {}).get("version", "")
    version = _sanitize(version)
    timestamp_str: t.Union[str, None] = sbom.get("metadata", {}).get("timestamp")

    if not name and not version and not timestamp_str:
        return "bom.json"

    try:
        timestamp = isoparse(timestamp_str)  # type: ignore # because type errors are caught below
    except (ValueError, TypeError):
        logger.info(
            "SBOM has no or an unparsable timestamp. Using current time in filename."
        )
        timestamp = datetime.now(timezone.utc)

    name = name or "unknown"
    timestamp_str = _timestamp_to_utc_str(timestamp)

    components = [name]
    if version:
        components.append(version)

    components.append(timestamp_str)

    return "_".join(components) + ".cdx.json"


def generate_validation_pattern(sbom: dict) -> str:
    """
    Creates a regular expression which can be used to validate the filename of the given SBOM.

    The pattern allows the following variants of the filename:

    * ``bom.json`` is always an allowed name.
    * ``<name>_[<version>_][<hash>_<timestamp>|<hash>|<timestamp>].cdx.json``, where
      * ``<name>`` == ``metadata.component.name``, if it exists, otherwise ``unknown``.
      * ``<version>`` MUST be present, if and only if ``metadata.component.version`` exists.
      * ``<hash>`` == ``metadata.component.hashes[x].content`` for any index x.

    :param dict sbom: The SBOM whose filename to validate.

    :return: A regular expression.
    """
    regex = "bom\\.json|"

    name = sbom.get("metadata", {}).get("component", {}).get("name", "unknown")
    name = _sanitize(name)
    regex += re.escape(name) + "_"

    version = sbom.get("metadata", {}).get("component", {}).get("version", "")
    version = _sanitize(version)
    if version:
        regex += re.escape(version) + "_"

    timestamp = sbom.get("metadata", {}).get("timestamp")
    if timestamp:
        try:
            timestamp_regex = _timestamp_to_utc_str(isoparse(timestamp))
        except:
            timestamp_regex = "[0-9]{8}T[0-9]{6}"
    else:
        timestamp_regex = "[0-9]{8}T[0-9]{6}"

    hashes = [
        hash["content"]
        for hash in sbom.get("metadata", {}).get("component", {}).get("hashes", [])
    ]
    hashes_regex = "(" + "|".join(hashes) + ")"

    if not hashes:
        regex += timestamp_regex
    else:
        regex += f"({hashes_regex}|{hashes_regex}_{timestamp_regex}|{timestamp_regex})"

    regex += "\\.cdx\\.json"

    return regex


def _timestamp_to_utc_str(timestamp: datetime) -> str:
    """
    Converts a timestamp to the string format used in filenames.

    The timestamp will be converted to UTC if it isn't already.

    :param datetime timestamp: The timestamp to convert.

    :return: The string representation for use in the filename.
    """
    timestamp = timestamp.astimezone(timezone.utc)
    return timestamp.strftime("%Y%m%dT%H%M%S")


def _sanitize(s: str) -> str:
    """
    Converts a string to a representation safe for filenames.

    The following transformations are done:
    * Normalize Unicode
    * Filter out any characters which aren't alphanumeric, spaces, dashes, periods or underscores.
    * Strip any leading or trailing non-alphanumeric characters.

    :param str s: The original string.

    :return: A representation safe for use as a filename.
    """
    s = unicodedata.normalize("NFKC", s)
    s = "".join(c for c in s if (c.isalnum() or c in r" .-_"))
    s.strip(r" .-_")
    return s
