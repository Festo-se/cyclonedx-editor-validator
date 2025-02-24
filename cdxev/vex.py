# SPDX-License-Identifier: GPL-3.0-or-later


import re
from typing import Any, Union


def init_vex_header(input_file: dict) -> dict:
    """
    Copy important keys and values from input_file to output_file.

    Parameters
    ----------
    input_file: dict
        A VEX/SBOM dictionary from which the information should be copied

    Returns
    -------
    output_file: dict
        A dict with important header pairs
    """

    output_file = {}
    output_file["bomFormat"] = input_file.get("bomFormat", "")
    output_file["specVersion"] = input_file.get("specVersion", "")
    output_file["version"] = input_file.get("version", 0)
    return output_file


def get_list_of_ids(input_file: dict, scheme: str) -> str:
    """
    Get a list of vulnerability IDs.

    Parameters
    ----------
    input_file: dict
        A dictionary to search for values

    Returns
    -------
    list_str: str
        A string with all IDs in .csv format
    """

    list_str = ""
    if scheme == "default":
        list_str += "CVE-ID,Description,Status\n"
        for vulnerability in input_file.get("vulnerabilities", []):
            vul_id = vulnerability.get("id", "-")
            vul_ref_id = vulnerability.get("references", [])[0].get("id", "-")
            vul_description = vulnerability.get("description", "-")
            vul_state = vulnerability.get("analysis", {}).get("state", "-")
            ratings = vulnerability.get("ratings", [])
            severity_string = ""
            # write rating string
            for rating in ratings:
                if severity_string != "":
                    severity_string += ","
                severity_string += (
                    f"{rating.get('method', '')}:"
                    f"{rating.get('score', '')}"
                    f"({rating.get('severity', '')})"
                )
            if len(ratings) == 0:
                severity_string = "-"
            publish_date = vulnerability.get("published", "-")
            update_date = vulnerability.get("updated", "-")
            vul_description = re.sub(
                r"[\t\n\r\|]+", "", vulnerability.get("description", "-")
            )
            list_str += (
                vulID
                + ","
                + vulRefID
                + ","
                + vulDescription
                + ","
                + vulState
                + "\n"
            )
    elif scheme == "lightweight":
        list_str += "CVE-ID\n"
        for vulnerability in input_file.get("vulnerabilities", []):
            list_str += (
                vulnerability.get("id", "-")
                + ","
                + vulnerability.get("references", [])[0].get("id", "-")
                + "\n"
            )

    return list_str


def search_key(data: dict[str, Any], key: str, value: str) -> bool:
    """
    Searches a (nested) dicionary for a key-value pair.
    Returns True if found, False if not found

    Parameters
    ----------
    data: dict
        A dictionary to be searched
    key: str
        The key to search for
    value: str
        The value associated with the key


    Returns
    -------
    bool
        True if found, False if not found
    """
    if key in data and data[key] == value:
        return True
    for k, v in data.items():
        if isinstance(v, dict):
            if search_key(v, key, value):
                return True
    return False


def get_list_of_trimed_vulnerabilities(input_file: dict, state: str) -> dict:
    """
    Get a file with vulnerabilities filtered by a key-value pair.

    Parameters
    ----------
    input_file: dict
        A dictionary to trim only affected vulnerabilities
    keyval_pair: str
        The key-value pair of vulnerabilites for which the file gets filtered

    Returns
    -------
    output_file: dict
        A dict with filtered vulnerabilities
    """
    trimmed_vulnerabilities = []
    output_file = {}

    for vulnerability in input_file.get("vulnerabilities", []):
        if vulnerability.get("analysis", []).get("state", []) == state:
            trimmed_vulnerabilities.append(vulnerability)

    output_file = init_vex_header(input_file)
    output_file["vulnerabilities"] = trimmed_vulnerabilities
    return output_file


def get_vulnerability_by_id(input_file: dict, id: str) -> dict:
    searched_vulnerability = []
    output_file = {}
    for vulnerability in input_file.get("vulnerabilities", []):
        if vulnerability.get("id", "-") == id or vulnerability.get("references", {}).get("id", "") == id:
            searched_vulnerability.append(vulnerability)

    output_file = init_vex_header(input_file)
    output_file["vulnerabilities"] = found_vulnerabilities
    return output_file


def get_vex_from_sbom(input_file: dict[str, Any]) -> dict[str, Any]:
    """
    Extract the vulnerabilities of a SBOM file to a VEX file.

    Parameters
    ----------
    input_file: dict
        An SBOM dictionary from which the vulnerabilities should be extracted

    Returns
    -------
    output_file: dict
        A dict with vulnerabilities in form of a VEX file
    """

    output_file = init_vex_header(input_file)
    output_file["vulnerabilities"] = input_file.get("vulnerabilities", [])
    return output_file


def vex(
    sub_command: str, file: dict, state: str, scheme: str, vul_id: str = ""
) -> Union[dict[str, Any], str]:
    """
    Get different information about vulnerabilities in VEX file.

    Parameters
    ----------
    subcommand: string
        - "list": Get IDs of vulnerabilities in VEX file
        - "trim": Get only vulnerabilities with searched key-value pair
        - "search <ID>": Get only vulnerability with ID
        - "extract": Get VEX file from SBOM file
    file: dict
        A VEX dictionary to search for values
    keyval: string
        A string containing the filtered key-value pair for the trim subcommand
    schema: string
        A string containing the output schema for the list subcommand
    vul_id: string
        A string containing the searched vulnerability-ID for the search subcommand

    Returns
    -------
    Depends on subcommand (`list` returns a string; else return a dict)
    string:
        A string with needed information
    dict:
        A dict with needed information
    """

    if sub_command == "list":
        return get_list_of_ids(file, schema)
    elif sub_command == "trim":
        return get_list_of_trimed_vulnerabilities(file, key, value)
    elif sub_command == "search":
        return get_vulnerability_by_id(file, vul_id)
    elif sub_command == "extract":
        return get_vex_from_sbom(file)
    else:
        return {}
