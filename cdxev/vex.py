# SPDX-License-Identifier: GPL-3.0-or-later


from typing import Any, Union


def init_vex_header(input_file: dict[str, Any]) -> dict[str, Any]:
    """
    Copy important keys and values from input_file to output_file

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


def get_list_of_ids(input_file: dict[str, Any], scheme: str) -> str:
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
        list_str += "ID,RefID,Description,Status\n"
        for vulnerability in input_file.get("vulnerabilities", []):
            vul_id = vulnerability.get("id", "-")
            vul_ref_id = vulnerability.get("references", {}).get("id", "-")
            vul_description = vulnerability.get("description", "-")
            vul_state = vulnerability.get("analysis", {}).get("state", "-")
            list_str += (
                vul_id
                + ","
                + vul_ref_id
                + ","
                + vul_description
                + ","
                + vul_state
                + "\n"
            )
    elif scheme == "lightweight":
        list_str += "ID,RefID\n"
        for vulnerability in input_file.get("vulnerabilities", []):
            list_str += (
                vulnerability.get("id", "-")
                + ", "
                + vulnerability.get("references", {}).get("id", "-")
                + "\n"
            )

    return list_str


def get_list_of_trimed_vulnerabilities(
    input_file: dict[str, Any], state: str
) -> dict[str, Any]:
    """
    Get a file with vulnerabilities filtered by state

    Parameters
    ----------
    input_file: dict
        A dictionary to trim only affected vulnerabilities
    state: str
        The state of vulnerabilites for which the file gets filtered

    Returns
    -------
    output_file: dict
        A dict with filtered vulnerabilities
    """
    trimmed_vulnerabilities = []
    output_file = {}
    for vulnerability in input_file.get("vulnerabilities", []):
        if vulnerability.get("analysis", {}).get("state", "") == state:
            trimmed_vulnerabilities.append(vulnerability)

    output_file = init_vex_header(input_file)
    output_file["vulnerabilities"] = trimmed_vulnerabilities
    return output_file


def get_vulnerability_by_id(input_file: dict[str, Any], id: str) -> dict[str, Any]:
    searched_vulnerability = []
    output_file = {}
    for vulnerability in input_file.get("vulnerabilities", []):
        if (
            vulnerability.get("id", "-") == id
            or vulnerability.get("references", {}).get("id", "") == id
        ):
            searched_vulnerability.append(vulnerability)

    output_file = init_vex_header(input_file)
    output_file["vulnerabilities"] = searched_vulnerability
    return output_file


def get_vex_from_sbom(input_file: dict[str, Any]) -> dict[str, Any]:
    """
    Extract the vulnerabilities of a SBOM file to a VEX file

    Parameters
    ----------
    input_file: dict
        A SBOM dictionary from which the vulnerabilities should be extracted.

    Returns
    -------
    output_file: dict
        A dict with vulnerabilities in form of a VEX file
    """

    output_file = init_vex_header(input_file)
    output_file["vulnerabilities"] = input_file.get("vulnerabilities", [])
    return output_file


def vex(
    sub_command: str, file: dict[str, Any], state: str, scheme: str, vul_id: str = ""
) -> Union[dict[str, Any], str]:
    """
    Get different information about vulnerabilities in VEX file

    Parameters
    ----------
    subcommand: string
        - "list": Get IDs of vulnerabilities in VEX file
        - "trim": Get only affected vulnerabilities
        - "search <ID>": Get only vulnerability with ID
        - "extract": Get VEX file from SBOM file
    file: dict
        A VEX dictionary to search for values
    state: string
        A string containing the filtered state for the trim subcommand
    scheme: string
        A string containing the output scheme for the list subcommand
    vul_ID: String
        A string containing the sreached vulnerability-ID for the search subcommand

    Returns
    -------
    Depends on subcommand (`list` returns a string; else return a dict)
    string:
        A string with needed information
    dict:
        A dict with needed information
    """

    if sub_command == "list":
        return get_list_of_ids(file, scheme)
    elif sub_command == "trim":
        return get_list_of_trimed_vulnerabilities(file, state)
    elif sub_command == "search":
        return get_vulnerability_by_id(file, vul_id)
    elif sub_command == "extract":
        return get_vex_from_sbom(file)
    else:
        return {}
