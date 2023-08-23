##################################################
# Function to merge a Software Bill of Materials
# and a second_vex file
##################################################

from cdxev import merge


def merge_vex(first_vex: dict, second_vex: dict) -> dict:
    """
    Merges two vex files

    Parameters
    ----------
    second_vex: dict
        A second_vex dictionary
    second_vex: dict
        A second_vex dictionary

    Returns
    -------
    merged_vex:
        A vex with the vulnerabilities from the both vex files merged
        into it
    """
    merged_vex = first_vex
    current_vulnerabilities = first_vex.get("vulnerabilities", [])
    new_vulnerabilities = second_vex.get("vulnerabilities", [])
    if not new_vulnerabilities:
        return current_vulnerabilities
    elif not current_vulnerabilities:
        merged_vex["vulnerabilities"] = new_vulnerabilities
    else:
        merged_vulnerabilities = merge.merge_vulnerabilities(
            current_vulnerabilities, new_vulnerabilities
        )
        merged_vex["vulnerabilities"] = merged_vulnerabilities
    return merged_vex
