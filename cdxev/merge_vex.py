# SPDX-License-Identifier: GPL-3.0-or-later

from cdxev import merge


def get_refs_from_vex(vex: dict) -> list:
    """
    Collects the refs of a vex file into a list

    Parameters
    ----------
    vex: dict
        A vex dictionary

    Returns
    -------
    list:
        List with the refs used in the vex
    """
    references = []
    for vulnerability in vex.get("vulnerabilities", []):
        for reference in vulnerability.get("affects", []):
            current_reference = reference.get("ref")
            if current_reference not in references:
                references.append(current_reference)
    return references


def get_refs_from_sbom(sbom: dict) -> list:
    """
    Collects the refs of a sbom file into a list

    Parameters
    ----------
    sbom: dict
        A sbom dictionary

    Returns
    -------
    list:
        List with the bom-refs used in the sbom
    """
    references = [sbom.get("metadata", {}).get("component", {}).get("bom-ref", "")]
    for components in sbom.get("components", []):
        references.append(components.get("bom-ref", ""))
    return references


def check_if_refs_are_in_sbom(vex: dict, sbom: dict) -> bool:
    """
    Checks if the refs used in the vex are from
    the given sbom

    Parameters
    ----------
    vex: dict
        A vex dictionary
    sbom: dict
        A sbom dictionary

    Returns
    -------
    bool:
        Boolean if the references used in the vex are all
        contained in the sbom
    """
    references_sbom = get_refs_from_sbom(sbom)
    references_vex = get_refs_from_vex(vex)
    is_in = True
    for refs in references_vex:
        if refs not in references_sbom:
            is_in = False
    return is_in


def merge_vex(sbom: dict, vex: dict) -> dict:
    """
    Merges vex into a sbom

    Parameters
    ----------
    sbom: dict
        A sbom dictionary
    vex: dict
        A vex dictionary

    Returns
    -------
    sbom:
        A sbom with the vulnerabilities from the vex file merged
        into it
    """
    if check_if_refs_are_in_sbom(vex, sbom):
        if "vulnerabilities" not in sbom:
            sbom["vulnerabilities"] = vex.get("vulnerabilities")
        else:
            current_vulnerabilities = sbom.get("vulnerabilities", [])
            new_vulnerabilities = vex.get("vulnerabilities", [])
            merged_vulnerabilities = merge.merge_vulnerabilities(
                current_vulnerabilities,
                new_vulnerabilities,
            )
            sbom["vulnerabilities"] = merged_vulnerabilities
    return sbom
