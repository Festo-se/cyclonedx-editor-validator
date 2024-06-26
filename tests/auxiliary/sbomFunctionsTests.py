# Copyright: 2023 - 2024 Festo SE & Co. KG
# SPDX-License-Identifier: GPL-3.0-or-later


def compare_sboms(first_sbom: dict, second_sbom: dict) -> bool:
    """
    Compares two sboms while ignoring the timestamp.
    The order of elements contained in the sbom
    affects the result.

    Parameters
    ----------
    :first_sbom: dict
        A sbom dictionary
    :second_sbom: dict
        A sbom dictionary

    Returns
    -------
    bool:
        Returns True if the sboms are
        identical except of the timestamp,
        False if not
    """
    # Make copies so that we don't modify the original dicts
    first_sbom = dict(first_sbom)
    second_sbom = dict(second_sbom)

    # Isolate metadata out of the sboms because we have to remove the timestamp from it.
    metadata1 = first_sbom.pop("metadata", {})
    metadata2 = second_sbom.pop("metadata", {})

    metadata1.pop("timestamp", None)
    metadata2.pop("timestamp", None)

    return metadata1 == metadata2 and first_sbom == second_sbom


def compare_list_content(first_list: list, second_list: list) -> bool:
    """
    Compares the contents of two lists
    while ignoring the order of those
    elements in the respective lists.
    Basically treats lists as sets.

    Parameters
    ----------
    first_list: list
        A list
    second_list: list
        A list

    Returns
    -------
    bool:
        Returns True if the content of the lists
        is identical
    """
    is_equal = True
    if len(first_list) == len(second_list):
        for element in first_list:
            if element not in second_list:
                is_equal = False
    else:
        is_equal = False
    return is_equal
