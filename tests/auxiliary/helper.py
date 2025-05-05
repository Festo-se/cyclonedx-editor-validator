# SPDX-License-Identifier: GPL-3.0-or-later

import json
import typing as t


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


def search_entry(haystack: dict, key: t.Any, value: t.Any) -> t.Optional[dict]:
    """
    Recursively searches a dict of dicts for a specific key/value pair.

    :param haystack: A dict of dicts (any other values).
    :param key: The key of the entry to search.
    :param value: The value of the entry to search.
    :return: The sub-dict of haystack which contains the key/value pair or None if not found.
    """

    def _recurse(d: dict) -> t.Optional[dict]:
        for k, v in d.items():
            if key == k and value == v:
                return d
            elif isinstance(v, dict):
                return _recurse(v)
            elif isinstance(v, list):
                for i in v:
                    if isinstance(i, dict):
                        found = _recurse(i)
                        if found is not None:
                            return found
        return None

    return _recurse(haystack)


# Import functions for json files used in test_merge and test_sbom_functions
path_to_folder_with_test_sboms = "tests/auxiliary/test_merge_sboms/"


def get_ratings_dict() -> dict:
    with open(
        path_to_folder_with_test_sboms + "ratings_lists_for_tests.json",
        "r",
        encoding="utf-8-sig",
    ) as my_file:
        return json.load(my_file)


def get_dictionary_with_stuff() -> dict:
    with open(
        path_to_folder_with_test_sboms + "sections_for_test_sbom.json",
        "r",
        encoding="utf-8-sig",
    ) as my_file:
        return json.load(my_file)


def load_governing_program() -> dict:
    with open(
        path_to_folder_with_test_sboms + "governing_program.json",
        "r",
        encoding="utf-8-sig",
    ) as my_file:
        sbom = json.load(my_file)
    return sbom


def load_sections_for_test_sbom() -> dict:
    with open(
        path_to_folder_with_test_sboms + "sections_for_test_sbom.json",
        "r",
        encoding="utf-8-sig",
    ) as my_file:
        sbom = json.load(my_file)
    return sbom


def load_governing_program_merged_sub_program() -> dict:
    with open(
        path_to_folder_with_test_sboms + "merged_sbom.json",
        "r",
        encoding="utf-8-sig",
    ) as my_file:
        sbom = json.load(my_file)
    return sbom


def load_sub_program() -> dict:
    with open(
        path_to_folder_with_test_sboms + "sub_program.json",
        "r",
        encoding="utf-8-sig",
    ) as my_file:
        sbom = json.load(my_file)
    return sbom


def load_additional_sbom_dict() -> dict:
    with open(
        path_to_folder_with_test_sboms + "additional_sboms.json",
        "r",
        encoding="utf-8-sig",
    ) as my_file:
        sbom = json.load(my_file)
    return sbom
