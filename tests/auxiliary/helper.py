# SPDX-License-Identifier: GPL-3.0-or-later

import typing as t
import copy


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


def create_components() -> dict:
    components_list: list[dict] = []
    base_component = {
        "name": "base_component",
        "version": "1.0.0",
        "bom-ref": "base_component",
        "components": components_list,
        "type": "library",
        "supplier": {"name": "Company Legal"},
        "group": "com.company.governing",
        "copyright": "Company Legal 2022, all rights reserved",
    }

    component_1 = copy.deepcopy(base_component)
    component_1["name"] = "component_1"
    component_1["bom-ref"] = "component_1"

    component_2 = copy.deepcopy(base_component)
    component_2["name"] = "component_2"
    component_2["bom-ref"] = "component_2"

    component_3 = copy.deepcopy(base_component)
    component_3["name"] = "component_3"
    component_3["bom-ref"] = "component_3"

    component_4 = copy.deepcopy(base_component)
    component_4["name"] = "component_4"
    component_4["bom-ref"] = "component_4"

    component_1_sub_1 = copy.deepcopy(base_component)
    component_1_sub_1["name"] = "component_1_sub_1"
    component_1_sub_1["bom-ref"] = "component_1_sub_1"

    component_2_sub_1 = copy.deepcopy(base_component)
    component_2_sub_1["name"] = "component_2_sub_1"
    component_2_sub_1["bom-ref"] = "component_2_sub_1"

    component_2_sub_2 = copy.deepcopy(base_component)
    component_2_sub_2["name"] = "component_2_sub_2"
    component_2_sub_2["bom-ref"] = "component_2_sub_2"

    component_2_sub_1_sub_1 = copy.deepcopy(base_component)
    component_2_sub_1_sub_1["name"] = "component_2_sub_1_sub_1"
    component_2_sub_1_sub_1["bom-ref"] = "component_2_sub_1_sub_1"

    component_4_sub_1 = copy.deepcopy(base_component)
    component_4_sub_1["name"] = "component_4_sub_1"
    component_4_sub_1["bom-ref"] = "component_4_sub_1"

    component_4_sub_1_sub_1 = copy.deepcopy(base_component)
    component_4_sub_1_sub_1["name"] = "component_4_sub_1_sub_1"
    component_4_sub_1_sub_1["bom-ref"] = "component_4_sub_1_sub_1"

    component_4_sub_1_sub_2 = copy.deepcopy(base_component)
    component_4_sub_1_sub_2["name"] = "component_4_sub_1_sub_2"
    component_4_sub_1_sub_2["bom-ref"] = "component_4_sub_1_sub_2"

    components = {
        "component_1": component_1,
        "component_2": component_2,
        "component_3": component_3,
        "component_4": component_4,
        "component_1_sub_1": component_1_sub_1,
        "component_2_sub_1": component_2_sub_1,
        "component_2_sub_2": component_2_sub_2,
        "component_2_sub_1_sub_1": component_2_sub_1_sub_1,
        "component_4_sub_1": component_4_sub_1,
        "component_4_sub_1_sub_1": component_4_sub_1_sub_1,
        "component_4_sub_1_sub_2": component_4_sub_1_sub_2,
    }
    return components
