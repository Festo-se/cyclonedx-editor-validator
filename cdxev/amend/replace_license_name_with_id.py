##################################################
# Function adds the id to a Software Bill of Materials, if only the name is given and the
# given name is found in the reference list of possible names
##################################################

from typing import Sequence


def find_license_id(license_name: str, license_namelist: Sequence[dict]) -> str:
    """
    Searches in the given list for the name and returns
    given the license

    Parameters
    ----------
    license_name: str
        Name of a license
    license_namelist: list
        Possible names of licenses and the id

    Returns
    -------
    str:
        Id of the given string
    """
    license_id = ""
    if isinstance(license_name, str):
        for dicts in license_namelist:
            if license_name.lower() == dicts.get("exp", "").lower():
                license_id = dicts.get("exp", "")
            else:
                for name in dicts.get("names", []):
                    if license_name.lower() == name.lower():
                        license_id = dicts.get("exp", "")
    return license_id


def replace_license_name_with_id(component: dict, license_name_id_list: list) -> dict:
    """
    Adds the id of a license to a component and removes te name, if the name
    is in the list of licenses provided

    Parameters
    ----------
    :component: dict
        A component
    :license_name_id_map: list
        A list with possible license names and
        belonging to a license id

    Returns
    -------

    """
    licenses = component.get("licenses", [])
    if not licenses:
        return component

    for license in licenses:
        if "license" not in license:
            continue

        current_license = license.get("license", {})
        if "id" in current_license:
            continue

        id_found = find_license_id(
            current_license.get("name", ""), license_name_id_list
        )
        if id_found:
            current_license["id"] = id_found
            current_license.pop("name")
    return component
