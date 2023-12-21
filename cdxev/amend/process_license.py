##################################################
# Function adds the id to a Software Bill of Materials, if only the name is given and the
# given name is found in the reference list of possible names
##################################################

import logging
import os
from typing import Sequence

from cdxev.auxiliary.identity import ComponentIdentity
from cdxev.error import AppError
from cdxev.log import LogMessage

logger = logging.getLogger(__name__)


def find_license_id(license_name: str, license_namelist: Sequence[dict]) -> str:
    """
    Searches in the given list for the name and returns the
    SPDX-ID of the license, if existing.

    Parameters
    ----------
    license_name: str
        Name of a license.
    license_namelist: list
        Possible names of licenses and the SPDX-ID.

    Returns
    -------
    str:
        SPDX-ID of the given string.
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


def process_license(
    component: dict, license_name_id_list: list, path_to_license_folder: str = ""
) -> None:
    """
    Adds the SPDX-ID of a license to a component and removes the name, if the name
    is in the list of licenses provided.

    If the path to a folder with txt files containing license descriptions with the
    naming convention 'license name'.txt is given,
    the program searches for a file with matching name
    and, if found, copies its content in the field "text".

    The operation is performed on the provided component.

    Parameters
    ----------
    :component: dict
        A component.
    :license_name_id_map: list
        A list with possible license names
        belonging to a license with SPDX-ID.
    :path_to_license_folder: str (optional)
        Path to a folder with txt files containing license texts.

    Returns
    -------

    """
    licenses = component.get("licenses", [])
    if not licenses:
        return

    component_id = ComponentIdentity.create(component, allow_unsafe=True)

    for license in licenses:
        if "license" not in license:
            continue

        current_license = license.get("license", {})
        if "id" in current_license:
            continue

        replace_license_name_with_id(current_license, license_name_id_list)
        add_text_from_folder_to_license_with_name(
            current_license, path_to_license_folder, component_id
        )

    return


def replace_license_name_with_id(license: dict, license_name_id_list: list) -> None:
    """
    Adds the SPDX-ID of a license to a license and removes the name, if the name
    is in the list of licenses provided.

    The operation is performed on the provided license.

    Parameters
    ----------
    :license: dict
        A license.
    :license_name_id_map: list
        A list with possible license names and
        belonging to a license id.

    Returns
    -------

    """
    if "id" in license:
        return

    id_found = find_license_id(license.get("name", ""), license_name_id_list)
    if id_found:
        license["id"] = id_found
        license.pop("name")
    return


def add_text_from_folder_to_license_with_name(
    license: dict,
    path_to_license_folder: str = "",
    component_id: ComponentIdentity = ComponentIdentity.create({}, allow_unsafe=True),
) -> None:
    """
    Adds the text describing a license,
    if the provided folder contains a corresponding txt-file with the text of the license.
    The txt-file has to follow the naming convention 'license name'.txt.

    The operation is performed on the provided license.

    Parameters
    ----------
    :license: dict
        A license.
    :path_to_license_folder: str
        The path to a folder with txt-files containing license descriptions.
    :component_id (optional): ComponentIdentity
        The ComponentIdentity of the component the submitted license belongs to.

    Returns
    -------

    """
    if path_to_license_folder and license.get("name", ""):
        license_text = get_license_text_from_folder(
            license.get("name", ""), path_to_license_folder
        )
        if license_text == "":
            logger.warning(
                LogMessage(
                    "License text not found",
                    (
                        f"No text for the license ({license.get('name', '')}), "
                        f"in component ({component_id}), was found. "
                        "An empty string was added as text."
                    ),
                )
            )
        else:
            if license.get("text", {}).get("content", "") != "":
                logger.warning(
                    LogMessage(
                        "License text replaced",
                        (
                            f"The license text of the license ({license.get('name', '')}),"
                            f" in component ({component_id}), was overwritten."
                        ),
                    )
                )
            logger.info(
                LogMessage(
                    "License text added",
                    (
                        f"The text of the license ({license.get('name', '')}),"
                        f" in component ({component_id}), was added."
                    ),
                )
            )
        license["text"] = {"content": license_text}
    return


def get_license_text_from_folder(license_name: str, path_to_license_folder: str) -> str:
    """
    Searches in given folder for a txt-file with the name of of a given license and
    returns the file's content as a string.

    Parameters
    ----------
    :license_name: str
        Name of the license.
    :path_to_license_folder: str
        Path to a folder with txt-files containing license descriptions.

    Returns
    -------
    str : the content of the file.
    """
    if os.path.isdir(path_to_license_folder):
        file_name = license_name + ".txt"
        for licenses_text_file in os.listdir(path_to_license_folder):
            if licenses_text_file == file_name:
                with open(os.path.join(path_to_license_folder, file_name)) as f:
                    license_text = f.read()
                return license_text
        return ""
    else:
        if not os.path.exists(path_to_license_folder):
            raise AppError(
                "Invalid path to license folder",
                (f"The submitted path ({path_to_license_folder})" " does not exist."),
            )
        else:
            raise AppError(
                "Invalid path to license folder",
                (
                    f"The submitted path ({path_to_license_folder})"
                    " does not lead to a folder."
                ),
            )
