# CycloneDX Editor Validator
# Copyright (C) 2023  Festo SE & Co. KG

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

from collections.abc import Callable


def license_has_id(license: dict) -> bool:
    """
    Returns ``True`` if ``license`` contains an SPDX id.

    :param license: A license object.
    :returns: ``True`` if ``license`` contains an SPDX id.
    """
    return "id" in license


def license_has_text(license: dict) -> bool:
    """
    Returns ``True`` if ``license`` contains a non-empty text.

    :param license: A license object.
    :returns: ``True`` if ``license`` contains a non-empty text.
    """
    return "text" in license and license["text"]["content"]


def foreach_license(callable: Callable[[dict, dict], None], component: dict) -> None:
    """
    Runs the given callable on every license contained in the given component.

    SPDX license expressions are not considered. Components declaring their licenses in this form
    are skipped.

    For every other license, ``callable`` is invoked with the license object (i.e., the object
    containing the ``id`` and ``name`` properties) and the component itself as arguments.

    :param callable: A callable object that can accept a license object as its first and the
                     declaring component as its second argument.
    :param component: The component whose licenses to process.
    """
    if "licenses" not in component:
        return

    for license_container in component["licenses"]:
        if "license" not in license_container:
            # We don't do anything with SPDX expressions
            continue

        license = license_container["license"]
        callable(license, component)
