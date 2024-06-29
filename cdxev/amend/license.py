# SPDX-License-Identifier: GPL-3.0-or-later

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
