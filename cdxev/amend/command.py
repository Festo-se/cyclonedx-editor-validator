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

import logging
import typing as t

from cdxev.auxiliary.sbomFunctions import walk_components

from .operations import Operation

logger = logging.getLogger(__name__)


def get_all_operations() -> list[type[Operation]]:
    return Operation.__subclasses__()


def create_operations(
    operations: list[type[Operation]], config: dict[type[Operation], dict[str, t.Any]]
) -> list["Operation"]:
    instances = []
    for op in operations:
        options = config.get(op, {})
        instances.append(op(**options))

    return instances


def run(
    sbom: dict,
    selected: t.Optional[list[type[Operation]]] = None,
    config: dict[type[Operation], dict[str, t.Any]] = {},
) -> None:
    """
    Runs the amend command on an SBOM. The SBOM is modified in-place.

    :param dict sbom: The SBOM model.
    :param selected: List of operation classes to run on the SBOM.
    :param config: Arguments for the operations. They will be passed to the operation's
                   __init__() method as kw-args.
    """
    # If no operations are selected, select the default operations.
    if not selected:
        selected = [op for op in get_all_operations() if hasattr(op, "_amendDefault")]

    operations = create_operations(selected, config)

    _prepare(operations, sbom)
    _metadata(operations, sbom)
    walk_components(sbom, _do_amend, operations, skip_meta=True)


def _prepare(operations: list[Operation], sbom: dict) -> None:
    for operation in operations:
        operation.prepare(sbom)


def _metadata(operations: list[Operation], sbom: dict) -> None:
    if "metadata" not in sbom:
        return

    logger.debug("Processing metadata")
    metadata = sbom["metadata"]
    for operation in operations:
        operation.handle_metadata(metadata)


def _do_amend(component: dict, operations: list[Operation]) -> None:
    for operation in operations:
        logger.debug(
            "Processing component %s", (component.get("bom-ref", "<no bom-ref>"))
        )
        operation.handle_component(component)
