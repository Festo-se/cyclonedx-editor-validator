# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import pathlib
import re
import sys
import typing as t
from dataclasses import dataclass, field, fields

import univers.version_range  # type:ignore

from cdxev.auxiliary.identity import ComponentIdentity, Coordinates, Key, KeyType
from cdxev.auxiliary.sbomFunctions import walk_components
from cdxev.error import AppError
from cdxev.log import LogMessage

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SetConfig:
    force: bool
    allow_protected: bool
    sbom_paths: t.Sequence[pathlib.Path]
    from_file: t.Optional[pathlib.Path]
    ignore_missing: bool = False


@dataclass
class Context:
    config: "SetConfig"
    component_map: dict[Key, list[dict]] = field(init=False)
    sbom: dict


@dataclass(init=True, frozen=True)
class CoordinatesWithVersionRange(Coordinates):
    version_range: univers.version_range.VersionRange
    version_type: univers.versions

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CoordinatesWithVersionRange):
            for field_ in fields(self):
                if getattr(self, field_.name) != getattr(other, field_.name):
                    return False
            return True

        if isinstance(other, Coordinates):
            for field_ in fields(other):
                if field_.name != "version" and getattr(self, field_.name) != getattr(
                    other, field_.name
                ):
                    return False

            if other.version is not None:
                if self.version_type(other.version) in self.version_range:
                    return True

        return False


@dataclass(frozen=True)
class UpdateIdentity(ComponentIdentity):
    """
    Represents the component identity as a set of identifying keys.

    A component can have more than one key. For two identities to be considered equal, at least
    one of their keys must be equal.
    An empty identity (which doesn't contain any keys) can never be equal to any other identity,
    even another empty one.

    Instances of this class are immutable.
    """

    def __init__(self, *keys: t.Optional[Key]):
        super().__init__(*keys)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, ComponentIdentity) or isinstance(other, UpdateIdentity)
        ) and any(k in self._keys for k in other._keys)

    @classmethod
    def create(
        cls, component: t.Mapping[str, t.Any], allow_unsafe: bool = False
    ) -> "ComponentIdentity":

        if "version_range" in component and "version" not in component:
            coordinates = cls._from_coordinates(
                name=component["name"],
                group=component.get("group"),
                version_range=component.get("version_range", ""),
            )
            return UpdateIdentity(coordinates)  # type:ignore

        else:
            return super().create(component, allow_unsafe)

    @staticmethod
    def _from_coordinates(
        name: str,
        group: t.Optional[str] = None,
        version_range: t.Optional[str] = None,
    ) -> "Key":
        coordinates = Coordinates(name, group, None)
        if (
            version_range is not None
            and re.fullmatch("vers:.+/.+", version_range) is not None
        ):
            version_range_object = univers.version_range.VersionRange.from_string(
                version_range
            )
            version_type = version_range_object.version_class
            coordinates = CoordinatesWithVersionRange(
                name, group, None, version_range_object, version_type
            )
        return Key(KeyType.COORDINATES, coordinates)


_IDENTIFIERS = {"cpe", "purl", "swid", "name", "version", "group"}
_PROTECTED = _IDENTIFIERS | {"components"}


def _should_merge(property: str, component: dict, update_set: dict) -> bool:
    return (
        property in component
        and isinstance(component[property], list)
        and not isinstance(update_set[property], list)
    )


def _should_delete(property: str, component: dict, update_set: dict) -> bool:
    return property in component and update_set[property] is None


def _should_overwrite(
    property: str, component_id: ComponentIdentity, force: bool
) -> bool:
    if force:
        logger.debug(f'Overwriting "{property}" on component "{component_id}"')
        return True

    if not sys.stdin.isatty():
        raise AppError(
            "Attempted overwrite",
            (
                f'The property "{property}" is already present on the component "{component_id}". '
                "Use the --force option to overwrite."
            ),
        )

    if _prompt_for_overwrite(property, component_id):
        logger.debug(
            f'Overwriting "{property}" on component "{component_id}" due to user choice.'
        )
        return True

    logger.debug(
        f'Not overwriting "{property}" on component "{component_id}" due to user choice.'
    )
    return False


def _prompt_for_overwrite(property: str, component_id: ComponentIdentity) -> bool:
    print(
        f'The property "{property}" is already present on the component with id "{component_id}".'
    )
    while True:
        s = input("Overwrite? [Y/n]: ")
        if s in ["y", "Y", "yes", "Yes", ""]:
            return True
        elif s in ["n", "N", "no", "No"]:
            return False


def _should_update_id(property: str) -> bool:
    return property in _IDENTIFIERS


def _should_remap(property: str) -> bool:
    return property in _PROTECTED and property not in _IDENTIFIERS


def _update_id(
    old: ComponentIdentity, new: ComponentIdentity, map: dict[Key, list[dict]]
) -> None:
    instance_list = None
    for key in old:
        instance_list = map.pop(key)

    if instance_list is None:
        return

    for key in new:
        map[key] = instance_list


def _do_update(component: dict, update: dict, ctx: Context) -> None:
    component_id = update["id"]
    update_set = update["set"]

    original_id: t.Optional[ComponentIdentity] = None
    remap = False

    for prop in update_set:
        if _should_delete(prop, component, update_set):
            logger.debug(f'Deleting "{prop}" on component "{component_id}".')
            del component[prop]
            continue

        if _should_merge(prop, component, update_set):
            logger.debug(f'Merging "{prop}" on component "{component_id}".')
            component[prop].append(update_set[prop])
            continue

        if _should_update_id(prop):
            original_id = original_id or ComponentIdentity.create(component, True)

        if _should_remap(prop):
            remap = True

        if prop not in component or _should_overwrite(
            prop, component_id, ctx.config.force
        ):
            logger.debug(f'Setting "{prop}" on component "{component_id}".')
            component[prop] = update_set[prop]

    if remap:
        ctx.component_map = _map_out_components(ctx.sbom)
    elif original_id:
        # If at least one identifying property has been changed, original_id will be set.
        # In this case, we'll update the old keys in the component map with the new ones.
        new_id = ComponentIdentity.create(component, True)
        _update_id(original_id, new_id, ctx.component_map)


def _map_out_components(sbom: dict) -> dict[Key, list[dict]]:
    def _add_to_map(component: dict, map: dict[Key, list[dict]]) -> None:
        component_id = ComponentIdentity.create(component, allow_unsafe=True)
        for key in component_id:
            instance_list = map.setdefault(key, [])
            instance_list.append(component)

    map: dict[Key, list[dict]] = {}
    walk_components(sbom, _add_to_map, map)
    return map


def _get_protected(update_set: dict) -> t.Union[t.Literal[False], set]:
    global _PROTECTED
    intersection = _PROTECTED & update_set.keys()
    if intersection:
        return intersection
    else:
        return False


def _validate_update_list(updates: t.Sequence[dict[str, t.Any]], ctx: Context) -> None:
    if len(updates) == 0:
        logger.debug(
            "No updates to perform. This is probably wrong but what do I know."
        )
        return

    for upd in updates:
        if "id" not in upd:
            raise AppError(
                "Invalid set file", "An update object is missing the 'id' property."
            )
        component_id = UpdateIdentity.create(upd["id"], True)
        upd["id"] = component_id

        if len(component_id) == 0:
            raise AppError(
                "Invalid set file", "An update object has an empty 'id' property."
            )
        if len(component_id) > 1:
            raise AppError(
                "Invalid set file",
                f"The update object with id {component_id} has more than one id.",
            )

        if "set" not in upd:
            raise AppError(
                "Invalid set file",
                f"The update object with id {component_id} is missing the 'set' property.",
            )
        if (protected := _get_protected(upd["set"])) and not ctx.config.allow_protected:
            raise AppError(
                "Invalid set usage",
                "The following properties are protected: "
                + ", ".join(protected)
                + ". Use the --allow-protected option to set them.",
            )


def run(sbom: dict, updates: t.Sequence[dict[str, t.Any]], cfg: SetConfig) -> None:
    ctx = Context(cfg, sbom)

    try:
        _validate_update_list(updates, ctx)
    except AppError:
        msg = LogMessage(
            "Set not performed",
            f'Exception was raised while setting from file "{cfg.from_file}',
        )
        raise AppError(log_msg=msg)

    ctx.component_map = _map_out_components(sbom)

    for update in updates:
        target_list: list[dict] = []
        try:
            update_id = update["id"]
            if isinstance(update_id[0].key, CoordinatesWithVersionRange):
                for key in ctx.component_map.keys():
                    if update_id[0] == key:
                        target_list += ctx.component_map[key]
            else:
                target_list = ctx.component_map[update_id[0]]
            for target in target_list:
                _do_update(target, update, ctx)
        except KeyError:
            if not cfg.ignore_missing:
                msg = LogMessage(
                    "Set not performed",
                    f'The component "{update["id"]}" was not found and could not be updated.',
                )
                raise AppError(log_msg=msg)
            else:
                logger.info(
                    LogMessage(
                        "Set not performed",
                        f'The component "{update["id"]}" was not found and could not be updated.',
                    )
                )
