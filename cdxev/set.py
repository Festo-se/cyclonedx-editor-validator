# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import pathlib
import re
import sys
import typing as t
from dataclasses import dataclass, field

import univers.version_range
import univers.versions

from cdxev.auxiliary.identity import (
    ComponentIdentity,
    Coordinates,
    CoordinatesRegexIdentity,
    CoordinatesWithVersionRange,
    Key,
    KeyType,
    RegexUpdateIdentity,
)
from cdxev.auxiliary.sbom_functions import walk_components
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
    ignore_existing: bool = False


@dataclass
class Context:
    config: "SetConfig"
    component_map: dict[Key, list[dict]] = field(init=False)
    sbom: dict


@dataclass(frozen=True)
class UpdateIdentity(ComponentIdentity):
    """
    Represents the identity of components the set command shall apply an update to.

    This class inherits from cdxev.auxiliary.identity.ComponentIdentity and
    extends its functionality to allow CoordinatesWithVersionRange objects
    as keys of the type coordinate.

    This classes comparator is compatible with UpdateIdentity objects.

    Instances of this class are immutable.
    """

    def __init__(self, *keys: t.Optional[Key]):
        super().__init__(*keys)

    def __eq__(self, other: object) -> bool:
        return (isinstance(other, ComponentIdentity) or isinstance(other, UpdateIdentity)) and any(
            k in self._keys for k in other._keys
        )

    @classmethod
    def create(
        cls, component: t.Mapping[str, t.Any], allow_unsafe: bool = False
    ) -> "t.Union[UpdateIdentity, ComponentIdentity]":
        if "version-range" in component:
            coordinates = cls.from_coordinates(
                name=component["name"],
                group=component.get("group"),
                version_range=component.get("version-range", ""),
            )
            return UpdateIdentity(coordinates)

        else:
            return super().create(component, allow_unsafe)

    @staticmethod
    def from_coordinates(
        name: str,
        group: t.Optional[str] = None,
        version: t.Optional[str] = None,
        version_range: t.Optional[str] = None,
    ) -> "Key":
        coordinates: Coordinates
        if version_range is not None:
            vers = univers.version_range.VersionRange.from_string(version_range)  # type:ignore
            coordinates = CoordinatesWithVersionRange(name, group, None, vers)
        else:
            coordinates = Coordinates(name, group, version)
        return Key(KeyType.COORDINATES, coordinates)


_IDENTIFIERS = {"cpe", "purl", "swid", "name", "version", "group"}
_PROTECTED = _IDENTIFIERS | {"components"}
_REGEX_IDENTIFIER_ALIASES = {
    "namePattern": "name",
    "cpePattern": "cpe",
    "purlPattern": "purl",
}


def _should_merge(property: str, component: dict, update_set: dict) -> bool:
    return (
        property in component
        and isinstance(component[property], list)
        and not isinstance(update_set[property], list)
    )


def _should_delete(property: str, component: dict, update_set: dict) -> bool:
    return property in component and update_set[property] is None


def _should_overwrite(
    property: str, component_id: ComponentIdentity, force: bool, ignore_existing: bool
) -> bool:
    if force:
        logger.debug(f'Overwriting "{property}" on component "{component_id}"')
        return True

    if ignore_existing:
        logger.debug(f'Not overwriting "{property}" on component "{component_id}"')
        return False

    if not sys.stdin.isatty():
        raise AppError(
            "Attempted overwrite",
            (
                f'The property "{property}" is already present on the component "{component_id}". '
                "Use the --force option to overwrite. "
                "Or --ignore-existing option to not overwrite."
            ),
        )
    else:  # pragma: no cover
        if _prompt_for_overwrite(property, component_id):
            return True

        logger.debug(
            f'Not overwriting "{property}" on component "{component_id}" due to user choice.'
        )
        return False


def _prompt_for_overwrite(
    property: str, component_id: ComponentIdentity
) -> bool:  # pragma: no cover
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


def _update_id(old: ComponentIdentity, new: ComponentIdentity, map: dict[Key, list[dict]]) -> None:
    instance_list = None
    for key in old:
        instance_list = map.pop(key)

    instance_list = t.cast(list[dict], instance_list)

    for key in new:
        map[key] = instance_list


def _do_update(component: dict, update: dict, ctx: Context) -> None:
    component_id = update["id"]
    update_set = update["set"]

    original_id: t.Optional[ComponentIdentity] = None
    remap = False

    for prop in update_set:
        if _should_update_id(prop):
            original_id = original_id or ComponentIdentity.create(component, True)

        if _should_remap(prop):
            remap = True

        if _should_delete(prop, component, update_set):
            logger.debug(f'Deleting "{prop}" on component "{component_id}".')
            del component[prop]
            continue

        if _should_merge(prop, component, update_set):
            logger.debug(f'Merging "{prop}" on component "{component_id}".')
            component[prop].append(update_set[prop])
            continue

        if prop not in component or _should_overwrite(
            prop, component_id, ctx.config.force, ctx.config.ignore_existing
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
    intersection = _PROTECTED & update_set.keys()
    if intersection:
        return intersection
    else:
        return False


def _extract_regex_str(value: t.Any, field: str) -> str:
    """Validate and extract the expression from a ``{"regex": "..."}`` dict."""
    if not isinstance(value, dict) or "regex" not in value:
        raise AppError(
            "Invalid set file",
            f'The update object identifier "{field}" must be a string or '
            'an object with a single "regex" property.',
        )
    if len(value) != 1:
        raise AppError(
            "Invalid set file",
            f'The update object identifier "{field}" uses regex and may only '
            'contain the property "regex".',
        )
    expr = value["regex"]
    if not isinstance(expr, str):
        raise AppError(
            "Invalid set file",
            f'The update object identifier "{field}" has a regex expression that is not a string.',
        )
    return expr


def _parse_simple_regex(
    update_id: t.Mapping[str, t.Any],
) -> t.Optional[RegexUpdateIdentity]:
    """Parse a single-field cpe or purl regex identifier."""
    matches: list[tuple[str, str, str]] = []
    for alias in ("cpePattern", "purlPattern"):
        if alias in update_id:
            expr = update_id[alias]
            if not isinstance(expr, str):
                raise AppError(
                    "Invalid set file",
                    f'The update object identifier "{alias}" must be a string.',
                )
            matches.append((_REGEX_IDENTIFIER_ALIASES[alias], expr, alias))

    for target in ("cpe", "purl"):
        value = update_id.get(target)
        if isinstance(value, dict):
            matches.append((target, _extract_regex_str(value, target), target))

    if not matches:
        return None

    if len(matches) > 1 or len(update_id) > 1:
        raise AppError(
            "Invalid set file",
            f"The update object with id {dict(update_id)} has more than one id.",
        )

    target, expression, source = matches[0]
    try:
        return RegexUpdateIdentity.create(target, expression)
    except re.error as exc:
        raise AppError(
            "Invalid set file",
            f'The update object identifier "{source}" has an invalid regular expression: {exc}',
        ) from exc


def _parse_coordinates_regex(
    update_id: t.Mapping[str, t.Any],
) -> t.Optional[CoordinatesRegexIdentity]:
    """Parse a name-based regex identifier with optional group/version companions."""
    name_expression: t.Optional[str] = None
    name_source: t.Optional[str] = None

    if "namePattern" in update_id:
        expr = update_id["namePattern"]
        if not isinstance(expr, str):
            raise AppError(
                "Invalid set file",
                'The update object identifier "namePattern" must be a string.',
            )
        name_expression = expr
        name_source = "namePattern"
    elif isinstance(update_id.get("name"), dict):
        name_expression = _extract_regex_str(update_id["name"], "name")
        name_source = "name"

    if name_expression is None:
        return None

    allowed = {name_source} | {"group", "version", "version-range"}
    unexpected = set(update_id.keys()) - allowed
    if unexpected:
        companions = ", ".join(sorted(unexpected))
        raise AppError(
            "Invalid set file",
            "A name regex identifier may only be combined with group, version "
            f'or version-range, but found unsupported companion(s): {companions}.',
        )

    group_expression: t.Optional[str] = None
    group_is_regex = False
    if "group" in update_id:
        g = update_id["group"]
        if isinstance(g, str):
            group_expression = g
        elif isinstance(g, dict):
            group_expression = _extract_regex_str(g, "group")
            group_is_regex = True
        else:
            raise AppError(
                "Invalid set file",
                'The update object identifier "group" must be a string or {"regex": "..."}.',
            )

    version: t.Optional[str] = None
    if "version" in update_id:
        v = update_id["version"]
        if not isinstance(v, str):
            raise AppError(
                "Invalid set file",
                'The update object identifier "version" must be a string.',
            )
        version = v

    version_range_obj: t.Optional[univers.version_range.VersionRange] = None
    if version is not None and "version-range" in update_id:
        raise AppError(
            "Invalid set file",
            "An update object contains a 'version' and 'version-range' but only "
            "one of them is permitted.",
        )

    if "version-range" in update_id:
        vr = update_id["version-range"]
        if not isinstance(vr, str):
            raise AppError(
                "Invalid set file",
                'The update object identifier "version-range" must be a string.',
            )
        try:
            from_string = univers.version_range.VersionRange.from_string
            version_range_obj = from_string(vr)  # type: ignore[no-untyped-call]
        except (ValueError, univers.versions.InvalidVersion) as exc:
            raise AppError(
                "Invalid set file",
                f"An update object has an invalid version-range: {exc}",
            ) from exc

    try:
        return CoordinatesRegexIdentity.create(
            name_expression=name_expression,
            group_expression=group_expression,
            group_is_regex=group_is_regex,
            version=version,
            version_range=version_range_obj,
        )
    except re.error as exc:
        raise AppError(
            "Invalid set file",
            f'The update object identifier "{name_source}" has an invalid '
            f"regular expression: {exc}",
        ) from exc


def _reject_unsupported_id_dicts(update_id: t.Mapping[str, t.Any]) -> None:
    """Raise AppError if any identifier field carries an unsupported dict value."""
    for id_field, value in update_id.items():
        if id_field in _REGEX_IDENTIFIER_ALIASES:
            continue
        if id_field not in _IDENTIFIERS:
            continue
        if not isinstance(value, dict):
            continue
        if "regex" not in value:
            continue

        if id_field == "group":
            raise AppError(
                "Invalid set file",
                'The update object identifier "group" supports regex only '
                "in combination with a name regex identifier.",
            )

        raise AppError(
            "Invalid set file",
            f'The update object identifier "{id_field}" does not support regex.',
        )


def _parse_regex_update_identity(
    update_id: t.Mapping[str, t.Any],
) -> t.Optional[t.Union[RegexUpdateIdentity, CoordinatesRegexIdentity]]:
    if not isinstance(update_id, t.Mapping):
        return None

    name_result = _parse_coordinates_regex(update_id)
    simple_result = _parse_simple_regex(update_id)

    if name_result is not None and simple_result is not None:
        raise AppError(
            "Invalid set file",
            f"The update object with id {dict(update_id)} has more than one id.",
        )

    if name_result is not None:
        return name_result

    if simple_result is not None:
        return simple_result

    _reject_unsupported_id_dicts(update_id)
    return None


_AnyRegexIdentity = t.Union[RegexUpdateIdentity, CoordinatesRegexIdentity]


def _get_regex_targets(sbom: dict, update_id: _AnyRegexIdentity) -> list[dict]:
    targets: list[dict] = []

    def _collect(component: dict, target_list: list[dict], target_id: _AnyRegexIdentity) -> None:
        if target_id.matches(component):
            target_list.append(component)

    walk_components(sbom, _collect, targets, update_id)
    return targets


def _validate_update_list(updates: t.Sequence[dict[str, t.Any]], ctx: Context) -> None:
    if len(updates) == 0:
        logger.debug("No updates to perform. This is probably wrong but what do I know.")
        return

    for upd in updates:
        if "id" not in upd:
            raise AppError("Invalid set file", "An update object is missing the 'id' property.")
        if (
            isinstance(upd["id"], t.Mapping)
            and "version" in upd["id"]
            and "version-range" in upd["id"]
        ):
            raise AppError(
                "Invalid set file",
                "An update object contains a 'version' and 'version-range' but only "
                "one of them is permitted.",
            )

        regex_component_id = _parse_regex_update_identity(upd["id"])
        component_id: t.Union[ComponentIdentity, RegexUpdateIdentity, CoordinatesRegexIdentity]

        if regex_component_id is None:
            try:
                component_id = UpdateIdentity.create(upd["id"], True)
            except (
                univers.versions.InvalidVersion,
                ValueError,
                TypeError,
                KeyError,
            ) as exc:
                raise AppError(
                    "Invalid set file",
                    f"An update object has an invalid identifier: {exc}",
                ) from exc
        else:
            component_id = regex_component_id

        upd["id"] = component_id

        if not isinstance(component_id, (RegexUpdateIdentity, CoordinatesRegexIdentity)):
            if len(component_id) == 0:
                raise AppError("Invalid set file", "An update object has an empty 'id' property.")
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
    except AppError as exc:
        raise AppError(
            "Set not performed",
            f"Invalid update record: {exc.details.description}",
            log_msg=exc.details,
        ) from exc

    ctx.component_map = _map_out_components(sbom)

    for update in updates:
        target_list: list[dict] = []
        update_id = update["id"]

        if isinstance(update_id, (RegexUpdateIdentity, CoordinatesRegexIdentity)):
            target_list = _get_regex_targets(sbom, update_id)
        else:
            update_key = update_id[0]
            if isinstance(update_key.key, CoordinatesWithVersionRange):
                for key in ctx.component_map.keys():
                    if update_key == key:
                        target_list += ctx.component_map[key]
            elif update_key in ctx.component_map:
                target_list = ctx.component_map[update_key]

        if len(target_list) == 0:
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

        for target in target_list:
            _do_update(target, update, ctx)
