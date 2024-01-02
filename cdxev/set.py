import logging
import pathlib
import sys
import typing as t
from dataclasses import dataclass, field

from cdxev.auxiliary.identity import ComponentIdentity, Key
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
        component_id = ComponentIdentity.create(upd["id"], True)
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
        target_list: list[dict]
        try:
            target_list = ctx.component_map[update["id"][0]]
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
