# SPDX-License-Identifier: GPL-3.0-or-later

import functools
import json
import typing as t
from dataclasses import dataclass
from enum import Enum
from cdxev.auxiliary.version_processing import VersionRange
from cdxev.error import AppError
import re


@functools.total_ordering
class KeyType(Enum):
    CPE = 1
    PURL = 2
    SWID = 3
    COORDINATES = 4

    def __lt__(self, other: "KeyType") -> bool:
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


@dataclass(init=True, frozen=True, eq=True)
class Key:
    """
    Represents a key which identifies a component.

    CycloneDX SBOMs can contain several kinds of keys, which are not compatible with each other.
    Therefore, two keys are only considered equal if the kind of key as well as the key's content
    are equal.

    Key equality is naively implemented as string or deep dict equality and **does not take
    key-type-specific considerations into account**. For instance, the algorithms for matching CPEs
    against each other are officially specified in a document of several dozen pages. This class
    simply checks whether both strings are the same. The same goes for SWID and PURL.
    """

    type: KeyType
    key: t.Any

    def __str__(self) -> str:
        return f"{self.type.name}[{self.key}]"

    @classmethod
    def from_cpe(cls, cpe: str) -> "Key":
        return cls(KeyType.CPE, cpe)

    @classmethod
    def from_purl(cls, purl: str) -> "Key":
        return cls(KeyType.PURL, purl)

    @classmethod
    def from_swid(cls, swid: t.Union[t.Mapping, str]) -> "Key":
        if isinstance(swid, t.Mapping):
            return cls(KeyType.SWID, SWID(swid))
        elif isinstance(swid, str):
            swid_dict = json.loads(swid)
            return cls(KeyType.SWID, SWID(swid_dict))
        else:
            raise ValueError("swid must be either a Mapping or a str.")

    @classmethod
    def from_coordinates(
        cls,
        *,
        name: str,
        group: t.Optional[str] = None,
        version: t.Optional[str] = None,
    ) -> "Key":
        coordinates = Coordinates(name, group, version)
        return cls(KeyType.COORDINATES, coordinates)


class SWID(dict):
    """
    SWIDs are a complex construct which can contain a lot of information.

    Fortunately, a single property of an SWID is both mandatory and unique: the tagId.
    """

    def __str__(self) -> str:
        return "tagId: " + self["tagId"]

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SWID) and self["tagId"] == other["tagId"]

    def __hash__(self) -> int:  # type: ignore[override]
        return self["tagId"].__hash__()


@dataclass(init=True, frozen=True, eq=True)
class Coordinates:
    name: str
    group: t.Optional[str]
    version: t.Optional[str]

    def __str__(self) -> str:
        group_str = (self.group + "/") if self.group is not None else ""
        version_str = ("@" + self.version) if self.version is not None else ""
        return group_str + self.name + version_str


@dataclass(frozen=True)
class ComponentIdentity:
    """
    Represents the component identity as a set of identifying keys.

    A component can have more than one key. For two identities to be considered equal, at least
    one of their keys must be equal.
    An empty identity (which doesn't contain any keys) can never be equal to any other identity,
    even another empty one.

    Instances of this class are immutable.
    """

    _keys: t.Tuple[Key]

    def __init__(self, *keys: t.Optional[Key]):
        filtered = (key for key in keys if key is not None)
        sorted_keys = sorted(filtered, key=lambda k: k.type)
        keyset = tuple(sorted_keys)
        object.__setattr__(self, "_keys", keyset)

    def __getitem__(self, key: int) -> Key:
        return self._keys[key]

    def __iter__(self) -> t.Iterator[Key]:
        return self._keys.__iter__()

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ComponentIdentity) and any(
            k in self._keys for k in other._keys
        )

    def __str__(self) -> str:
        return str(self._keys[0]) if len(self) > 0 else ""

    def __len__(self) -> int:
        return len(self._keys)

    def __contains__(self, item: Key) -> bool:
        return item in self._keys

    @classmethod
    def create(
        cls, component: t.Mapping[str, t.Any], allow_unsafe: bool = False
    ) -> "ComponentIdentity":
        """
        Creates a :py:class:`.ComponentIdentity` for the given component.

        The identity will contain all keys specified on the component.

        If the `allow_unsafe` argument is set to `True`, then component properties will be taken
        into account for identification which might not enforce strict identity.

        This function considers as *safe*:

        * *purl*
        * *cpe*
        * *swid*

        The following are considered *unsafe*:

        * package coordinates, i.e. the combination of *name*, *group* and *version*

        :param component: one component dictionary from sbom["components"]

        :param bool allow_unsafe: If set to true, *unsafe* keys will also be added to the returned
                                    identity.

        :returns: The `ComponentIdentity`.
        """
        cpe = Key.from_cpe(component["cpe"]) if "cpe" in component else None
        purl = Key.from_purl(component["purl"]) if "purl" in component else None
        swid = Key.from_swid(component["swid"]) if "swid" in component else None

        if allow_unsafe and "name" in component:
            coordinates = Key.from_coordinates(
                name=component["name"],
                group=component.get("group"),
                version=component.get("version"),
            )
        else:
            coordinates = None

        return ComponentIdentity(cpe, purl, swid, coordinates)


@dataclass(frozen=True)
class UpdateIdentity(ComponentIdentity):
    _version_range: t.Union[VersionRange | None]
    has_version_range: bool

    def __init__(self, *keys: t.Optional[Key], version_range: t.Optional[VersionRange] = None):
        filtered = (key for key in keys if key is not None)
        sorted_keys = sorted(filtered, key=lambda k: k.type)
        keyset = tuple(sorted_keys)
        has_version_range = False
        if version_range is not None:
            has_version_range = True
        object.__setattr__(self, "_keys", keyset)
        object.__setattr__(self, "_version_range", version_range)
        object.__setattr__(self, "has_version_range", has_version_range)

    @classmethod
    def create(
        cls, update: t.Mapping[str, t.Any], allow_unsafe: bool = False
    ) -> "UpdateIdentity":  # TODO adapt description!
        """
        Creates a :py:class:`.UpdateIdentity` for the given component.

        The identity will contain all keys specified on the component.

        If the `allow_unsafe` argument is set to `True`, then component properties will be taken
        into account for identification which might not enforce strict identity.

        This function considers as *safe*:

        * *purl*
        * *cpe*
        * *swid*

        The following are considered *unsafe*:

        * package coordinates, i.e. the combination of *name*, *group* and *version*

        :param component: one component dictionary from sbom["components"]

        :param bool allow_unsafe: If set to true, *unsafe* keys will also be added to the returned
                                    identity.

        :returns: The `ComponentIdentity`.
        """
        cpe = Key.from_cpe(update["cpe"]) if "cpe" in update else None
        purl = Key.from_purl(update["purl"]) if "purl" in update else None
        swid = Key.from_swid(update["swid"]) if "swid" in update else None

        if allow_unsafe and "name" in update:
            coordinates = Key.from_coordinates(
                name=update["name"],
                group=update.get("group"),
                version=update.get("version"),
            )
        else:
            coordinates = None

        version_range = None
        version_str = update.get("version", "")
        if re.match('^range:.*', version_str):
            if re.fullmatch('^range:.*/.*', version_str):
                version_range = VersionRange(version_str[version_str.find(":") + 1:])
            else:
                raise AppError(
                    message="Provided version range does not match the required schema",
                    description=(
                        f'The provided version range: {update.get("version", "")} does'
                        ' not match the required schema "^range:.*/.*".'
                    ),
                )
        return UpdateIdentity(cpe, purl, swid, coordinates, version_range=version_range)

    def __str__(self) -> str:
        return str(self._keys[0]) if len(self) > 0 else ""

    def __eq__(self, other: object) -> bool:
        return (isinstance(other, UpdateIdentity) and any(
            k in self._keys for k in other._keys
        ) and self._version_range == other._version_range)

    def is_target_in_version_range(self, identity: Key) -> bool:
        if self._version_range is None:
            return False
        # only one identity specifier is allowed, so its has to be Coordinates, if it exists
        update_name = self.__getitem__(0).key.name
        update_group = self.__getitem__(0).key.group
        if identity.type == KeyType.COORDINATES:
            component_name = identity.key.name
            component_group = identity.key.group
            component_version = identity.key.version
        else:
            return False

        if update_name != component_name:
            return False

        if (
            update_group != component_group
            and update_group is not None
        ):
            return False

        version_range = self._version_range
        if not version_range.version_string_is_in_range(component_version):
            return False

        return True
