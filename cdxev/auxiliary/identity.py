# SPDX-License-Identifier: GPL-3.0-or-later

import functools
import json
import logging
import re
import typing as t
from dataclasses import dataclass, fields
from enum import Enum

import univers.version_range
import univers.versions

from cdxev.log import LogMessage


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
        return "tagId: " + str(self["tagId"])

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SWID) and self["tagId"] == other["tagId"]

    def __hash__(self) -> int:  # type: ignore[override]
        return self["tagId"].__hash__()  # type: ignore


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
        return isinstance(other, ComponentIdentity) and any(k in self._keys for k in other._keys)

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
class RegexUpdateIdentity:
    field: str
    expression: str
    pattern: re.Pattern[str]

    @classmethod
    def create(cls, field: str, expression: str) -> "RegexUpdateIdentity":
        return cls(field=field, expression=expression, pattern=re.compile(f"^(?:{expression})$"))

    def matches(self, component: dict) -> bool:
        value = component.get(self.field)
        return isinstance(value, str) and self.pattern.fullmatch(value) is not None

    def __str__(self) -> str:
        return f"{self.field}[regex:{self.expression}]"


@dataclass(init=True, frozen=True)
class CoordinatesWithVersionRange(Coordinates):
    """
    This class inherits from cdxev.auxiliary.identity.Coordinates
    and extends it to be able to handle version ranges.
    It achieves this by introducing the attribute 'version_range'
    of type univers.version_range.VersionRange.

    This class's comparator is compatible with Coordinates objects.
    If the 'name' and 'group' match,
    it will check if the provided version of the coordinates object
    is contained in this class instance's 'version_range'
    and return True or False depending on the result.
    """

    version_range: univers.version_range.VersionRange

    def __eq__(self, other: object) -> bool:
        if t.TYPE_CHECKING:
            # univers guarantees that version_class is not None
            assert self.version_range.version_class is not None  # nosec - only for type checker

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
                try:
                    if self.version_range.version_class(other.version) in self.version_range:
                        return True
                except univers.versions.InvalidVersion:
                    possible_versions = []
                    for version_type in univers.versions.AVAILABLE_VERSIONS:
                        try:
                            if version_type.is_valid(other.version):
                                possible_versions.append(str(version_type.__name__))
                        except univers.versions.nuget.InvalidNuGetVersion:
                            pass
                    version_is_of = " which is valid under the schemas: "

                    if not possible_versions:
                        version_is_of = "which versioning schema is not supported"
                    else:
                        for version in possible_versions:
                            version_is_of += version + ", "
                        version_is_of = version_is_of[:-2]
                    logger = logging.getLogger(__name__)
                    logger.warning(
                        LogMessage(
                            "Incompatible version ranges",
                            f"The component {other} matches the target {self}"
                            f" in the name and group keys but has a different versioning"
                            f" schema. The target has versioning schema"
                            f' "{self.version_range.version_class.__name__}"'
                            f' this is incompatible with the version "{other.version}"'
                            + version_is_of,
                        )
                    )
                    return False

        return False

    def __str__(self) -> str:
        group_str = (f"{self.group}/") if self.group is not None else ""
        version_str = (f"@{self.version_range}") if self.version_range is not None else ""
        return group_str + self.name + version_str


@dataclass(frozen=True)
class CoordinatesRegexIdentity:
    """
    Matches components by a regex on *name*, optionally narrowed by
    *group* (literal string or regex), *version* (exact), or *version-range*.
    """

    name_expression: str
    name_pattern: re.Pattern[str]
    group_expression: t.Optional[str]
    group_pattern: t.Optional[re.Pattern[str]]
    version: t.Optional[str]
    version_range: t.Optional[univers.version_range.VersionRange]

    @classmethod
    def create(
        cls,
        name_expression: str,
        group_expression: t.Optional[str] = None,
        group_is_regex: bool = False,
        version: t.Optional[str] = None,
        version_range: t.Optional[univers.version_range.VersionRange] = None,
    ) -> "CoordinatesRegexIdentity":
        name_pattern = re.compile(f"^(?:{name_expression})$")
        if group_expression is not None:
            grp_str = (
                f"^(?:{group_expression})$"
                if group_is_regex
                else f"^{re.escape(group_expression)}$"
            )
            group_pat: t.Optional[re.Pattern[str]] = re.compile(grp_str)
        else:
            group_pat = None
        return cls(
            name_expression=name_expression,
            name_pattern=name_pattern,
            group_expression=group_expression,
            group_pattern=group_pat,
            version=version,
            version_range=version_range,
        )

    def matches(self, component: dict) -> bool:
        name = component.get("name")
        if not isinstance(name, str) or not self.name_pattern.fullmatch(name):
            return False

        if self.group_pattern is not None:
            comp_group = component.get("group")
            if not isinstance(comp_group, str) or not self.group_pattern.fullmatch(comp_group):
                return False

        if self.version is not None:
            if component.get("version") != self.version:
                return False

        if self.version_range is not None:
            if t.TYPE_CHECKING:
                assert self.version_range.version_class is not None  # nosec
            comp_version = component.get("version")
            if comp_version is None:
                return False
            try:
                if self.version_range.version_class(comp_version) not in self.version_range:
                    return False
            except univers.versions.InvalidVersion:
                return False

        return True

    def __str__(self) -> str:
        group_str = f"/{self.group_expression}" if self.group_expression is not None else ""
        if self.version is not None:
            ver_str = f"@{self.version}"
        elif self.version_range is not None:
            ver_str = f"@{self.version_range}"
        else:
            ver_str = ""
        return f"name[regex:{self.name_expression}]{group_str}{ver_str}"


@dataclass(frozen=True, init=True)
class VulnerabilityIdentity:
    id: str
    aliases: list[str]

    @classmethod
    def from_vulnerability(cls, vulnerability: dict) -> "VulnerabilityIdentity":
        id = vulnerability.get("id", "")
        aliases = cls.get_ids_from_vulnerability(vulnerability)
        return cls(id, aliases)

    @classmethod
    def from_string(cls, id: str) -> "VulnerabilityIdentity":
        aliases = id.split("_|_")
        return cls(aliases[0], aliases)

    @classmethod
    def get_ids_from_vulnerability(cls, vulnerability: dict) -> list[str]:
        ids_vulnerability: list[str] = []

        primary_id = vulnerability.get("id", None)
        references = vulnerability.get("references", [])

        if primary_id is not None:
            ids_vulnerability.append(primary_id)

        for reference in references:
            id = reference.get("id", None)
            if id is not None and id not in ids_vulnerability:
                ids_vulnerability.append(id)

        return ids_vulnerability

    def id_is_in(self, other_id: str) -> bool:
        if other_id == self.id:
            return True

        if other_id in self.aliases:
            return True
        else:
            return False

    def one_of_ids_is_in(self, other_ids: list[str]) -> bool:
        for id in other_ids:
            if id == self.id:
                return True
            if id in self.aliases:
                return True
        return False

    def __eq__(self, other: object) -> bool:
        """
        Compares two vulnerability objects based on the described vulnerability.
        Fields like affects or analysis are not taken into account.
        """
        if not isinstance(other, VulnerabilityIdentity):
            raise TypeError(f"Can not compare {type(other)} with VulnerabilityIdentity")
        return self.one_of_ids_is_in(other.aliases)

    def __str__(self) -> str:
        if id not in self.aliases:  # type: ignore[comparison-overlap]
            string = self.id
        for ref in self.aliases:
            if ref not in string:
                string += "_|_" + ref
        return string

    def string(self) -> str:
        return self.__str__()
