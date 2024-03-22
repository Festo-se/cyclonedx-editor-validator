import re
import typing as t
import logging
from cdxev.error import AppError, InputFileError
from packaging import version as pack_ver
from pathlib import Path
import json
import copy


logger = logging.getLogger(__name__)


class IncompatibleVersionError(AppError):
    """Indicates that the software version schemas are not compatible under a given operation."""


class UnsupportedVersionError(AppError):
    """Indicates that software versions with the provided schema are not supported."""


def throw_incompatible_version_error(
    own_version_schema: str, other_version_schema: str
) -> None:
    raise IncompatibleVersionError(
        message="Versions of different type cannot be compared",
        description=(
            f'The compared versions are of type "{own_version_schema}" and'
            f' "{other_version_schema}"'  # type:ignore
            "no order operator for different version types is implemented"
        ),
    )


def throw_unsupported_version_error(version: str) -> None:
    raise UnsupportedVersionError(
        message="Version schema not supported",
        description=(
            f"The version {version}"
            f" does not belong to any supported schemas or provided custom schemas"
        ),
    )


class version:
    def __init__(self, version: str, type: str):
        self.version_string = version
        self._version_schema = type


class VersionConstraint:
    _version_schema = "undefined"

    def __init__(
        self,
        version: str,
    ) -> None:
        self._lesser_then: bool = False
        self._lesser_equal: bool = False
        self._greater_then: bool = False
        self._greater_equal: bool = False

        self._input = version
        self.version_string = self._parse_version(version)
        self.version = self.parse_version_schema()

    def __str__(self) -> str:
        if self._lesser_then:
            return "<" + self.version_string
        elif self._lesser_equal:
            return "<=" + self.version_string
        elif self._greater_equal:
            return ">=" + self.version_string
        elif self._greater_then:
            return ">" + self.version_string
        else:
            return self.version_string

    def __eq__(self, other: object) -> bool:
        try:
            if (
                self.version_string == other.version_string  # type:ignore
                and self._lesser_then == other._lesser_then  # type:ignore
                and self._lesser_equal == other._lesser_equal  # type:ignore
                and self._greater_then == other._greater_then  # type:ignore
                and self._greater_equal == other._greater_equal  # type:ignore
                and self._version_schema == other._version_schema  # type:ignore
            ):
                return True
            else:
                return False
        except:
            return False

    def __lt__(self, other: object) -> bool:
        return False

    def __le__(self, other: object) -> bool:
        return False

    def __gt__(self, other: object) -> bool:
        return False

    def __ge__(self, other: object) -> bool:
        return False

    def parse_version_schema(self) -> object:
        return self.version_string

    def _parse_version(self, version: str) -> str:
        if "<=" in version:
            self._lesser_equal = True
            return version.replace("<=", "")
        elif ">=" in version:
            self._greater_equal = True
            return version.replace(">=", "")
        elif "<" in version:
            self._lesser_then = True
            return version.replace("<", "")
        elif ">" in version:
            self._greater_then = True
            return version.replace(">", "")
        else:
            return version

    def is_upper_limit(self) -> bool:
        if self._lesser_then or self._lesser_equal:
            return True
        else:
            return False

    def is_lower_limit(self) -> bool:
        if self._greater_then or self._greater_equal:
            return True
        else:
            return False

    def is_fixed_version(self) -> bool:
        if (
            self._lesser_then is False
            and self._lesser_equal is False
            and self._greater_then is False
            and self._greater_equal is False
        ):
            return True
        else:
            return False

    def get_versioning_schema(self) -> str:
        return self._version_schema


class VersionConstraintSemver(VersionConstraint):
    """
    Class to describe a constraint for a software version.

    Attributes
    ----------
    version_string : str
        the version string of the version defining this constraint
    version : packaging.Version
        version object generated from the submitted version

        _input: str
            the version constraint string provided as input
        _lesser_then: bool
            a variable describing if the associated constraint of the version is <
        _lesser_equal: bool
            a variable describing if the associated constraint of the version is <=
        _greater_then: bool
            a variable describing if the associated constraint of the version is >
        _greater_equal: bool
            a variable describing if the associated constraint of the version is >=

    """
    _version_schema = "semver"

    def parse_version_schema(self) -> pack_ver.Version:
        return pack_ver.parse(self.version_string)

    def __lt__(self, other: object) -> bool:
        if self.version < other.version:  # type:ignore
            return True
        else:
            return False

    def __le__(self, other: object) -> bool:
        if self.version <= other.version:  # type:ignore
            return True
        else:
            return False

    def __gt__(self, other: object) -> bool:
        if self.version > other.version:  # type:ignore
            return True
        else:
            return False

    def __ge__(self, other: object) -> bool:
        if self.version >= other.version:  # type:ignore
            return True
        else:
            return False

    @staticmethod
    def is_semver_version(version: str) -> bool:
        try:
            pack_ver.parse(version)
            is_semver = True
        except pack_ver.InvalidVersion:
            is_semver = False
        return is_semver


class CustomVersionData:
    """
    Class storing the data for software versions provided by the user.
    The input is a path to a file containing the information about the versions.
    The file has to be of the form:

    [
        {
            "name: "Name of the versioning",
            "version_list": [
                Ordered list of the software versions
            ]
        }
    ]

    The "version_type" field is a identifier for the versioning schema.
    The "version_list" is a list of all the software versions,
    beginning with the lowest up to the highest.
    """

    _custom_versions: dict[str, t.Any] = {}

    @classmethod
    def get_data(cls) -> dict:
        return copy.deepcopy(cls._custom_versions)

    @classmethod
    def version_is_in_custom_versions(cls, version: str) -> tuple[bool, str]:
        matched_schema = False
        schema = ""
        for version_schema in cls._custom_versions.keys():
            if version in cls._custom_versions[version_schema]:
                matched_schema = True
                schema = version_schema
        return matched_schema, schema

    def __init__(self, path_to_file: t.Union[Path, None]):
        if isinstance(path_to_file, Path):
            schema_data = self.read_schema_data_from_file(path_to_file)
            self.add_data_to_custom_versions(schema_data)

    def add_data_from_file(self, path_to_file: Path) -> None:
        schema_data = self.read_schema_data_from_file(path_to_file)
        self.add_data_to_custom_versions(schema_data)

    def add_data_from_list(self, list_of_schema_data: list) -> None:
        self.add_data_to_custom_versions(list_of_schema_data)

    def add_data_from_dict(self, schema_data_dict: dict) -> None:
        schema_data = [schema_data_dict]
        self.add_data_to_custom_versions(schema_data)

    def read_schema_data_from_file(self, path_to_file: Path) -> list:
        with open(path_to_file, "r") as from_file:
            try:
                schema_data = json.load(from_file)
            except json.JSONDecodeError as ex:
                raise InputFileError(
                    "Invalid JSON passed to --custom_versions",
                    None,
                    ex.lineno,
                ) from ex

        # Check the format of the input file
        if isinstance(schema_data, dict):
            schema_data = [schema_data]

        return schema_data

    @classmethod
    def add_data_to_custom_versions(cls, schema_data: list) -> None:
        if len(schema_data) == 0:
            return

        for schema in schema_data:
            if not (
                "version_type" in schema.keys() and "version_list" in schema.keys()
            ):
                raise AppError(
                    message="Invalid format",
                    description=(
                        f"The provided schema {schema} is not according to the specified format."
                        '"version_type" and "version_list" are required properties.'
                    ),
                )
            if not (
                isinstance(schema["version_type"], str)
                and isinstance(schema["version_list"], list)
            ):
                raise AppError(
                    message="Inavlid type",
                    description=(
                        '"version_type" has to be of type "str" and "version_list" of type "list".'
                    ),
                )
        if schema["version_type"] in cls._custom_versions.keys():
            logger.info(
                (
                    f'The version schema "{schema["version_type"]}"'
                    "existed already and will be overwritten"
                )
            )
        cls._custom_versions[schema["version_type"]] = schema["version_list"]


class VersionConstraintCustom(VersionConstraint):
    def __init__(self, version: str, version_type: str) -> None:
        if not CustomVersionData.version_is_in_custom_versions(version):
            throw_unsupported_version_error(version)
        self._input = version
        self._lesser_then = False
        self._lesser_equal = False
        self._greater_then = False
        self._greater_equal = False
        self._version_schema = version_type
        self.version_string = self._parse_version(version)
        self.version = self.parse_version_schema()

    def get_index(self, version: str) -> int:
        if version in CustomVersionData.get_data().get(self._version_schema, []):
            return (
                CustomVersionData.get_data()
                .get(self._version_schema, [])
                .index(version)
            )
        else:
            throw_unsupported_version_error(version)
            return 1

    def __eq__(self, other: object) -> bool:
        try:
            if (
                self.version_string == other.version_string  # type:ignore
                and self._lesser_then == other._lesser_then  # type:ignore
                and self._lesser_equal == other._lesser_equal  # type:ignore
                and self._greater_then == other._greater_then  # type:ignore
                and self._greater_equal == other._greater_equal  # type:ignore
                and self._version_schema == other._version_schema  # type:ignore
                and self._version_schema == other._version_schema  # type:ignore
            ):
                return True
            else:
                return False
        except:
            return False

    def __lt__(self, other: object) -> bool:
        if self._version_schema != other._version_schema:  # type:ignore
            throw_incompatible_version_error(
                self._version_schema, other._version_schema  # type:ignore
            )
        own_index = self.get_index(self.version)  # type:ignore
        other_index = other.get_index(other.version)  # type:ignore
        if own_index < other_index:
            return True
        else:
            return False

    def __le__(self, other: object) -> bool:
        if self._version_schema != other._version_schema:  # type:ignore
            throw_incompatible_version_error(
                self._version_schema, other._version_schema  # type:ignore
            )
        own_index = self.get_index(self.version)  # type:ignore
        other_index = other.get_index(other.version)  # type:ignore
        if own_index <= other_index:
            return True
        else:
            return False

    def __gt__(self, other: object) -> bool:
        if self._version_schema != other._version_schema:  # type:ignore
            throw_incompatible_version_error(
                self._version_schema, other._version_schema  # type:ignore
            )
        own_index = self.get_index(self.version)  # type:ignore
        other_index = other.get_index(other.version)  # type:ignore
        if own_index > other_index:
            return True
        else:
            return False

    def __ge__(self, other: object) -> bool:
        if self._version_schema != other._version_schema:  # type:ignore
            throw_incompatible_version_error(
                self._version_schema, other._version_schema  # type:ignore
            )
        own_index = self.get_index(self.version)  # type:ignore
        other_index = other.get_index(other.version)  # type:ignore
        if own_index >= other_index:
            return True
        else:
            return False


class VersionRange:
    """
    Class to describe a version range.
    A instance of this class contains a one or more sub ranges
    that define what versions fall into this range and functions to verify,
    if a specific version is in the represented version range.
    """

    _supported_schemas = ["semver", "custom"]

    def __init__(self, range: str):
        self._versioning_schema = ""
        self._version_constraints: list[str] = []
        self.regular_constraints: list[str] = []
        self._sorted_versions: list[object] = []
        self._sub_ranges: list[dict] = []
        self.regex_constraints: list = []

        self.all_versions = False
        # TODO check if range is  a valid expression
        if range[-1] == "|":
            range = range[:-1]
        self._version_constraints = range.split("|")
        self.process_constraints(range)
        self._version_objects = self._create_version_from_constraints()
        self._sort_versions()
        self._extract_sub_ranges()

    def process_constraints(self, range: str) -> None:
        for constraint in self._version_constraints:
            if constraint.find("*") != -1:
                regex_string = constraint.replace(".", "\\.")
                regex_string = regex_string.replace("*", ".*")
                regex = re.compile(regex_string)
                self.regex_constraints.append(regex)
            else:
                self.regular_constraints.append(constraint)

    def __str__(self) -> str:
        print_string = ""
        for constraint in self._version_objects:
            print_string += constraint.__str__() + "|"
        for regex in self.regex_constraints:
            print_string += regex.__str__() + "|"
        return print_string[:-1]

    def get_versioning_schema(self) -> str:
        return self._versioning_schema

    def get_version_constraints(self) -> list[str]:
        return self._version_constraints

    def _create_version_from_constraints(
        self,
    ) -> list[VersionConstraintSemver | VersionConstraintCustom]:
        list_of_version_objects: list[
            VersionConstraintSemver | VersionConstraintCustom
        ] = []
        if self.regular_constraints:
            version = self.extract_version_from_constrained(self.regular_constraints[0])
            if VersionConstraintSemver.is_semver_version(version):
                self._versioning_schema = "semver"
                for constraint in self.regular_constraints:
                    list_of_version_objects.append(VersionConstraintSemver(constraint))
            else:
                matched_schema, version_schema = (
                    CustomVersionData.version_is_in_custom_versions(version)
                )
                self._versioning_schema = version_schema
                if matched_schema:
                    for constraint in self.regular_constraints:
                        list_of_version_objects.append(
                            VersionConstraintCustom(
                                version=constraint, version_type=version_schema
                            )  # type:ignore
                        )
                if not matched_schema:
                    throw_unsupported_version_error(version)
        return list_of_version_objects

    def extract_version_from_constrained(self, version_constrained: str) -> str:
        version = version_constrained.replace("<=", "")
        version = version.replace(">=", "")
        version = version.replace(">", "")
        version = version.replace("<", "")
        # remove leading whitespaces
        version = version.lstrip()
        return version

    def _sort_versions(self) -> None:
        n = len(self._version_objects)
        for i in range(n):
            already_sorted = True
            for j in range(n - i - 1):
                if (
                    self._version_objects[j] > self._version_objects[j + 1]
                ):  # type:ignore
                    (
                        self._version_objects[j],
                        self._version_objects[j + 1],
                    ) = (  # type:ignore
                        self._version_objects[j + 1],
                        self._version_objects[j],
                    )
                    already_sorted = False
            if already_sorted:
                break

    def _extract_sub_ranges(self) -> None:
        index = 0
        counter = 0
        upper_limit: object = None
        lower_limit: object = None
        fixed_version: object = None
        has_upper_limit = False
        has_lower_limit = False
        while index < len(self._version_objects) and counter < len(
            self._version_objects
        ):
            counter += 1
            constraint = self._version_objects[index]
            if constraint.is_lower_limit():
                lower_limit = constraint
                fixed_version = None
                upper_limit = None
                has_lower_limit = True
                has_upper_limit = False
                index += 1
                for n in range(index, len(self._version_objects)):
                    if (
                        upper_limit is not None
                        and self._version_objects[n].is_lower_limit()
                    ):
                        break
                    elif self._version_objects[n].is_upper_limit():
                        upper_limit = self._version_objects[n]
                        has_upper_limit = True
                        index = n + 1

            elif constraint.is_upper_limit():
                upper_limit = constraint
                has_upper_limit = True
                fixed_version = None
                index += 1
                for n in range(index, len(self._version_objects)):
                    if (
                        self._version_objects[n].is_lower_limit()
                        or self._version_objects[n].is_fixed_version()
                    ):
                        break
                    elif self._version_objects[n].is_upper_limit():
                        upper_limit = self._version_objects[n]
                        index = n + 1

            if constraint.is_fixed_version():
                fixed_version = self._version_objects[index]
                index += 1
                self._sub_ranges.append(
                    {
                        "upper_limit": None,
                        "lower_limit": None,
                        "fixed_version": fixed_version,
                        "has_upper_limit": False,
                        "has_lower_limit": False,
                        "is_fixed_version": True,
                    }
                )
            else:
                self._sub_ranges.append(
                    {
                        "upper_limit": upper_limit,
                        "lower_limit": lower_limit,
                        "fixed_version": fixed_version,
                        "has_upper_limit": has_upper_limit,
                        "has_lower_limit": has_lower_limit,
                        "is_fixed_version": False,
                    }
                )

    def version_string_is_in_range(self, version: str) -> bool:
        if self._versioning_schema == "semver":
            version_object = VersionConstraintSemver(version)
        else:
            found = False
            for key in CustomVersionData.get_data().keys():
                if version in CustomVersionData.get_data()[key]:
                    found = True
                    version_object = VersionConstraintCustom(
                        version=version, version_type=key
                    )  # type:ignore# type:ignore
            if not found:
                throw_unsupported_version_error(version)
        return self.version_is_in(version_object)

    def version_is_in(self, version: VersionConstraint) -> bool:
        def is_lesser_then_upper_limit(
            upper_limit: VersionConstraint, version: VersionConstraint
        ) -> bool:
            if upper_limit._lesser_then:
                if version < upper_limit:
                    return True
            elif upper_limit._lesser_equal:
                if version <= upper_limit:
                    return True
            return False

        def is_greater_then_lower_limit(
            lower_limit: VersionConstraint, version: VersionConstraint
        ) -> bool:
            if lower_limit._greater_then:
                if version > lower_limit:
                    return True
            elif lower_limit._greater_equal:
                if version >= lower_limit:
                    return True
            return False

        # check that versioning schemas are comparable if regular constraints are provided
        if not (
            version.get_versioning_schema() == self._versioning_schema
            or not self.regular_constraints
        ):
            throw_incompatible_version_error(
                version.get_versioning_schema(), self.get_versioning_schema()
            )

        if self.regex_constraints:
            matches_regex = False
            for regex in self.regex_constraints:
                if regex.fullmatch(version.version_string):
                    matches_regex = True
            if matches_regex and not self._sub_ranges:
                return True
        else:
            matches_regex = True

        for sub_range in self._sub_ranges:
            is_in = True
            if sub_range.get("is_fixed_version", False):
                if not version == sub_range.get(
                    "fixed_version", VersionConstraint("0.0.0")
                ):
                    is_in = False

            if sub_range.get("has_lower_limit", False):
                lower_limit = sub_range.get("lower_limit", VersionConstraint("0.0.0"))
                if not is_greater_then_lower_limit(lower_limit, version):
                    is_in = False

            if sub_range.get("has_upper_limit", False):
                upper_limit = sub_range.get("upper_limit", VersionConstraint("0.0.0"))
                if not is_lesser_then_upper_limit(upper_limit, version):
                    is_in = False
            if is_in and matches_regex:
                return True
        return False
