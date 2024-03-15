import semver
import re
from cdxev.error import AppError


class version:
    def __init__(self, version: str, type: str):
        self.version_string = version
        self.version_type = type


class VersionConstraint:
    _lesser_then: bool = False
    _lesser_equal: bool = False
    _greater_then: bool = False
    _greater_equal: bool = False
    _version_schema = "undefined"

    def __init__(
        self,
        version: str,
        lesser_then: bool = False,
        lesser_equal: bool = False,
        greater_then: bool = False,
        greater_equal: bool = False,
    ) -> None:
        self._input = version
        self._lesser_then = lesser_then
        self._lesser_equal = lesser_equal
        self._greater_then = greater_then
        self._greater_equal = greater_equal
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
        if (
            self._lesser_then
            or self._lesser_equal
        ):
            return True
        else:
            return False

    def is_lower_limit(self) -> bool:
        if (
            self._greater_then
            or self._greater_equal
        ):
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
    _version_schema = "semver"

    def parse_version_schema(self) -> semver.Version:
        return semver.Version.parse(self.version_string)

    def __lt__(self, other: object) -> bool:
        if semver.Version.compare(self.version, other.version) == -1:  # type:ignore
            return True
        else:
            return False

    def __le__(self, other: object) -> bool:
        if (
            semver.Version.compare(self.version, other.version) == -1  # type:ignore
            or semver.Version.compare(self.version, other.version) == 0  # type:ignore
        ):  # type:ignore
            return True
        else:
            return False

    def __gt__(self, other: object) -> bool:
        if semver.Version.compare(self.version, other.version) == 1:  # type:ignore
            return True
        else:
            return False

    def __ge__(self, other: object) -> bool:
        if (
            semver.Version.compare(self.version, other.version) == 1  # type:ignore
            or semver.Version.compare(self.version, other.version) == 0  # type:ignore
        ):  # type:ignore
            return True
        else:
            return False


class VersionConstraintCalVer(VersionConstraint):
    _version_schema = "calver"

    def check_regex(self, version_string: str) -> None:
        if not re.fullmatch("[0-9]+([-.][0-9]+)*", version_string):
            raise AppError(
                "Version schema not valid",
                (
                    f'The version {version_string} is not according '
                    f'to "[0-9]+([-.][0-9]+)*"'
                ),
            )

    def compare(self, version_1: VersionConstraint, version_2: VersionConstraint) -> int:
        self.check_regex(version_1.version_string)
        self.check_regex(version_2.version_string)

        for n in range(min(len(version_1.version), len(version_2.version))):  # type:ignore
            if version_1.version[n] > version_2.version[n]:  # type:ignore
                return 1
            elif version_1.version[n] < version_2.version[n]:  # type:ignore
                return -1

        if len(version_1.version) == len(version_2.version):  # type:ignore
            return 0
        elif len(version_1.version) > len(version_2.version):  # type:ignore
            return 1
        else:
            return -1

    def __lt__(self, other: object) -> bool:
        if self.compare(self, other) == -1:  # type:ignore
            return True
        return False

    def __le__(self, other: object) -> bool:
        if (
            self.compare(self, other) == -1  # type:ignore
            or self.compare(self, other) == 0  # type:ignore
        ):
            return True
        return False

    def __gt__(self, other: object) -> bool:
        if self.compare(self, other) == 1:  # type:ignore
            return True
        return False

    def __ge__(self, other: object) -> bool:
        if (
            self.compare(self, other) == 1  # type:ignore
            or self.compare(self, other) == 0  # type:ignore
        ):
            return True
        return False

    def parse_version_schema(self) -> list:
        self.check_regex(self.version_string)
        version_list = []
        lower_limit = 0
        for index, symbol in enumerate(self.version_string):
            if symbol == "." or symbol == "-":
                version_list.append(int(self.version_string[lower_limit:index]))
                lower_limit = index + 1
        version_list.append(int(self.version_string[lower_limit:]))
        return version_list


class VersionRange:
    _supported_schemata = ["semver", "calver"]

    def __init__(self, range: str):
        self._versioning_scheme = ""
        self._version_constraints: list[str] = []
        self._sorted_versions: list[object] = []
        self._sub_ranges: list[dict] = []

        # TODO check if range is  a valid expression
        self._versioning_scheme = range[: range.find("/")]
        self._version_constraints = range[range.find("/") + 1 :].split("|")

        self._version_objects = self._create_version_from_constraints()
        self._sort_versions()
        self._extract_sub_ranges()

    def __str__(self) -> str:
        print_string = self._versioning_scheme + "/"
        for constraint in self._version_objects:
            print_string += constraint.__str__() + "|"
        return print_string[:-1]

    def get_versioning_scheme(self) -> str:
        return self._versioning_scheme

    def get_version_constraints(self) -> list[str]:
        return self._version_constraints

    def _create_version_from_constraints(
            self
    ) -> list[VersionConstraintSemver | VersionConstraintCalVer]:
        VersionClass: VersionConstraintSemver | VersionConstraintCalVer
        if self._versioning_scheme == "calver":
            VersionClass = VersionConstraintCalVer  # type:ignore
        elif self._versioning_scheme == "semver":
            VersionClass = VersionConstraintSemver  # type:ignore
        else:
            raise AppError(
                "Version schema not supported",
                (
                    f'The versioning schema {self._versioning_scheme} is not supported.'
                ),
            )

        list_of_version_objects = []
        for constraint in self._version_constraints:
            list_of_version_objects.append(VersionClass(constraint))  # type:ignore
        return list_of_version_objects

    def _sort_versions(self) -> None:
        n = len(self._version_objects)
        for i in range(n):
            already_sorted = True
            for j in range(n - i - 1):
                if self._version_objects[j] > self._version_objects[j + 1]:  # type:ignore
                    self._version_objects[j], self._version_objects[j + 1] = (  # type:ignore
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
        while (index < len(self._version_objects) and counter < len(self._version_objects)):
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
                        "is_fixed_version": True
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
                        "is_fixed_version": False
                    }
                )

    def version_is_in(self, version: VersionConstraint) -> bool:
        def is_lesser_then_upper_limit(
                upper_limit: VersionConstraint,
                version: VersionConstraint
        ) -> bool:

            if upper_limit._lesser_then:
                if version < upper_limit:
                    return True
            elif upper_limit._lesser_equal:
                if version <= upper_limit:
                    return True
            return False

        def is_greater_then_lower_limit(
                lower_limit: VersionConstraint,
                version: VersionConstraint
        ) -> bool:

            if lower_limit._greater_then:
                if version > lower_limit:
                    return True
            elif lower_limit._greater_equal:
                if version >= lower_limit:
                    return True
            return False

        if not version.get_versioning_schema() == self._versioning_scheme:
            raise AppError(
                "Incompatible version schemes",
                (
                    f'The scheme {version.get_versioning_schema()} of the provided '
                    f'software version does not match the versions'
                    f' in the ranges provided "{self.get_versioning_scheme()}".'
                ),
            )
        for sub_range in self._sub_ranges:
            is_in = True
            if sub_range.get("is_fixed_version", False):
                if not version == sub_range.get(
                    "fixed_version",
                    VersionConstraint("0.0.0")
                ):
                    is_in = False

            if sub_range.get("has_lower_limit", False):
                lower_limit = sub_range.get(
                    "lower_limit",
                    VersionConstraint("0.0.0")
                )
                if not is_greater_then_lower_limit(lower_limit, version):
                    is_in = False

            if sub_range.get("has_upper_limit", False):
                upper_limit = sub_range.get(
                    "upper_limit",
                    VersionConstraint("0.0.0")
                )
                if not is_lesser_then_upper_limit(upper_limit, version):
                    is_in = False
            if is_in:
                return True
        return False
