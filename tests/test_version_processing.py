import unittest
import pathlib

from cdxev.auxiliary import version_processing as verpro_
from cdxev.error import AppError
import re


class TestVersionConstraint(unittest.TestCase):
    def test_compare_function(self) -> None:
        version_constraint_1 = verpro_.VersionConstraint("some_version", lesser_then=True)
        version_constraint_2 = verpro_.VersionConstraint("some_version", lesser_equal=True)
        version_constraint_3 = verpro_.VersionConstraint("some_version", greater_then=True)
        version_constraint_4 = verpro_.VersionConstraint("some_version", greater_equal=True)
        version_constraint_5 = verpro_.VersionConstraint("<some_version")
        version_constraint_6 = verpro_.VersionConstraint("<=some_version")
        version_constraint_7 = verpro_.VersionConstraint(">some_version")
        version_constraint_8 = verpro_.VersionConstraint(">=some_version")
        self.assertTrue(version_constraint_1 == version_constraint_5)
        self.assertTrue(version_constraint_2 == version_constraint_6)
        self.assertTrue(version_constraint_3 == version_constraint_7)
        self.assertTrue(version_constraint_4 == version_constraint_8)
        self.assertFalse(version_constraint_1 == version_constraint_2)
        self.assertFalse(version_constraint_1 == version_constraint_3)
        self.assertFalse(version_constraint_1 == version_constraint_4)
        self.assertFalse(version_constraint_2 == version_constraint_5)

    def test_parse_order_operator(self) -> None:
        version_constraint_lesser = verpro_.VersionConstraint("<some_version")
        version_constraint_lesser_eq = verpro_.VersionConstraint("<=some_version")
        version_constraint_greater = verpro_.VersionConstraint(">some_version")
        version_constraint_greater_eq = verpro_.VersionConstraint(">=some_version")
        self.assertTrue(version_constraint_lesser._lesser_then)
        self.assertFalse(version_constraint_lesser._lesser_equal)
        self.assertFalse(version_constraint_lesser._greater_equal)
        self.assertFalse(version_constraint_lesser._greater_then)

        self.assertFalse(version_constraint_lesser_eq._lesser_then)
        self.assertTrue(version_constraint_lesser_eq._lesser_equal)
        self.assertFalse(version_constraint_lesser_eq._greater_equal)
        self.assertFalse(version_constraint_lesser_eq._greater_then)

        self.assertFalse(version_constraint_greater._lesser_then)
        self.assertFalse(version_constraint_greater._lesser_equal)
        self.assertFalse(version_constraint_greater._greater_equal)
        self.assertTrue(version_constraint_greater._greater_then)

        self.assertFalse(version_constraint_greater_eq._lesser_then)
        self.assertFalse(version_constraint_greater_eq._lesser_equal)
        self.assertTrue(version_constraint_greater_eq._greater_equal)
        self.assertFalse(version_constraint_greater_eq._greater_then)

    def test_print(self) -> None:
        version_no_constraint = verpro_.VersionConstraint("some_version")
        self.assertEqual(version_no_constraint.__str__(), "some_version")

        version_lesser_then = verpro_.VersionConstraint("some_version", lesser_then=True)
        self.assertEqual(version_lesser_then.__str__(), "<some_version")

        version_lesser_then = verpro_.VersionConstraint("some_version", lesser_equal=True)
        self.assertEqual(version_lesser_then.__str__(), "<=some_version")

        version_lesser_then = verpro_.VersionConstraint("some_version", greater_then=True)
        self.assertEqual(version_lesser_then.__str__(), ">some_version")

        version_lesser_then = verpro_.VersionConstraint("some_version", greater_equal=True)
        self.assertEqual(version_lesser_then.__str__(), ">=some_version")

    def test_is_upper_limit(self) -> None:
        version_upper_limit_1 = verpro_.VersionConstraint("<some_version")
        self.assertTrue(version_upper_limit_1.is_upper_limit())
        version_upper_limit_2 = verpro_.VersionConstraint("<=some_version")
        self.assertTrue(version_upper_limit_2.is_upper_limit())
        version_not_upper_limit_1 = verpro_.VersionConstraint(">some_version")
        self.assertFalse(version_not_upper_limit_1.is_upper_limit())
        version_not_upper_limit_2 = verpro_.VersionConstraint(">=some_version")
        self.assertFalse(version_not_upper_limit_2.is_upper_limit())
        version_is_fixed = verpro_.VersionConstraint("some_version")
        self.assertFalse(version_is_fixed.is_upper_limit())

    def test_is_lower_limit(self) -> None:
        version_lower_limit_1 = verpro_.VersionConstraint(">some_version")
        self.assertTrue(version_lower_limit_1.is_lower_limit())
        version_lower_limit_2 = verpro_.VersionConstraint(">=some_version")
        self.assertTrue(version_lower_limit_2.is_lower_limit())
        version_not_lower_limit_1 = verpro_.VersionConstraint("<some_version")
        self.assertFalse(version_not_lower_limit_1.is_lower_limit())
        version_not_lower_limit_2 = verpro_.VersionConstraint("<=some_version")
        self.assertFalse(version_not_lower_limit_2.is_lower_limit())
        version_is_fixed = verpro_.VersionConstraint("some_version")
        self.assertFalse(version_is_fixed.is_lower_limit())

    def test_is_fixed(self) -> None:
        version_lower_limit_1 = verpro_.VersionConstraint(">some_version")
        self.assertFalse(version_lower_limit_1.is_fixed_version())
        version_lower_limit_2 = verpro_.VersionConstraint(">=some_version")
        self.assertFalse(version_lower_limit_2.is_fixed_version())
        version_not_lower_limit_1 = verpro_.VersionConstraint("<some_version")
        self.assertFalse(version_not_lower_limit_1.is_fixed_version())
        version_not_lower_limit_2 = verpro_.VersionConstraint("<=some_version")
        self.assertFalse(version_not_lower_limit_2.is_fixed_version())
        version_is_fixed = verpro_.VersionConstraint("some_version")
        self.assertTrue(version_is_fixed.is_fixed_version())


class TestVersionConstraintSemver(unittest.TestCase):
    def test_semver_compare_equal(self) -> None:
        version_1 = verpro_.VersionConstraintSemver("1.2.3")
        version_2 = verpro_.VersionConstraintSemver("1.2.3")
        version_3 = verpro_.VersionConstraintSemver("1.1.1")
        self.assertTrue(version_1 == version_2)
        self.assertFalse(version_1 == version_3)

    def test_semver_compare_smaller(self) -> None:
        version_1 = verpro_.VersionConstraintSemver("1.2.3")
        version_2 = verpro_.VersionConstraintSemver("1.2.4")
        version_3 = verpro_.VersionConstraintSemver("1.1.1")
        self.assertTrue(version_1 < version_2)
        self.assertFalse(version_1 < version_3)

    def test_semver_compare_smaller_or_equal(self) -> None:
        version_1 = verpro_.VersionConstraintSemver("1.2.3")
        version_2 = verpro_.VersionConstraintSemver("1.2.4")
        version_3 = verpro_.VersionConstraintSemver("1.1.1")
        version_4 = verpro_.VersionConstraintSemver("1.1.1")
        self.assertTrue(version_1 <= version_2)
        self.assertFalse(version_1 <= version_3)
        self.assertTrue(version_3 <= version_4)

    def test_semver_compare_greater(self) -> None:
        version_1 = verpro_.VersionConstraintSemver("1.2.3")
        version_2 = verpro_.VersionConstraintSemver("1.2.4")
        version_3 = verpro_.VersionConstraintSemver("1.1.1")
        self.assertTrue(version_1 < version_2)
        self.assertFalse(version_1 < version_3)

    def test_semver_compare_greater_or_equal(self) -> None:
        version_1 = verpro_.VersionConstraintSemver("1.2.5")
        version_2 = verpro_.VersionConstraintSemver("1.2.4")
        version_3 = verpro_.VersionConstraintSemver("2.1.1")
        version_4 = verpro_.VersionConstraintSemver("2.1.1")
        self.assertTrue(version_1 >= version_2)
        self.assertFalse(version_1 >= version_3)
        self.assertTrue(version_3 >= version_4)


class TestVersionRange(unittest.TestCase):
    def test_semver_parse_input(self) -> None:
        version_range = verpro_.VersionRange("semver/<1.2.5")
        self.assertEqual(version_range.__str__(), "semver/<1.2.5")
        self.assertEqual(version_range._version_constraints, ["<1.2.5"])
        self.assertEqual(
            version_range._version_objects[0],
            verpro_.VersionConstraintSemver("<1.2.5")
        )

        version_range = verpro_.VersionRange("semver/<1.2.5|>2.1.1")
        self.assertEqual(version_range.__str__(), "semver/<1.2.5|>2.1.1")
        self.assertEqual(version_range._version_constraints, ["<1.2.5", ">2.1.1"])
        self.assertEqual(
            version_range._version_objects[0],
            verpro_.VersionConstraintSemver("<1.2.5")
        )
        self.assertEqual(
            version_range._version_objects[1],
            verpro_.VersionConstraintSemver(">2.1.1")
        )

    def test_semver_version_print(self) -> None:
        version_range = verpro_.VersionRange("semver/<1.2.5|>1.2.6|<=2.0.0|>=3.1.2")
        self.assertEqual(version_range.__str__(), "semver/<1.2.5|>1.2.6|<=2.0.0|>=3.1.2")

    def test_semver_version_sort_input(self) -> None:
        version_range = verpro_.VersionRange("semver/>=3.1.2|<1.2.5|<=2.0.0|>1.2.6")
        self.assertEqual(version_range.__str__(), "semver/<1.2.5|>1.2.6|<=2.0.0|>=3.1.2")

    def test_semver_create_sub_ranges(self) -> None:
        version_range_1 = verpro_.VersionRange("semver/<3.1.2|>=1.2.5|<=2.0.0|>1.2.6")
        self.assertEqual(
            version_range_1._sub_ranges[0],
            {
                "lower_limit": verpro_.VersionConstraintSemver(">=1.2.5"),
                "upper_limit": verpro_.VersionConstraintSemver("<3.1.2"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": True,
                "is_fixed_version": False
            }
        )
        version_range_2 = verpro_.VersionRange("semver/<3.1.2")
        self.assertEqual(
            version_range_2._sub_ranges[0],
            {
                "lower_limit": None,
                "upper_limit": verpro_.VersionConstraintSemver("<3.1.2"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": False,
                "is_fixed_version": False
            }
        )
        version_range_3 = verpro_.VersionRange("semver/>3.1.2")
        self.assertEqual(
            version_range_3._sub_ranges[0],
            {
                "lower_limit": verpro_.VersionConstraintSemver(">3.1.2"),
                "upper_limit": None,
                "fixed_version": None,
                "has_upper_limit": False,
                "has_lower_limit": True,
                "is_fixed_version": False
            }
        )
        version_range_4 = verpro_.VersionRange("semver/3.1.2")
        self.assertEqual(
            version_range_4._sub_ranges[0],
            {
                "lower_limit": None,
                "upper_limit": None,
                "fixed_version": verpro_.VersionConstraintSemver("3.1.2"),
                "has_upper_limit": False,
                "has_lower_limit": False,
                "is_fixed_version": True
            }
        )
        version_range_5 = verpro_.VersionRange(
            "semver/>1.0.0|<2.0.0|>2.1.0|2.2.0|<3.0.0|<3.1.1|>3.1.2|<3.1.4"
        )
        self.assertEqual(
            version_range_5._sub_ranges[0],
            {
                "lower_limit": verpro_.VersionConstraintSemver(">1.0.0"),
                "upper_limit": verpro_.VersionConstraintSemver("<2.0.0"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": True,
                "is_fixed_version": False
            }
        )
        self.assertEqual(
            version_range_5._sub_ranges[1],
            {
                "lower_limit": verpro_.VersionConstraintSemver(">2.1.0"),
                "upper_limit": verpro_.VersionConstraintSemver("<3.1.1"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": True,
                "is_fixed_version": False
            }
        )
        self.assertEqual(
            version_range_5._sub_ranges[2],
            {
                "lower_limit": verpro_.VersionConstraintSemver(">3.1.2"),
                "upper_limit": verpro_.VersionConstraintSemver("<3.1.4"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": True,
                "is_fixed_version": False
            }
        )
        version_range_6 = verpro_.VersionRange(
            "semver/<1.0.0|<2.0.0|2.1.0|>2.2.0|<3.0.0|>3.1.1"
        )
        self.assertEqual(
            version_range_6._sub_ranges[0],
            {
                "lower_limit": None,
                "upper_limit": verpro_.VersionConstraintSemver("<2.0.0"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": False,
                "is_fixed_version": False
            }
        )
        self.assertEqual(
            version_range_6._sub_ranges[1],
            {
                "lower_limit": None,
                "upper_limit": None,
                "fixed_version": verpro_.VersionConstraintSemver("2.1.0"),
                "has_upper_limit": False,
                "has_lower_limit": False,
                "is_fixed_version": True
            }
        )
        self.assertEqual(
            version_range_6._sub_ranges[2],
            {
                "lower_limit": verpro_.VersionConstraintSemver(">2.2.0"),
                "upper_limit": verpro_.VersionConstraintSemver("<3.0.0"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": True,
                "is_fixed_version": False
            },
        )
        self.assertEqual(
            version_range_6._sub_ranges[3],
            {
                "lower_limit": verpro_.VersionConstraintSemver(">3.1.1"),
                "upper_limit": None,
                "fixed_version": None,
                "has_upper_limit": False,
                "has_lower_limit": True,
                "is_fixed_version": False
            }
        )
        version_range_7 = verpro_.VersionRange(
            "semver/<2.0.0|<1.0.0|<3.0.0|5.0.0|>=6.1.0|>=7.3.2|>=8.1.1|<10.1.1|4.0.0"
        )
        self.assertEqual(
            version_range_7._sub_ranges[0],
            {
                "lower_limit": None,
                "upper_limit": verpro_.VersionConstraintSemver("<3.0.0"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": False,
                "is_fixed_version": False
            }
        )
        self.assertEqual(
            version_range_7._sub_ranges[1],
            {
                "lower_limit": None,
                "upper_limit": None,
                "fixed_version": verpro_.VersionConstraintSemver("4.0.0"),
                "has_upper_limit": False,
                "has_lower_limit": False,
                "is_fixed_version": True
            }
        )
        self.assertEqual(
            version_range_7._sub_ranges[2],
            {
                "lower_limit": None,
                "upper_limit": None,
                "fixed_version": verpro_.VersionConstraintSemver("5.0.0"),
                "has_upper_limit": False,
                "has_lower_limit": False,
                "is_fixed_version": True
            }
        )
        self.assertEqual(
            version_range_7._sub_ranges[3],
            {
                "lower_limit": verpro_.VersionConstraintSemver(">=6.1.0"),
                "upper_limit": verpro_.VersionConstraintSemver("<10.1.1"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": True,
                "is_fixed_version": False
            }
        )
        version_range_8 = verpro_.VersionRange(
            "semver/>1.0.0"
        )
        self.assertEqual(
            version_range_8._sub_ranges[0],
            {
                "lower_limit": verpro_.VersionConstraintSemver(">1.0.0"),
                "upper_limit": None,
                "fixed_version": None,
                "has_upper_limit": False,
                "has_lower_limit": True,
                "is_fixed_version": False
            }
        )

    def test_semver_is_in_one_limit(self) -> None:
        version_range_1 = verpro_.VersionRange(
            "semver/<1.0.0"
        )
        version_range_2 = verpro_.VersionRange(
            "semver/1.0.0"
        )
        version_range_3 = verpro_.VersionRange(
            "semver/>1.0.0"
        )
        version_range_4 = verpro_.VersionRange(
            "semver/<=1.0.0"
        )
        version_range_5 = verpro_.VersionRange(
            "semver/>=1.0.0"
        )
        with self.assertRaises(AppError):
            version_range_1.version_is_in(verpro_.VersionConstraint(">=6.1.0"))

        self.assertTrue(version_range_2.version_is_in(verpro_.VersionConstraintSemver("1.0.0")))
        self.assertFalse(version_range_2.version_is_in(verpro_.VersionConstraintSemver("1.1.0")))
        self.assertTrue(version_range_1.version_is_in(verpro_.VersionConstraintSemver("0.1.0")))
        self.assertFalse(version_range_1.version_is_in(verpro_.VersionConstraintSemver("1.1.0")))
        self.assertTrue(version_range_3.version_is_in(verpro_.VersionConstraintSemver("1.1.0")))
        self.assertFalse(version_range_3.version_is_in(verpro_.VersionConstraintSemver("1.0.0")))
        self.assertTrue(version_range_4.version_is_in(verpro_.VersionConstraintSemver("1.0.0")))
        self.assertTrue(version_range_5.version_is_in(verpro_.VersionConstraintSemver("1.0.0")))

    def test_semver_is_in_one_range(self) -> None:
        version_range_1 = verpro_.VersionRange(
            "semver/<1.0.0|>0.0.1"
        )
        version_range_2 = verpro_.VersionRange(
            "semver/1.0.0|>1.1.0"
        )
        version_range_3 = verpro_.VersionRange(
            "semver/>1.0.0|<=1.1.0"
        )
        version_range_4 = verpro_.VersionRange(
            "semver/<1.0.0|>=2.1.0"
        )
        self.assertTrue(version_range_2.version_is_in(verpro_.VersionConstraintSemver("1.0.0")))
        self.assertFalse(version_range_2.version_is_in(verpro_.VersionConstraintSemver("1.1.0")))
        self.assertTrue(version_range_1.version_is_in(verpro_.VersionConstraintSemver("0.1.0")))
        self.assertFalse(version_range_1.version_is_in(verpro_.VersionConstraintSemver("1.1.0")))
        self.assertTrue(version_range_3.version_is_in(verpro_.VersionConstraintSemver("1.1.0")))
        self.assertFalse(version_range_3.version_is_in(verpro_.VersionConstraintSemver("1.0.0")))

        self.assertTrue(version_range_4.version_is_in(verpro_.VersionConstraintSemver("0.1.0")))
        self.assertTrue(version_range_4.version_is_in(verpro_.VersionConstraintSemver("2.2.0")))
        self.assertFalse(version_range_4.version_is_in(verpro_.VersionConstraintSemver("1.0.0")))

    def test_semver_is_in_complex_example(self) -> None:
        version_range_1 = verpro_.VersionRange(
            "semver/<2.0.0|<1.0.0|<3.0.0|5.0.0|>=6.1.0|>=7.3.2|>=8.1.1|<10.1.1|4.0.0"
        )
        self.assertTrue(version_range_1.version_is_in(verpro_.VersionConstraintSemver("4.0.0")))
        self.assertTrue(version_range_1.version_is_in(verpro_.VersionConstraintSemver("6.1.0")))
        self.assertTrue(version_range_1.version_is_in(verpro_.VersionConstraintSemver("8.1.1")))
        self.assertTrue(version_range_1.version_is_in(verpro_.VersionConstraintSemver("1.5.1")))
        self.assertTrue(version_range_1.version_is_in(verpro_.VersionConstraintSemver("5.0.0")))
        self.assertTrue(version_range_1.version_is_in(verpro_.VersionConstraintSemver("7.9.9")))
        self.assertFalse(version_range_1.version_is_in(verpro_.VersionConstraintSemver("10.2.0")))
        self.assertFalse(version_range_1.version_is_in(verpro_.VersionConstraintSemver("4.1.0")))

    def test_version_string_is_in_range(self) -> None:
        version_range = verpro_.VersionRange(
            "semver/<2.0.0|<1.0.0|<3.0.0|5.0.0|>=6.1.0|>=7.3.2|>=8.1.1|<10.1.1|4.0.0"
        )
        self.assertTrue(version_range.version_string_is_in_range("4.0.0"))
        self.assertTrue(version_range.version_string_is_in_range("6.1.0"))
        self.assertTrue(version_range.version_string_is_in_range("8.1.1"))
        self.assertTrue(version_range.version_string_is_in_range("1.5.1"))
        self.assertTrue(version_range.version_string_is_in_range("5.0.0"))
        self.assertTrue(version_range.version_string_is_in_range("7.9.9"))
        self.assertFalse(version_range.version_string_is_in_range("10.2.0"))
        self.assertFalse(version_range.version_string_is_in_range("4.1.0"))

    def test_all_versions(self) -> None:
        version_range_1 = verpro_.VersionRange(
            "semver/*"
        )
        self.assertTrue(version_range_1.version_is_in(verpro_.VersionConstraintSemver("4.0.0")))
        self.assertTrue(version_range_1.version_is_in(verpro_.VersionConstraintSemver("6.1.0")))
        self.assertTrue(version_range_1.version_is_in(verpro_.VersionConstraintSemver("8.1.1")))
        self.assertTrue(version_range_1.version_is_in(verpro_.VersionConstraintSemver("1.5.1")))
        self.assertTrue(version_range_1.version_is_in(verpro_.VersionConstraintSemver("5.0.0")))
        self.assertTrue(version_range_1.version_is_in(verpro_.VersionConstraintSemver("7.9.9")))

        version_range_2 = verpro_.VersionRange(
            "semver/1.*"
        )
        self.assertTrue(version_range_2.version_is_in(verpro_.VersionConstraintSemver("1.0.0")))
        self.assertFalse(version_range_2.version_is_in(verpro_.VersionConstraintSemver("2.1.0")))
        self.assertFalse(version_range_2.version_is_in(verpro_.VersionConstraintSemver("8.1.1")))
        self.assertTrue(version_range_2.version_is_in(verpro_.VersionConstraintSemver("1.5.1")))
        self.assertFalse(version_range_2.version_is_in(verpro_.VersionConstraintSemver("5.0.0")))
        self.assertFalse(version_range_2.version_is_in(verpro_.VersionConstraintSemver("12.1.1")))


class TestCustomVersionData(unittest.TestCase):
    path_to_version_file = pathlib.Path("tests/auxiliary/custom_version_list.json")

    def test_init(self) -> None:
        data = verpro_.CustomVersionData(path_to_file=self.path_to_version_file)
        self.assertEqual(data.get_data()["ubuntu"][0], "Warty Warthog")

    def test_add_data_file(self) -> None:
        data = verpro_.CustomVersionData(path_to_file=self.path_to_version_file)
        test_data_1 = [
            {
                "version_typ": "ubuntu",
                "version_list": [
                    "version 1",
                    "version 2"
                ]
            }
        ]
        test_data_2 = [
            {
                "version_type": "ubuntu",
                "version_list": "str"
            }
        ]
        test_data_3 = [
            {
                "version_type": "some_type",
                "version_list": [
                    "version 1",
                    "version 2"
                ]
            }
        ]
        with self.assertRaises(AppError):
            data.add_data_from_dict(test_data_1[0])
        with self.assertRaises(AppError):
            data.add_data_from_list(test_data_1)
        with self.assertRaises(AppError):
            data.add_data_from_dict(test_data_2[0])
        with self.assertRaises(AppError):
            data.add_data_from_list(test_data_2)
        with self.assertRaises(AppError):
            data.add_data_from_file(
                pathlib.Path("tests/auxiliary/test_set_sboms/test.cdx.json")
            )
        data.add_data_from_list(test_data_3)
        self.assertEqual(
            data.get_data()["some_type"], [
                "version 1",
                "version 2"
            ]
        )
        del data

    def test_get_data(self) -> None:
        data = verpro_.CustomVersionData(path_to_file=self.path_to_version_file)
        self.assertTrue(data.get_data()["ubuntu"][0] == "Warty Warthog")


class TestVersionConstraintCustom(unittest.TestCase):
    path_to_version_file = pathlib.Path("tests/auxiliary/custom_version_list.json")
    data = verpro_.CustomVersionData(path_to_file=path_to_version_file)
    test_data = [
        {
            "version_type": "some_type",
            "version_list": [
                "version 1",
                "version 2",
                "version 3",
                "version 4"
            ]
        }
    ]
    data.add_data_from_list(test_data)

    def test_equal(self) -> None:
        version_1 = verpro_.VersionConstraintCustom("version 1", "some_type")
        version_2 = verpro_.VersionConstraintCustom("version 2", "some_type")
        version_1_2 = verpro_.VersionConstraintCustom("version 1", "some_type")
        version_1_2 = verpro_.VersionConstraintCustom("version 1", "some_type")
        version_ubuntu = verpro_.VersionConstraintCustom("Warty Warthog", "ubuntu")
        self.assertTrue(version_1 == version_1_2)
        self.assertFalse(version_1 == version_2)
        self.assertFalse(version_1 == version_ubuntu)

    def test_lesser_then(self) -> None:
        version_1 = verpro_.VersionConstraintCustom("version 1", "some_type")
        version_2 = verpro_.VersionConstraintCustom("version 2", "some_type")
        self.assertTrue(version_1 < version_2)
        self.assertFalse(version_1 > version_2)

    def test_lesser_equal(self) -> None:
        version_1 = verpro_.VersionConstraintCustom("version 1", "some_type")
        version_2 = verpro_.VersionConstraintCustom("version 2", "some_type")
        self.assertTrue(version_1 <= version_2)
        self.assertTrue(version_1 <= version_1)
        self.assertFalse(version_1 >= version_2)

    def test_greater_then(self) -> None:
        version_1 = verpro_.VersionConstraintCustom("version 1", "some_type")
        version_2 = verpro_.VersionConstraintCustom("version 2", "some_type")
        self.assertTrue(version_2 > version_1)
        self.assertFalse(version_2 < version_1)

    def test_greater_equal(self) -> None:
        version_1 = verpro_.VersionConstraintCustom("version 1", "some_type")
        version_2 = verpro_.VersionConstraintCustom("version 2", "some_type")
        self.assertTrue(version_2 >= version_1)
        self.assertTrue(version_2 >= version_2)
        self.assertFalse(version_2 <= version_1)
