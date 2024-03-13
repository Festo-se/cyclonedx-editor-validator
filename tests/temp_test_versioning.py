import unittest

from cdxev.auxiliary import sbomFunctions as sbF


class TestVersionConstraint(unittest.TestCase):
    def test_compare_function(self) -> None:
        version_constraint_1 = sbF.VersionConstraint("some_version", lesser_then=True)
        version_constraint_2 = sbF.VersionConstraint("some_version", lesser_equal=True)
        version_constraint_3 = sbF.VersionConstraint("some_version", greater_then=True)
        version_constraint_4 = sbF.VersionConstraint("some_version", greater_equal=True)
        version_constraint_5 = sbF.VersionConstraint("<some_version")
        version_constraint_6 = sbF.VersionConstraint("<=some_version")
        version_constraint_7 = sbF.VersionConstraint(">some_version")
        version_constraint_8 = sbF.VersionConstraint(">=some_version")
        self.assertTrue(version_constraint_1 == version_constraint_5)
        self.assertTrue(version_constraint_2 == version_constraint_6)
        self.assertTrue(version_constraint_3 == version_constraint_7)
        self.assertTrue(version_constraint_4 == version_constraint_8)
        self.assertFalse(version_constraint_1 == version_constraint_2)
        self.assertFalse(version_constraint_1 == version_constraint_3)
        self.assertFalse(version_constraint_1 == version_constraint_4)
        self.assertFalse(version_constraint_2 == version_constraint_5)

    def test_parse_order_operator(self) -> None:
        version_constraint_lesser = sbF.VersionConstraint("<some_version")
        version_constraint_lesser_eq = sbF.VersionConstraint("<=some_version")
        version_constraint_greater = sbF.VersionConstraint(">some_version")
        version_constraint_greater_eq = sbF.VersionConstraint(">=some_version")
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
        version_no_constraint = sbF.VersionConstraint("some_version")
        self.assertEqual(version_no_constraint.__str__(), "some_version")

        version_lesser_then = sbF.VersionConstraint("some_version", lesser_then=True)
        self.assertEqual(version_lesser_then.__str__(), "<some_version")

        version_lesser_then = sbF.VersionConstraint("some_version", lesser_equal=True)
        self.assertEqual(version_lesser_then.__str__(), "<=some_version")

        version_lesser_then = sbF.VersionConstraint("some_version", greater_then=True)
        self.assertEqual(version_lesser_then.__str__(), ">some_version")

        version_lesser_then = sbF.VersionConstraint("some_version", greater_equal=True)
        self.assertEqual(version_lesser_then.__str__(), ">=some_version")

    def test_is_upper_limit(self) -> None:
        version_upper_limit_1 = sbF.VersionConstraint("<some_version")
        self.assertTrue(version_upper_limit_1.is_upper_limit())
        version_upper_limit_2 = sbF.VersionConstraint("<=some_version")
        self.assertTrue(version_upper_limit_2.is_upper_limit())
        version_not_upper_limit_1 = sbF.VersionConstraint(">some_version")
        self.assertFalse(version_not_upper_limit_1.is_upper_limit())
        version_not_upper_limit_2 = sbF.VersionConstraint(">=some_version")
        self.assertFalse(version_not_upper_limit_2.is_upper_limit())
        version_is_fixed = sbF.VersionConstraint("some_version")
        self.assertFalse(version_is_fixed.is_upper_limit())

    def test_is_lower_limit(self) -> None:
        version_lower_limit_1 = sbF.VersionConstraint(">some_version")
        self.assertTrue(version_lower_limit_1.is_lower_limit())
        version_lower_limit_2 = sbF.VersionConstraint(">=some_version")
        self.assertTrue(version_lower_limit_2.is_lower_limit())
        version_not_lower_limit_1 = sbF.VersionConstraint("<some_version")
        self.assertFalse(version_not_lower_limit_1.is_lower_limit())
        version_not_lower_limit_2 = sbF.VersionConstraint("<=some_version")
        self.assertFalse(version_not_lower_limit_2.is_lower_limit())
        version_is_fixed = sbF.VersionConstraint("some_version")
        self.assertFalse(version_is_fixed.is_lower_limit())

    def test_is_fixed(self) -> None:
        version_lower_limit_1 = sbF.VersionConstraint(">some_version")
        self.assertFalse(version_lower_limit_1.is_fixed_version())
        version_lower_limit_2 = sbF.VersionConstraint(">=some_version")
        self.assertFalse(version_lower_limit_2.is_fixed_version())
        version_not_lower_limit_1 = sbF.VersionConstraint("<some_version")
        self.assertFalse(version_not_lower_limit_1.is_fixed_version())
        version_not_lower_limit_2 = sbF.VersionConstraint("<=some_version")
        self.assertFalse(version_not_lower_limit_2.is_fixed_version())
        version_is_fixed = sbF.VersionConstraint("some_version")
        self.assertTrue(version_is_fixed.is_fixed_version())


class TestVersionConstraintSemver(unittest.TestCase):
    def test_semver_compare_equal(self) -> None:
        version_1 = sbF.VersionConstraintSemver("1.2.3")
        version_2 = sbF.VersionConstraintSemver("1.2.3")
        version_3 = sbF.VersionConstraintSemver("1.1.1")
        self.assertTrue(version_1 == version_2)
        self.assertFalse(version_1 == version_3)

    def test_semver_compare_smaller(self) -> None:
        version_1 = sbF.VersionConstraintSemver("1.2.3")
        version_2 = sbF.VersionConstraintSemver("1.2.4")
        version_3 = sbF.VersionConstraintSemver("1.1.1")
        self.assertTrue(version_1 < version_2)
        self.assertFalse(version_1 < version_3)

    def test_semver_compare_smaller_or_equal(self) -> None:
        version_1 = sbF.VersionConstraintSemver("1.2.3")
        version_2 = sbF.VersionConstraintSemver("1.2.4")
        version_3 = sbF.VersionConstraintSemver("1.1.1")
        version_4 = sbF.VersionConstraintSemver("1.1.1")
        self.assertTrue(version_1 <= version_2)
        self.assertFalse(version_1 <= version_3)
        self.assertTrue(version_3 <= version_4)

    def test_semver_compare_greater(self) -> None:
        version_1 = sbF.VersionConstraintSemver("1.2.3")
        version_2 = sbF.VersionConstraintSemver("1.2.4")
        version_3 = sbF.VersionConstraintSemver("1.1.1")
        self.assertTrue(version_1 < version_2)
        self.assertFalse(version_1 < version_3)

    def test_semver_compare_greater_or_equal(self) -> None:
        version_1 = sbF.VersionConstraintSemver("1.2.5")
        version_2 = sbF.VersionConstraintSemver("1.2.4")
        version_3 = sbF.VersionConstraintSemver("2.1.1")
        version_4 = sbF.VersionConstraintSemver("2.1.1")
        self.assertTrue(version_1 >= version_2)
        self.assertFalse(version_1 >= version_3)
        self.assertTrue(version_3 >= version_4)


class TestVersionRange(unittest.TestCase):
    def test_semver_parse_input(self) -> None:
        version_range = sbF.VersionRange("semver/<1.2.5")
        self.assertEqual(version_range.__str__(), "semver/<1.2.5")
        self.assertEqual(version_range._version_constraints, ["<1.2.5"])
        self.assertEqual(
            version_range._version_objects[0],
            sbF.VersionConstraintSemver("<1.2.5")
        )

        version_range = sbF.VersionRange("semver/<1.2.5|>2.1.1")
        self.assertEqual(version_range.__str__(), "semver/<1.2.5|>2.1.1")
        self.assertEqual(version_range._version_constraints, ["<1.2.5", ">2.1.1"])
        self.assertEqual(
            version_range._version_objects[0],
            sbF.VersionConstraintSemver("<1.2.5")
        )
        self.assertEqual(
            version_range._version_objects[1],
            sbF.VersionConstraintSemver(">2.1.1")
        )

    def test_semver_version_print(self) -> None:
        version_range = sbF.VersionRange("semver/<1.2.5|>1.2.6|<=2.0.0|>=3.1.2")
        self.assertEqual(version_range.__str__(), "semver/<1.2.5|>1.2.6|<=2.0.0|>=3.1.2")

    def test_semver_version_sort_input(self) -> None:
        version_range = sbF.VersionRange("semver/>=3.1.2|<1.2.5|<=2.0.0|>1.2.6")
        self.assertEqual(version_range.__str__(), "semver/<1.2.5|>1.2.6|<=2.0.0|>=3.1.2")

    def test_semver_create_sub_ranges(self) -> None:
        version_range_1 = sbF.VersionRange("semver/<3.1.2|>=1.2.5|<=2.0.0|>1.2.6")
        self.assertEqual(
            version_range_1._sub_ranges[0],
            {
                "lower_limit": sbF.VersionConstraintSemver(">=1.2.5"),
                "upper_limit": sbF.VersionConstraintSemver("<3.1.2"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": True,
                "is_fixed_version": False
            }
        )
        version_range_2 = sbF.VersionRange("semver/<3.1.2")
        self.assertEqual(
            version_range_2._sub_ranges[0],
            {
                "lower_limit": None,
                "upper_limit": sbF.VersionConstraintSemver("<3.1.2"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": False,
                "is_fixed_version": False
            }
        )
        version_range_3 = sbF.VersionRange("semver/>3.1.2")
        self.assertEqual(
            version_range_3._sub_ranges[0],
            {
                "lower_limit": sbF.VersionConstraintSemver(">3.1.2"),
                "upper_limit": None,
                "fixed_version": None,
                "has_upper_limit": False,
                "has_lower_limit": True,
                "is_fixed_version": False
            }
        )
        version_range_4 = sbF.VersionRange("semver/3.1.2")
        self.assertEqual(
            version_range_4._sub_ranges[0],
            {
                "lower_limit": None,
                "upper_limit": None,
                "fixed_version": sbF.VersionConstraintSemver("3.1.2"),
                "has_upper_limit": False,
                "has_lower_limit": False,
                "is_fixed_version": True
            }
        )
        version_range_5 = sbF.VersionRange(
            "semver/>1.0.0|<2.0.0|>2.1.0|2.2.0|<3.0.0|<3.1.1|>3.1.2|<3.1.4"
        )
        self.assertEqual(
            version_range_5._sub_ranges[0],
            {
                "lower_limit": sbF.VersionConstraintSemver(">1.0.0"),
                "upper_limit": sbF.VersionConstraintSemver("<2.0.0"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": True,
                "is_fixed_version": False
            }
        )
        self.assertEqual(
            version_range_5._sub_ranges[1],
            {
                "lower_limit": sbF.VersionConstraintSemver(">2.1.0"),
                "upper_limit": sbF.VersionConstraintSemver("<3.1.1"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": True,
                "is_fixed_version": False
            }
        )
        self.assertEqual(
            version_range_5._sub_ranges[2],
            {
                "lower_limit": sbF.VersionConstraintSemver(">3.1.2"),
                "upper_limit": sbF.VersionConstraintSemver("<3.1.4"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": True,
                "is_fixed_version": False
            }
        )
        version_range_6 = sbF.VersionRange(
            "semver/<1.0.0|<2.0.0|2.1.0|>2.2.0|<3.0.0|>3.1.1"
        )
        self.assertEqual(
            version_range_6._sub_ranges[0],
            {
                "lower_limit": None,
                "upper_limit": sbF.VersionConstraintSemver("<2.0.0"),
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
                "fixed_version": sbF.VersionConstraintSemver("2.1.0"),
                "has_upper_limit": False,
                "has_lower_limit": False,
                "is_fixed_version": True
            }
        )
        self.assertEqual(
            version_range_6._sub_ranges[2],
            {
                "lower_limit": sbF.VersionConstraintSemver(">2.2.0"),
                "upper_limit": sbF.VersionConstraintSemver("<3.0.0"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": True,
                "is_fixed_version": False
            },
        )
        self.assertEqual(
            version_range_6._sub_ranges[3],
            {
                "lower_limit": sbF.VersionConstraintSemver(">3.1.1"),
                "upper_limit": None,
                "fixed_version": None,
                "has_upper_limit": False,
                "has_lower_limit": True,
                "is_fixed_version": False
            }
        )
        version_range_7 = sbF.VersionRange(
            "semver/<2.0.0|<1.0.0|<3.0.0|5.0.0|>=6.1.0|>=7.3.2|>=8.1.1|<10.1.1|4.0.0"
        )
        for object in version_range_7._sub_ranges:
            print("subrange")
            print(object["lower_limit"])
            print(object["upper_limit"])
        self.assertEqual(
            version_range_7._sub_ranges[0],
            {
                "lower_limit": None,
                "upper_limit": sbF.VersionConstraintSemver("<3.0.0"),
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
                "fixed_version": sbF.VersionConstraintSemver("4.0.0"),
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
                "fixed_version": sbF.VersionConstraintSemver("5.0.0"),
                "has_upper_limit": False,
                "has_lower_limit": False,
                "is_fixed_version": True
            }
        )
        self.assertEqual(
            version_range_7._sub_ranges[3],
            {
                "lower_limit": sbF.VersionConstraintSemver(">=6.1.0"),
                "upper_limit": sbF.VersionConstraintSemver("<10.1.1"),
                "fixed_version": None,
                "has_upper_limit": True,
                "has_lower_limit": True,
                "is_fixed_version": False
            }
        )
