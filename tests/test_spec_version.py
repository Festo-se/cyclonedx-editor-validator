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

import unittest

from cdxev.auxiliary.sbomFunctions import CycloneDXVersion, SpecVersion


class SpecVersionTestCase(unittest.TestCase):
    def test_parse(self):
        s = "1.2"
        parsed = SpecVersion.parse(s)

        self.assertEqual(parsed, CycloneDXVersion.V1_2)
        self.assertEqual(CycloneDXVersion.V1_2, parsed)
        self.assertEqual(s, str(parsed))

    def test_compare_parsed(self):
        s1 = "1.2"
        s2 = "1.4"
        parsed1 = SpecVersion.parse(s1)
        parsed2 = SpecVersion.parse(s2)

        self.assertNotEqual(parsed1, parsed2)
        self.assertLess(parsed1, parsed2)
        self.assertGreater(parsed2, parsed1)

    def test_parse_blank(self):
        s = ""
        parsed = SpecVersion.parse(s)

        self.assertIsNone(parsed)

    def test_parse_no_major(self):
        s = ".3"
        parsed = SpecVersion.parse(s)

        self.assertIsNone(parsed)

    def test_parse_no_minor(self):
        s = "1."
        parsed = SpecVersion.parse(s)

        self.assertIsNone(parsed)

    def test_parse_no_dot(self):
        s = "15"
        parsed = SpecVersion.parse(s)

        self.assertIsNone(parsed)

    def test_parse_invalid(self):
        s = "f1.5"
        parsed = SpecVersion.parse(s)

        self.assertIsNone(parsed)

    def test_compare(self):
        self.assertLessEqual(CycloneDXVersion.V1_0, CycloneDXVersion.V1_0)
        self.assertEqual(CycloneDXVersion.V1_0, CycloneDXVersion.V1_0)
        self.assertLess(CycloneDXVersion.V1_0, CycloneDXVersion.V1_1)
        self.assertGreater(CycloneDXVersion.V1_1, CycloneDXVersion.V1_0)
