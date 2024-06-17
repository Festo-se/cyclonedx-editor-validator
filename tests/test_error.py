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

import cdxev.error as err
import cdxev.log as log


class AppErrorTestCase(unittest.TestCase):
    def test_create_error(self):
        exc = err.AppError("Foo", "bar")

        self.assertIsInstance(exc.details, log.LogMessage)
        self.assertEqual(exc.details.message, "Foo")
        self.assertEqual(exc.details.description, "bar")

    def test_create_error_without_args_raises(self):
        with self.assertRaisesRegex(
            ValueError, "Either log_msg or message and description must be passed"
        ):
            err.AppError()

        with self.assertRaisesRegex(
            ValueError, "Either log_msg or message and description must be passed"
        ):
            err.AppError("Foo")

    def test_create_error_from_log(self):
        exc = err.AppError(
            log_msg=log.LogMessage(
                message="Foo", description="bar", module_name="module", line_start=0
            )
        )
        self.assertIsInstance(exc.details, log.LogMessage)
        self.assertEqual(exc.details.message, "Foo")
        self.assertEqual(exc.details.description, "bar")
        self.assertEqual(exc.details.module_name, "module")
        self.assertEqual(exc.details.line_start, 0)

        exc = err.AppError(
            message="Foo",
            description="bar",
            module_name="module",
            line_start=0,
            log_msg=log.LogMessage(message="test", description="test2"),
        )
        self.assertIsInstance(exc.details, log.LogMessage)
        self.assertEqual(exc.details.message, "Foo")
        self.assertEqual(exc.details.description, "bar")
        self.assertEqual(exc.details.module_name, "module")
        self.assertEqual(exc.details.line_start, 0)
