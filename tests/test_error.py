# SPDX-License-Identifier: GPL-3.0-or-later

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
