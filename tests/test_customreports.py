# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import cdxev.log as log
from cdxev.validator.customreports import GitLabCQReporter, WarningsNgReporter


# noinspection PyUnresolvedReferences
class WarningsNgTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        formatter = log.LogMessageFormatter()
        cls.logger = logging.getLogger(__name__)
        cls.tempdir = TemporaryDirectory()
        cls.expected_file = os.path.join(cls.tempdir.name, "bom.json")
        cls.expected_target = os.path.join(cls.tempdir.name, "issues.json")
        warnings_ng_handler = WarningsNgReporter(
            Path(cls.expected_file), Path(cls.expected_target)
        )
        warnings_ng_handler.setFormatter(formatter)
        cls.logger.addHandler(warnings_ng_handler)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tempdir.cleanup()

    def test_format_full(self) -> None:
        line_start = 10
        message = "message"
        description = "description"
        module_name = "module"
        msg_obj = log.LogMessage(message, description, module_name, line_start)
        self.logger.error(msg_obj)
        self.assertEqual(str(self.logger.handlers[0].file_path), self.expected_file)
        self.assertEqual(str(self.logger.handlers[0].target), self.expected_target)
        expected_buffer = {
            "origin": "CycloneDX Editor Validator",
            "fingerprint": "unknown",
            "type": "SBOM",
            "category": "QA",
            "severity": "ERROR",
            "fileName": "bom.json",
            "pathName": self.tempdir.name,
            "lineStart": line_start,
            "message": message,
            "description": description,
            "moduleName": module_name,
        }
        self.assertDictEqual(
            self.logger.handlers[0].buffer["issues"][-1], expected_buffer
        )

    def test_format_without_line(self) -> None:
        line_start = None
        message = "message"
        description = "description"
        module_name = "module"
        msg_obj = log.LogMessage(message, description, module_name, line_start)
        self.logger.error(msg_obj)
        self.assertEqual(str(self.logger.handlers[0].file_path), self.expected_file)
        self.assertEqual(str(self.logger.handlers[0].target), self.expected_target)
        expected_buffer = {
            "origin": "CycloneDX Editor Validator",
            "fingerprint": "unknown",
            "type": "SBOM",
            "category": "QA",
            "severity": "ERROR",
            "fileName": "bom.json",
            "pathName": self.tempdir.name,
            "message": message,
            "description": description,
            "moduleName": module_name,
            "lineStart": 0,
        }
        self.assertDictEqual(
            self.logger.handlers[0].buffer["issues"][-1], expected_buffer
        )

    def test_format_without_module(self) -> None:
        line_start = 10
        message = "message"
        description = "description"
        module_name = None
        msg_obj = log.LogMessage(message, description, module_name, line_start)
        self.logger.error(msg_obj)
        self.assertEqual(str(self.logger.handlers[0].file_path), self.expected_file)
        self.assertEqual(str(self.logger.handlers[0].target), self.expected_target)
        expected_buffer = {
            "origin": "CycloneDX Editor Validator",
            "fingerprint": "unknown",
            "type": "SBOM",
            "category": "QA",
            "severity": "ERROR",
            "fileName": "bom.json",
            "pathName": self.tempdir.name,
            "lineStart": line_start,
            "message": message,
            "description": description,
            "moduleName": "",
        }
        self.assertDictEqual(
            self.logger.handlers[0].buffer["issues"][-1], expected_buffer
        )

    def test_wrong_format(self) -> None:
        with self.assertRaises(TypeError) as exc:
            self.logger.error("only string message")
        self.assertEqual(
            "JenkinsFormatter cannot process string messages", exc.exception.args[0]
        )

    def test_close(self) -> None:
        line_start = 10
        message = "message"
        description = "description"
        module_name = None
        msg_obj = log.LogMessage(message, description, module_name, line_start)
        self.logger.error(msg_obj)
        with mock.patch(
            "pathlib.Path.write_text", mock.mock_open()
        ) as write_text_mocked:
            self.logger.handlers[0].close()
        self.assertIn(
            '"origin": "CycloneDX Editor Validator"', write_text_mocked.call_args[0][0]
        )

    def test_file_path_missing(self) -> None:
        self.logger.handlers[0].file_path = None
        line_start = 10
        message = "message"
        description = "description"
        module_name = None
        msg_obj = log.LogMessage(message, description, module_name, line_start)
        self.logger.error(msg_obj)
        self.assertIsNone(self.logger.handlers[0].file_path)
        self.assertEqual(str(self.logger.handlers[0].target), self.expected_target)
        expected_buffer = {
            "origin": "CycloneDX Editor Validator",
            "fingerprint": "unknown",
            "type": "SBOM",
            "category": "QA",
            "severity": "ERROR",
            "lineStart": line_start,
            "message": message,
            "description": description,
            "moduleName": "",
        }
        self.assertDictEqual(
            self.logger.handlers[0].buffer["issues"][-1], expected_buffer
        )
        self.logger.handlers[0].file_path = Path(self.expected_file)


class TestGitLabCQReporter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file_path = Path("test.log")
        cls.target = mock.MagicMock()
        cls.reporter = GitLabCQReporter(cls.file_path, cls.target)

    def test_emit(self):
        record = mock.MagicMock()
        record.exc_info = None
        record.msg = log.LogMessage("Test Message", "test", "module", 10)
        self.reporter.buffer = []
        self.reporter.emit(record)
        self.assertEqual(len(self.reporter.buffer), 1)
        self.assertEqual(self.reporter.buffer[0]["description"], "test")
        self.assertEqual(self.reporter.buffer[0]["location"]["path"], "test.log")
        self.assertEqual(self.reporter.buffer[0]["location"]["lines"]["begin"], 10)

    def test_type_error(self):
        record = mock.MagicMock()
        record.exc_info = None
        record.msg = "String message"

        with self.assertRaises(TypeError) as exc:
            self.reporter.emit(record)
        self.assertEqual(
            "GitLabFormatter cannot process string messages", exc.exception.args[0]
        )

    def test_emit_with_frame(self):
        handler = GitLabCQReporter(None, self.target)
        record = mock.MagicMock()
        record.msg = log.LogMessage("Test Message", "test", "module", 10)
        record.exc_info = (None, None, mock.MagicMock())

        with mock.patch("traceback.extract_tb") as mock_extract_tb:
            mock_extract_tb.return_value = [
                mock.MagicMock(filename="test.py", lineno=30)
            ]
            handler.emit(record)

        self.assertEqual(len(handler.buffer), 1)
        self.assertEqual(handler.buffer[0]["location"]["lines"]["begin"], 30)
        self.assertEqual(handler.buffer[0]["location"]["path"], "test.py")

    def test_close(self):
        self.reporter.buffer = [{"issue": "1"}, {"issue": "2"}]
        self.reporter.close()
        self.assertEqual(self.target.write.call_count, 1)
        expected_output = (
            '[\n    {\n        "issue": "1"\n    }'
            + ',\n    {\n        "issue": "2"\n    }\n]'
        )
        self.assertEqual(self.target.write.call_args[0][0], expected_output)
