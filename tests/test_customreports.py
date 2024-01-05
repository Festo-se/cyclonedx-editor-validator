import logging
import unittest
from pathlib import Path
from unittest import mock

import cdxev.log as log
from cdxev.validator.customreports import GitLabCQReporter, WarningsNgReporter


# noinspection PyUnresolvedReferences
class WarningsNgTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        formatter = log.LogMessageFormatter()
        cls.logger = logging.getLogger(__name__)
        cls.expected_file = "bom.json"
        cls.expected_target = "issues.json"
        warnings_ng_handler = WarningsNgReporter(
            Path(cls.expected_file), Path(cls.expected_target)
        )
        warnings_ng_handler.setFormatter(formatter)
        cls.logger.addHandler(warnings_ng_handler)

    def test_format_full(self) -> None:
        line_start = 10
        message = "message"
        description = "description"
        module_name = "module"
        msg_obj = log.LogMessage(message, description, module_name, line_start)
        self.logger.error(msg_obj)
        self.assertEqual(self.logger.handlers[0].file_path.name, self.expected_file)
        self.assertEqual(self.logger.handlers[0].target.name, self.expected_target)
        expected_buffer = {
            "origin": "CycloneDX Editor Validator",
            "fingerprint": "unknown",
            "type": "SBOM",
            "category": "QA",
            "severity": "ERROR",
            "fileName": "bom.json",
            "pathName": ".",
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
        self.assertEqual(self.logger.handlers[0].file_path.name, self.expected_file)
        self.assertEqual(self.logger.handlers[0].target.name, self.expected_target)
        expected_buffer = {
            "origin": "CycloneDX Editor Validator",
            "fingerprint": "unknown",
            "type": "SBOM",
            "category": "QA",
            "severity": "ERROR",
            "fileName": "bom.json",
            "pathName": ".",
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
        self.assertEqual(self.logger.handlers[0].file_path.name, self.expected_file)
        self.assertEqual(self.logger.handlers[0].target.name, self.expected_target)
        expected_buffer = {
            "origin": "CycloneDX Editor Validator",
            "fingerprint": "unknown",
            "type": "SBOM",
            "category": "QA",
            "severity": "ERROR",
            "fileName": "bom.json",
            "pathName": ".",
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
        self.assertEqual(self.logger.handlers[0].target.name, self.expected_target)
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
    def setUpClass(cls) -> None:
        formatter = log.LogMessageFormatter()
        cls.file_path = Path("test.log")
        cls.target = mock.MagicMock()
        cls.buffer = []
        cls.logger = logging.getLogger(__name__)
        cls.reporter = GitLabCQReporter(cls.file_path, cls.target, cls.buffer)
        cls.reporter.setFormatter(formatter)
        cls.logger.addHandler(cls.reporter)

    def test_format_full(self):
        record = log.LogMessage("Test Message", "test", "module", 10)
        self.logger.error(record)
        self.assertEqual(len(self.buffer), 1)
        self.assertEqual(self.buffer[0]["description"], "test")
        self.assertEqual(self.buffer[0]["location"]["path"], "test.log")
        self.assertEqual(self.buffer[0]["location"]["lines"]["begin"], 10)
