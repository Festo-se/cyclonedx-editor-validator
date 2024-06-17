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

import io
import logging
import unittest
from unittest.mock import Mock, patch

import cdxev.log as log


class LogConfigTestCase(unittest.TestCase):
    @patch(f"{log.__name__}.logging")
    def test_configure_logging_not_quiet_not_verbose(self, m_logging):
        m_logger = Mock(logging.Logger)
        m_logging.getLogger.return_value = m_logger
        log.configure_logging(False, False)

        m_logger.addHandler.assert_called_once()
        m_logger.setLevel.assert_called_once_with(m_logging.INFO)

    @patch(f"{log.__name__}.logging")
    def test_configure_logging_verbose(self, m_logging):
        m_logger = Mock(logging.Logger)
        m_logging.getLogger.return_value = m_logger
        log.configure_logging(False, True)

        m_logger.addHandler.assert_called_once()
        m_logger.setLevel.assert_called_once_with(m_logging.DEBUG)

    @patch(f"{log.__name__}.logging")
    def test_configure_logging_quiet(self, m_logging):
        m_logger = Mock(logging.Logger)
        m_logging.getLogger.return_value = m_logger
        log.configure_logging(True, False)

        m_logger.addHandler.assert_not_called()

    @patch(f"{log.__name__}.logging")
    def test_configure_logging_quiet_and_verbose(self, m_logging):
        m_logger = Mock(logging.Logger)
        m_logging.getLogger.return_value = m_logger
        log.configure_logging(True, True)

        m_logger.addHandler.assert_not_called()


class LogFormatterTestCase(unittest.TestCase):
    def setUp(self) -> None:
        formatter = log.LogMessageFormatter()
        self.log_stream = io.StringIO()
        handler = logging.StreamHandler(self.log_stream)
        handler.setFormatter(formatter)
        self.logger = logging.getLogger(__name__)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)

    def test_format_full(self):
        msg_obj = log.LogMessage("message", "description", "module", 10)
        self.logger.info(msg_obj)
        msg = self.log_stream.getvalue()
        expected = "INFO: message (component: module at line 10) - description\n"
        self.assertEqual(expected, msg)

    def test_format_without_line(self):
        msg_obj = log.LogMessage("message", "description", "module", None)
        self.logger.info(msg_obj)
        msg = self.log_stream.getvalue()
        expected = "INFO: message (component: module) - description\n"
        self.assertEqual(expected, msg)

    def test_format_without_module(self):
        msg_obj = log.LogMessage("message", "description", None, 10)
        self.logger.info(msg_obj)
        msg = self.log_stream.getvalue()
        expected = "INFO: message (at line 10) - description\n"
        self.assertEqual(expected, msg)
