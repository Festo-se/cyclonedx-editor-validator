# SPDX-License-Identifier: GPL-3.0-or-later

import contextlib
import copy
import datetime as dt
import io
import pathlib
import random
import unittest
from textwrap import dedent
from unittest.mock import Mock, patch

import pytest

import cdxev.auxiliary.io_processing as out
from cdxev import pkg


class OutputTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.minimal_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 0,
        }

        self.minimal_json = dedent(
            """\
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 0
        }"""
        )

    @patch(f"{out.__name__}.datetime", wraps=dt.datetime)
    def test_add_timestamp(self, mock_dt):
        expected_timestamp = dt.datetime(2000, 1, 1, 12, 30, 45)

        sbom = self.minimal_sbom

        expected_sbom = copy.deepcopy(self.minimal_sbom)
        expected_sbom["metadata"] = {
            "timestamp": expected_timestamp.isoformat(timespec="seconds")
        }

        mock_dt.now.return_value = expected_timestamp
        out.update_timestamp(sbom)

        self.assertDictEqual(expected_sbom, sbom)

    @patch(f"{out.__name__}.datetime", wraps=dt.datetime)
    def test_overwrite_timestamp(self, mock_dt):
        expected_timestamp = dt.datetime(2000, 1, 1, 12, 30, 45)

        sbom = self.minimal_sbom
        expected_sbom = copy.deepcopy(self.minimal_sbom)
        expected_sbom["metadata"] = {
            "timestamp": expected_timestamp.isoformat(timespec="seconds")
        }

        sbom["metadata"] = {"timestamp": "1900-01-01T10:11:12Z"}

        mock_dt.now.return_value = expected_timestamp
        out.update_timestamp(sbom)

        self.assertDictEqual(expected_sbom, sbom)

    def test_add_tools_array(self):
        sbom = self.minimal_sbom

        expected_sbom = copy.deepcopy(sbom)
        expected_sbom["metadata"] = {
            "tools": [{"name": pkg.NAME, "vendor": pkg.VENDOR, "version": pkg.VERSION}]
        }

        out.update_tools(sbom)

        self.assertDictEqual(expected_sbom, sbom)

    def test_add_tools_object(self):
        sbom = self.minimal_sbom
        sbom["specVersion"] = "1.5"

        expected_sbom = copy.deepcopy(sbom)
        expected_sbom["metadata"] = {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": pkg.NAME,
                        "publisher": pkg.VENDOR,
                        "version": pkg.VERSION,
                    }
                ]
            }
        }

        out.update_tools(sbom)

        self.assertDictEqual(expected_sbom, sbom)

    def test_tool_already_present(self):
        sbom = self.minimal_sbom
        sbom["metadata"] = {
            "tools": [{"name": pkg.NAME, "vendor": pkg.VENDOR, "version": pkg.VERSION}]
        }

        expected_sbom = copy.deepcopy(sbom)

        out.update_tools(sbom)

        self.assertDictEqual(expected_sbom, sbom)

    def test_append_tool_to_array(self):
        sbom = self.minimal_sbom
        sbom["metadata"] = {"foo": "bar", "tools": [{"name": "some tool"}]}

        expected_sbom = copy.deepcopy(sbom)
        expected_sbom["metadata"]["tools"].append(
            {"name": pkg.NAME, "vendor": pkg.VENDOR, "version": pkg.VERSION}
        )

        out.update_tools(sbom)

        self.assertDictEqual(expected_sbom, sbom)

    def test_append_tool_to_object(self):
        sbom = self.minimal_sbom
        sbom["metadata"] = {
            "foo": "bar",
            "tools": {
                "components": [{"type": "application", "name": "some tool"}],
                "services": [{"name": "some service"}],
            },
        }

        expected_sbom = copy.deepcopy(sbom)
        expected_sbom["metadata"]["tools"]["components"].append(
            {
                "type": "application",
                "name": pkg.NAME,
                "publisher": pkg.VENDOR,
                "version": pkg.VERSION,
            }
        )

        out.update_tools(sbom)

        self.assertDictEqual(expected_sbom, sbom)

    def test_update_serial(self):
        sbom = self.minimal_sbom
        expected_sbom = copy.deepcopy(sbom)
        uuid_regex = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

        out.update_serial_number(sbom)

        self.assertRegex(sbom["serialNumber"], uuid_regex)

        # The rest of the SBOM should not have been modified
        del sbom["serialNumber"]
        self.assertDictEqual(expected_sbom, sbom)

    def test_update_version(self):
        sbom = self.minimal_sbom
        expected_sbom = copy.deepcopy(sbom)

        versions = [0, *random.sample(range(0, 2**32), 3)]

        for ver in versions:
            sbom["version"] = ver
            expected_sbom["version"] = ver + 1
            out.update_version(sbom)
            self.assertDictEqual(expected_sbom, sbom)

    @patch(f"{out.__name__}.update_timestamp")
    @patch(f"{out.__name__}.update_serial_number")
    @patch(f"{out.__name__}.update_tools")
    @patch(f"{out.__name__}.update_version")
    def test_write_to_stdout(
        self,
        mock_version: Mock,
        mock_tools: Mock,
        mock_serial: Mock,
        mock_timestamp: Mock,
    ):
        sbom = self.minimal_sbom

        with contextlib.redirect_stdout(io.StringIO()) as f:
            out.write_sbom(sbom, None, True)

        stdout = f.getvalue()
        expected = dedent(
            """\
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 0
        }"""
        )

        self.assertEqual(expected, stdout)
        mock_version.assert_called_once()
        mock_tools.assert_called_once()
        mock_serial.assert_called_once()
        mock_timestamp.assert_called_once()

    @patch(f"{out.__name__}.update_timestamp")
    @patch(f"{out.__name__}.update_serial_number")
    @patch(f"{out.__name__}.update_tools")
    @patch(f"{out.__name__}.update_version")
    def test_write_to_stdout_without_updates(
        self,
        mock_version: Mock,
        mock_tools: Mock,
        mock_serial: Mock,
        mock_timestamp: Mock,
    ):
        sbom = self.minimal_sbom
        expected = self.minimal_json

        with contextlib.redirect_stdout(io.StringIO()) as f:
            out.write_sbom(sbom, None, False)
        stdout = f.getvalue()

        self.assertEqual(expected, stdout)
        mock_version.assert_not_called()
        mock_tools.assert_not_called()
        mock_serial.assert_not_called()
        mock_timestamp.assert_not_called()


class OutputToFileTestCase(unittest.TestCase):
    @pytest.fixture(autouse=True)
    def init_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)  # change to pytest-provided temporary directory

    def setUp(self) -> None:
        self.minimal_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 0,
        }

        self.minimal_json = dedent(
            """\
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 0
        }"""
        )

    def test_write_to_file_in_existent_dir(self):
        sbom = self.minimal_sbom
        expected = self.minimal_json

        path = pathlib.Path("output.json")

        out.write_sbom(sbom, path, False)
        output = path.read_text()

        self.assertEqual(expected, output)

    def test_write_to_file_in_non_existent_dir(self):
        sbom = self.minimal_sbom
        expected = self.minimal_json

        path = pathlib.Path("doesnotexist") / "output.json"

        out.write_sbom(sbom, path, False)
        output = path.read_text()

        self.assertEqual(expected, output)

    def test_write_to_dir(self):
        sbom = self.minimal_sbom
        expected = self.minimal_json

        dir_path = pathlib.Path(".")
        expected_file_path = pathlib.Path("bom.json")

        out.write_sbom(sbom, dir_path, False)

        self.assertTrue(expected_file_path.is_file())

        output = expected_file_path.read_text()
        self.assertEqual(expected, output)
