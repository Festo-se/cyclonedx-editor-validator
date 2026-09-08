# SPDX-License-Identifier: GPL-3.0-or-later

import datetime as dt
import unittest
from unittest.mock import patch

import cdxev.auxiliary.filename_gen as fn


class FilenameGeneratorTestCase(unittest.TestCase):
    def setUp(self):
        self.sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": "2000-01-01T12:30:45Z",
                "component": {
                    "name": "Test",
                    "version": "1.0",
                    "hashes": [
                        {"alg": "SHA-512", "content": "abcdefg"},
                        {"alg": "MD5", "content": "1234567890"},
                    ],
                },
            },
        }

    def test_empty(self):
        del self.sbom["metadata"]
        filename = fn.generate_filename(self.sbom)
        self.assertEqual("bom.json", filename)

    def test_normal(self):
        filename = fn.generate_filename(self.sbom)
        self.assertEqual("Test_1.0_20000101T123045.cdx.json", filename)

    def test_no_name(self):
        del self.sbom["metadata"]["component"]["name"]
        filename = fn.generate_filename(self.sbom)
        self.assertEqual("unknown_1.0_20000101T123045.cdx.json", filename)

    def test_no_version(self):
        del self.sbom["metadata"]["component"]["version"]
        filename = fn.generate_filename(self.sbom)
        self.assertEqual("Test_20000101T123045.cdx.json", filename)

    @patch(f"{fn.__name__}.datetime", wraps=dt.datetime)
    def test_no_timestamp(self, mock_dt):
        mock_dt.now.return_value = dt.datetime(1999, 1, 1, 10, 11, 12, tzinfo=dt.timezone.utc)

        del self.sbom["metadata"]["timestamp"]
        filename = fn.generate_filename(self.sbom)
        self.assertEqual("Test_1.0_19990101T101112.cdx.json", filename)

    @patch(f"{fn.__name__}.datetime", wraps=dt.datetime)
    def test_only_name(self, mock_dt):
        mock_dt.now.return_value = dt.datetime(1999, 1, 1, 10, 11, 12, tzinfo=dt.timezone.utc)

        del self.sbom["metadata"]["timestamp"]
        del self.sbom["metadata"]["component"]["version"]
        filename = fn.generate_filename(self.sbom)
        self.assertEqual("Test_19990101T101112.cdx.json", filename)

    @patch(f"{fn.__name__}.datetime", wraps=dt.datetime)
    def test_only_version(self, mock_dt):
        mock_dt.now.return_value = dt.datetime(1999, 1, 1, 10, 11, 12, tzinfo=dt.timezone.utc)

        del self.sbom["metadata"]["timestamp"]
        del self.sbom["metadata"]["component"]["name"]
        filename = fn.generate_filename(self.sbom)
        self.assertEqual("unknown_1.0_19990101T101112.cdx.json", filename)

    def test_only_timestamp(self):
        del self.sbom["metadata"]["component"]["name"]
        del self.sbom["metadata"]["component"]["version"]
        filename = fn.generate_filename(self.sbom)
        self.assertEqual("unknown_20000101T123045.cdx.json", filename)

    @patch(f"{fn.__name__}.datetime", wraps=dt.datetime)
    @patch(f"{fn.__name__}.logger")
    def test_invalid_timestamp(self, mock_logger, mock_dt):
        mock_dt.now.return_value = dt.datetime(1999, 1, 1, 10, 11, 12, tzinfo=dt.timezone.utc)

        self.sbom["metadata"]["timestamp"] = "foo"
        filename = fn.generate_filename(self.sbom)
        self.assertEqual("Test_1.0_19990101T101112.cdx.json", filename)
        mock_logger.info.assert_called_once()

    def test_name_with_underscore(self):
        self.sbom["metadata"]["component"]["name"] = "Te_ST"
        filename = fn.generate_filename(self.sbom)
        self.assertEqual("Te_ST_1.0_20000101T123045.cdx.json", filename)

    def test_name_with_path_separator(self):
        self.sbom["metadata"]["component"]["name"] = "Te\\st"
        filename = fn.generate_filename(self.sbom)
        self.assertEqual("Test_1.0_20000101T123045.cdx.json", filename)

    def test_version_with_underscore(self):
        self.sbom["metadata"]["component"]["version"] = "1.0_build1"
        filename = fn.generate_filename(self.sbom)
        self.assertEqual("Test_1.0_build1_20000101T123045.cdx.json", filename)
