# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
import unittest.mock
from pathlib import Path

# noinspection PyProtectedMember
from cdxev.__main__ import InputFileError, load_json, load_xml, read_sbom


class TestSupplements(unittest.TestCase):
    @unittest.mock.patch("pathlib.Path.is_file")
    def test_read_sbom(self, mock_is_file: unittest.mock.Mock) -> None:
        with self.assertRaises(InputFileError) as ie:
            mock_is_file.return_value = False
            read_sbom(Path("test.json"))
        self.assertEqual("File not found: test.json", ie.exception.details.description)
        with self.assertRaises(InputFileError) as ie:
            mock_is_file.return_value = True
            read_sbom(Path("test.jason"))
        self.assertIn(
            "Failed to guess file type from extension", ie.exception.details.description
        )
        with unittest.mock.patch("cdxev.__main__.load_json", return_value={}):
            mock_is_file.return_value = True
            result = read_sbom(Path("test.json"))[0]
            self.assertEqual(result, {})

    @unittest.mock.patch(
        "pathlib.Path.open", unittest.mock.mock_open(read_data="not a json")
    )
    def test_load_json(self) -> None:
        with unittest.mock.patch("json.load", return_value={"sbom": []}):
            result = load_json(Path("test.json"))
            self.assertDictEqual({"sbom": []}, result)
        with self.assertRaises(InputFileError) as ie:
            load_json(Path("not_a_json.json"))
        self.assertEqual("Invalid JSON", ie.exception.details.description)

    def test_load_xml(self) -> None:
        with self.assertRaises(InputFileError) as ie:
            load_xml(Path("test.xml"))
        self.assertIn("XML files aren't supported", ie.exception.details.description)
