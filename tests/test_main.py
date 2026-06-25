# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
import unittest.mock
from argparse import Namespace
from pathlib import Path

# noinspection PyProtectedMember
from cdxev.__main__ import (
    InputFileError,
    _set_target_update_id,
    load_json,
    load_xml,
    read_sbom,
)


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
        self.assertIn("Failed to guess file type from extension", ie.exception.details.description)
        with unittest.mock.patch("cdxev.__main__.load_json", return_value={}):
            mock_is_file.return_value = True
            result = read_sbom(Path("test.json"))[0]
            self.assertEqual(result, {})

    @unittest.mock.patch("pathlib.Path.open", unittest.mock.mock_open(read_data="not a json"))
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


class TestSetCliHelpers(unittest.TestCase):
    def _base_set_args(self) -> Namespace:
        return Namespace(
            swid=None,
            cpe=None,
            purl=None,
            name=None,
            group=None,
            version=None,
            version_range=None,
            name_pattern=None,
            group_pattern=None,
            cpe_pattern=None,
            purl_pattern=None,
            parser=None,
        )

    def test_set_target_update_id_name_pattern(self) -> None:
        args = self._base_set_args()
        args.name_pattern = "dep.*"

        update_id = _set_target_update_id(args)

        self.assertEqual(update_id, {"namePattern": "dep.*"})

    def test_set_target_update_id_coordinates_with_version_range(self) -> None:
        args = self._base_set_args()
        args.name = "web-framework"
        args.group = "org.acme"
        args.version_range = "vers:generic/*"

        update_id = _set_target_update_id(args)

        self.assertEqual(
            update_id,
            {
                "name": "web-framework",
                "group": "org.acme",
                "version-range": "vers:generic/*",
            },
        )

    def test_set_target_update_id_name_pattern_with_version_range(self) -> None:
        args = self._base_set_args()
        args.name_pattern = "web-.*"
        args.version_range = "vers:generic/*"

        update_id = _set_target_update_id(args)

        self.assertEqual(
            update_id,
            {
                "namePattern": "web-.*",
                "version-range": "vers:generic/*",
            },
        )

    def test_set_target_update_id_name_pattern_with_group_pattern(self) -> None:
        args = self._base_set_args()
        args.name_pattern = "web-.*"
        args.group_pattern = "org\\..*"

        update_id = _set_target_update_id(args)

        self.assertEqual(
            update_id,
            {
                "namePattern": "web-.*",
                "group": {"regex": "org\\..*"},
            },
        )

    def test_set_target_update_id_cpe_pattern(self) -> None:
        args = self._base_set_args()
        args.cpe_pattern = "cpe:/a:example:.*"

        update_id = _set_target_update_id(args)

        self.assertEqual(update_id, {"cpePattern": "cpe:/a:example:.*"})

    def test_set_target_update_id_purl_pattern(self) -> None:
        args = self._base_set_args()
        args.purl_pattern = "pkg:npm/test-app@.*"

        update_id = _set_target_update_id(args)

        self.assertEqual(update_id, {"purlPattern": "pkg:npm/test-app@.*"})

    def test_set_target_update_id_group_pattern_requires_name_pattern(self) -> None:
        args = self._base_set_args()
        args.group_pattern = "org\\..*"

        with self.assertRaises(SystemExit):
            _set_target_update_id(args)

    def test_set_target_update_id_cpe_pattern_rejects_coordinates_options(self) -> None:
        args = self._base_set_args()
        args.cpe_pattern = "cpe:/a:example:.*"
        args.version_range = "vers:generic/*"

        with self.assertRaises(SystemExit):
            _set_target_update_id(args)
