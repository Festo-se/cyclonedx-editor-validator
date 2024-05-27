# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
import unittest.mock
from json import JSONDecodeError
from pathlib import Path

# noinspection PyProtectedMember
from cdxev.__main__ import InputFileError, Status, load_json, load_xml, main, read_sbom


class TestSupplements(unittest.TestCase):
    @unittest.mock.patch("pathlib.Path.is_file")
    def test_read_sbom(self, mock_is_file: unittest.mock.Mock) -> None:
        with self.assertRaises(InputFileError) as ie:
            mock_is_file.return_value = False
            read_sbom(Path("test.json"))
        self.assertEqual("File not found.", ie.exception.details.description)
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


class TestMergeVexCommand(unittest.TestCase):
    @unittest.mock.patch("cdxev.__main__.read_sbom")
    @unittest.mock.patch("cdxev.__main__.merge_vex")
    def test_get_merge_vex(
        self, mock_merge_vex: unittest.mock.Mock, mock_read: unittest.mock.Mock
    ) -> None:
        with unittest.mock.patch(
            "sys.argv", ["", "merge-vex", "fake_bom_1.cdx.json", "fake_bom_2.cdx.json"]
        ):
            mock_merge_vex.return_value = {}
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, Status.OK)


class TestSetCommand(unittest.TestCase):
    sample_cpe = '"cpe:/a:example:mylibrary:1.0.0"'
    sample_purl = '"pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.14"'
    sample_swid = '{"tagId": "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1"}'

    @unittest.mock.patch("cdxev.__main__.read_sbom")
    @unittest.mock.patch("cdxev.set.run")
    def test_get_set_from_targets(
        self, mock_set: unittest.mock.Mock, mock_read: unittest.mock.Mock
    ) -> None:
        with unittest.mock.patch(
            "sys.argv",
            [
                "",
                "set",
                "fake_bom_1.cdx.json",
                "--cpe",
                self.sample_cpe,
                "--key",
                "copyright",
                "--value",
                '"2022 Acme Inc"',
            ],
        ):
            mock_set.return_value = {}
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, Status.OK)

        with unittest.mock.patch(
            "sys.argv",
            [
                "",
                "set",
                "fake_bom_1.cdx.json",
                "--purl",
                self.sample_purl,
                "--key",
                "copyright",
                "--value",
                '"2022 Acme Inc"',
            ],
        ):
            mock_set.return_value = {}
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, Status.OK)

        with unittest.mock.patch(
            "sys.argv",
            [
                "",
                "set",
                "fake_bom_1.cdx.json",
                "--swid",
                self.sample_swid,
                "--key",
                "copyright",
                "--value",
                '"2022 Acme Inc"',
            ],
        ):
            mock_set.return_value = {}
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, Status.OK)

        with unittest.mock.patch(
            "sys.argv",
            [
                "",
                "set",
                "fake_bom_1.cdx.json",
                "--name",
                "<target-name>",
                "--group",
                "<target-group",
                "--version",
                "<target-version",
                "--key",
                "copyright",
                "--value",
                '"2022 Acme Inc"',
            ],
        ):
            mock_set.return_value = {}
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, Status.OK)

        with unittest.mock.patch(
            "sys.argv",
            [
                "",
                "set",
                "fake_bom_1.cdx.json",
                "--name",
                "<target-name>",
                "--group",
                "<target-group",
                "--version-range",
                "vers:generic/*",
                "--key",
                "copyright",
                "--value",
                '"2022 Acme Inc"',
            ],
        ):
            mock_set.return_value = {}
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, Status.OK)

    @unittest.mock.patch("cdxev.__main__.read_sbom")
    @unittest.mock.patch("cdxev.set.run")
    @unittest.mock.patch(
        "builtins.open", unittest.mock.mock_open(read_data="some data")
    )
    @unittest.mock.patch("json.load")
    def test_get_set_from_file(
        self,
        mock_json_load: unittest.mock.Mock,
        mock_set: unittest.mock.Mock,
        mock_read: unittest.mock.Mock,
    ) -> None:
        with unittest.mock.patch(
            "sys.argv",
            ["", "set", "fake_bom_1.cdx.json", "--from-file", "fake_set.json"],
        ):
            mock_set.return_value = {}
            mock_read.return_value = ({}, "json")
            mock_json_load.return_value = {
                "id": {"cpe": "<target-cpe>"},
                "set": {"copyright": "2022 Acme Inc"},
            }
            result = main()
            self.assertEqual(result, Status.OK)

        with unittest.mock.patch(
            "sys.argv",
            ["", "set", "fake_bom_1.cdx.json", "--from-file", "fake_set.json"],
        ):
            mock_json_load.side_effect = JSONDecodeError("test", "test", 0)
            result = main()
            self.assertEqual(result, Status.APP_ERROR)

    def test_set_usage_error(self) -> None:
        with unittest.mock.patch(
            "sys.argv",
            ["", "set", "fake_bom_1.cdx.json"],
        ):
            with self.assertRaises(SystemExit) as ex:
                main()
            self.assertEqual(ex.exception.code, Status.USAGE_ERROR)

        with unittest.mock.patch(
            "sys.argv",
            ["", "set", "fake_bom_1.cdx.json", "--cpe", "<target-cpe>"],
        ):
            with self.assertRaises(SystemExit) as ex:
                main()
            self.assertEqual(ex.exception.code, Status.USAGE_ERROR)

        with unittest.mock.patch(
            "sys.argv",
            [
                "",
                "set",
                "fake_bom_1.cdx.json",
                "--cpe",
                "<target-cpe>",
                "--key",
                "copyright",
            ],
        ):
            with self.assertRaises(SystemExit) as ex:
                main()
            self.assertEqual(ex.exception.code, Status.USAGE_ERROR)

        with unittest.mock.patch(
            "sys.argv",
            [
                "",
                "set",
                "fake_bom_1.cdx.json",
                "--purl",
                "<target-purl>",
                "--cpe",
                "<target-cpe>",
                "--key",
                "copyright",
                "--value",
                '"2022 Acme Inc"',
            ],
        ):
            with self.assertRaises(SystemExit) as ex:
                main()
            self.assertEqual(ex.exception.code, Status.USAGE_ERROR)

        with unittest.mock.patch(
            "sys.argv",
            [
                "",
                "set",
                "fake_bom_1.cdx.json",
                "--cpe",
                "<target-cpe>",
                "--key",
                "copyright",
                "--value",
                "2022 Acme Inc",
            ],
        ):
            with self.assertRaises(SystemExit) as ex:
                main()
            self.assertEqual(ex.exception.code, Status.USAGE_ERROR)

        with unittest.mock.patch(
            "sys.argv",
            [
                "",
                "set",
                "fake_bom_1.cdx.json",
                "--from-file",
                "fake_set.json",
                "--cpe",
                "<target-cpe>",
            ],
        ):
            with self.assertRaises(SystemExit) as ex:
                main()
            self.assertEqual(ex.exception.code, Status.USAGE_ERROR)
