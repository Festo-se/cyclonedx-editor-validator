import io
import os
import pathlib
import unittest
import unittest.mock
from contextlib import redirect_stdout
from json import JSONDecodeError
from pathlib import Path

from toml import load

# noinspection PyProtectedMember
from cdxev.__main__ import (
    _STATUS_APP_ERROR,
    _STATUS_OK,
    _STATUS_USAGE_ERROR,
    _STATUS_VALIDATION_ERROR,
    InputFileError,
    load_json,
    load_xml,
    main,
    read_sbom,
)


class TestSupplements(unittest.TestCase):
    def test_get_help(self) -> None:
        with unittest.mock.patch("sys.argv", ["", "--help"]):
            try:
                helper_text = io.StringIO()
                with redirect_stdout(helper_text):
                    main()
            except SystemExit:
                result = helper_text.getvalue()
                self.assertIn("usage:", result)

    @unittest.skipUnless("CI" in os.environ, "running only in CI")
    def test_get_version(self) -> None:
        with unittest.mock.patch("sys.argv", ["", "--version"]):
            try:
                pkg_version = io.StringIO()
                with redirect_stdout(pkg_version):
                    main()
            except SystemExit:
                toml_file = Path(__file__).parents[1] / "pyproject.toml"
                toml_content = load(toml_file)
                version_in_toml = (
                    toml_content.get("tool", {}).get("poetry", {}).get("version")
                )
                self.assertEqual(pkg_version.getvalue().strip(), version_in_toml)

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


class TestAmendCommand(unittest.TestCase):
    @unittest.mock.patch("cdxev.__main__.read_sbom")
    def test_get_amend(self, mock_read: unittest.mock.Mock) -> None:
        with unittest.mock.patch("sys.argv", ["", "amend", "fake_bom.cdx.json"]):
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, _STATUS_OK)

    @unittest.mock.patch("cdxev.__main__.read_sbom")
    def test_get_amend_license_from_folder(self, mock_read: unittest.mock.Mock) -> None:
        path = pathlib.Path(__file__).parent.resolve()
        with unittest.mock.patch(
            "sys.argv",
            [
                "",
                "amend",
                "fake_bom.cdx.json",
                str(("--license-path=" + path.as_posix() + "/auxiliary/licenses")),
            ],
        ):
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, _STATUS_OK)


class TestMergeCommand(unittest.TestCase):
    @unittest.mock.patch("cdxev.__main__.read_sbom")
    @unittest.mock.patch("cdxev.__main__.merge")
    def test_get_merge(
        self, mock_merge: unittest.mock.Mock, mock_read: unittest.mock.Mock
    ) -> None:
        with unittest.mock.patch(
            "sys.argv", ["", "merge", "fake_bom_1.cdx.json", "fake_bom_2.cdx.json"]
        ):
            mock_merge.return_value = {}
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, _STATUS_OK)

    def test_merge_usage_error(self) -> None:
        with unittest.mock.patch("sys.argv", ["", "merge", "fake_bom_1.cdx.json"]):
            with self.assertRaises(SystemExit) as ex:
                main()
            self.assertEqual(ex.exception.code, _STATUS_USAGE_ERROR)

    @unittest.mock.patch("cdxev.__main__.read_sbom")
    @unittest.mock.patch("cdxev.__main__.merge")
    def test_merge_from_folder(
        self, mock_merge: unittest.mock.Mock, mock_read: unittest.mock.Mock
    ) -> None:
        path = pathlib.Path(__file__).parent.resolve()
        with unittest.mock.patch(
            "sys.argv",
            [
                "",
                "merge",
                "fake_bom_1.cdx.json",
                ("--from-folder=" + path.as_posix() + "/auxiliary/test_amend_sboms"),
            ],
        ):
            mock_merge.return_value = {}
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, _STATUS_OK)

    @unittest.mock.patch("cdxev.__main__.read_sbom")
    def test_merge_from_folder_false_path(self, mock_read: unittest.mock.Mock) -> None:
        path = pathlib.Path(__file__).parent.resolve()
        with unittest.mock.patch(
            "sys.argv",
            [
                "",
                "merge",
                "fake_bom_1.cdx.json",
                ("--from-folder=" + path.as_posix() + "/NoPath"),
            ],
        ):
            with self.assertRaises(SystemExit) as ex:
                mock_read.return_value = ({}, "json")
                main()
            self.assertEqual(ex.exception.code, _STATUS_USAGE_ERROR)

    @unittest.mock.patch("cdxev.__main__.read_sbom")
    def test_merge_from_folder_no_sboms_in_folder(
        self, mock_read: unittest.mock.Mock
    ) -> None:
        path = pathlib.Path(__file__).parent.resolve()
        with unittest.mock.patch(
            "sys.argv",
            [
                "",
                "merge",
                "fake_bom_1.cdx.json",
                ("--from-folder=" + path.as_posix()),
            ],
        ):
            with self.assertRaises(SystemExit) as ex:
                mock_read.return_value = ({}, "json")
                main()
            self.assertEqual(ex.exception.code, _STATUS_USAGE_ERROR)


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
            self.assertEqual(result, _STATUS_OK)


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
            self.assertEqual(result, _STATUS_OK)

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
            self.assertEqual(result, _STATUS_OK)

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
            self.assertEqual(result, _STATUS_OK)

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
            self.assertEqual(result, _STATUS_OK)

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
            self.assertEqual(result, _STATUS_OK)

        with unittest.mock.patch(
            "sys.argv",
            ["", "set", "fake_bom_1.cdx.json", "--from-file", "fake_set.json"],
        ):
            mock_json_load.side_effect = JSONDecodeError("test", "test", 0)
            result = main()
            self.assertEqual(result, _STATUS_APP_ERROR)

    def test_set_usage_error(self) -> None:
        with unittest.mock.patch(
            "sys.argv",
            ["", "set", "fake_bom_1.cdx.json"],
        ):
            with self.assertRaises(SystemExit) as ex:
                main()
            self.assertEqual(ex.exception.code, _STATUS_USAGE_ERROR)

        with unittest.mock.patch(
            "sys.argv",
            ["", "set", "fake_bom_1.cdx.json", "--cpe", "<target-cpe>"],
        ):
            with self.assertRaises(SystemExit) as ex:
                main()
            self.assertEqual(ex.exception.code, _STATUS_USAGE_ERROR)

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
            self.assertEqual(ex.exception.code, _STATUS_USAGE_ERROR)

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
            self.assertEqual(ex.exception.code, _STATUS_USAGE_ERROR)

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
            self.assertEqual(ex.exception.code, _STATUS_USAGE_ERROR)

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
            self.assertEqual(ex.exception.code, _STATUS_USAGE_ERROR)


class TestValidateCommand(unittest.TestCase):
    @unittest.mock.patch("cdxev.__main__.read_sbom")
    @unittest.mock.patch("cdxev.__main__.validate_sbom")
    def test_get_validate(
        self, mock_validate: unittest.mock.Mock, mock_read: unittest.mock.Mock
    ) -> None:
        with unittest.mock.patch("sys.argv", ["", "validate", "fake_bom.cdx.json"]):
            mock_validate.return_value = 0
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, _STATUS_OK)
        with unittest.mock.patch("sys.argv", ["", "validate", "fake_bom.cdx.json"]):
            mock_validate.return_value = 1
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, _STATUS_VALIDATION_ERROR)
        with unittest.mock.patch(
            "sys.argv", ["", "validate", "--schema-type=custom", "fake_bom.cdx.json"]
        ):
            mock_validate.return_value = 0
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, _STATUS_OK)
        with unittest.mock.patch(
            "sys.argv",
            [
                "",
                "validate",
                "fake_bom.cdx.json",
                "--report-format",
                "warnings-ng",
                "--output",
                "issues_file.json",
            ],
        ):
            mock_validate.return_value = 0
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, _STATUS_OK)
        with unittest.mock.patch(
            "sys.argv",
            [
                "",
                "validate",
                "fake_bom.cdx.json",
                "--output",
                "issues_file.json",
                "--filename-pattern",
                ".*",
            ],
        ):
            mock_validate.return_value = 0
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, _STATUS_OK)


class TestBuildPublicCommand(unittest.TestCase):
    @unittest.mock.patch("cdxev.__main__.read_sbom")
    @unittest.mock.patch("cdxev.__main__.build_public_bom")
    def test_get_build_public_bom(
        self, mock_build_public: unittest.mock.Mock, mock_read: unittest.mock.Mock
    ) -> None:
        with unittest.mock.patch(
            "sys.argv", ["", "build-public", "fake_bom.cdx.json", "fake_schema.json"]
        ):
            mock_build_public.return_value = {}
            mock_read.return_value = ({}, "json")
            result = main()
            self.assertEqual(result, _STATUS_OK)
