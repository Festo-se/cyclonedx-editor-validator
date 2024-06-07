import json
import logging
import os
import re
from collections.abc import Callable
from itertools import chain
from pathlib import Path
from typing import TypedDict

import pytest
import toml

from cdxev.__main__ import Status
from cdxev.amend.operations import AddLicenseText
from tests.auxiliary.sbomFunctionsTests import search_entry
from tests.integration.helper import load_sbom, run_main


def test_help(argv: Callable[..., None], capsys: pytest.CaptureFixture[str]):
    argv("--help")
    with pytest.raises(SystemExit) as e:
        run_main()

    assert e.value.code == Status.OK
    stdout, _ = capsys.readouterr()
    assert stdout.startswith("usage: ")


def test_no_options(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as e:
        run_main()

    assert e.value.code == Status.USAGE_ERROR
    _, stderr = capsys.readouterr()
    assert stderr.startswith("usage: ")


def test_version(argv: Callable[..., None], capsys: pytest.CaptureFixture[str]):
    argv("--version")
    with pytest.raises(SystemExit) as e:
        run_main()

    assert e.value.code == Status.OK
    stdout, _ = capsys.readouterr()
    assert re.match(r"[0-9]+\.[0-9]+\.[0-9]+", stdout) is not None


@pytest.mark.skipif(
    "CI" not in os.environ, reason="Run only in CI, after a clean install"
)
def test_version_from_pyproject(
    argv: Callable[..., None], capsys: pytest.CaptureFixture[str]
):
    toml_file = Path(__file__).parents[2] / "pyproject.toml"
    toml_content = toml.load(toml_file)
    expected_version = toml_content.get("tool", {}).get("poetry", {}).get("version")

    argv("--version")
    with pytest.raises(SystemExit) as e:
        run_main()

    assert e.value.code == Status.OK
    stdout, _ = capsys.readouterr()
    assert stdout.strip() == expected_version


def test_dir_output(
    argv: Callable[..., None],
    data_dir: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    # The actual command and inputs don't matter for this test.
    # It is only meant to test that output to a directory works.
    argv(
        "amend",
        "--output",
        str(tmp_path),
        str(data_dir / "amend.input.cdx.json"),
    )
    exit_code, output_file, _ = run_main(capsys, "filename")

    # Verify that command completed successfully
    assert exit_code == Status.OK

    # Verify that output matches what is expected
    actual = load_sbom(tmp_path / output_file)
    expected = load_sbom(data_dir / "amend.expected_default.cdx.json")
    assert actual == expected


def test_file_output(
    argv: Callable[..., None],
    data_dir: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    # The actual command and inputs don't matter for this test.
    # It is only meant to test that output to a file works.
    output_file = tmp_path / "output.cdx.json"
    argv(
        "amend",
        "--output",
        str(output_file),
        str(data_dir / "amend.input.cdx.json"),
    )
    exit_code, *_ = run_main(capsys)

    # Verify that command completed successfully
    assert exit_code == Status.OK

    # Verify that output matches what is expected
    actual = load_sbom(output_file)
    expected = load_sbom(data_dir / "amend.expected_default.cdx.json")
    assert actual == expected


class TestAmend:
    class DataFixture(TypedDict):
        input: Path
        expected: dict
        operations: list[str]

    @pytest.fixture(
        scope="class",
        params=[
            {
                "input": "amend.input.cdx.json",
                "expected": "amend.expected_default.cdx.json",
                "operations": [],
            },
            {
                "input": "amend.input.cdx.json",
                "expected": "amend.expected_infer-copyright.cdx.json",
                "operations": ["infer-copyright"],
            },
        ],
        ids=["default operations", "single operation"],
    )
    def data(self, data_dir: Path, request: pytest.FixtureRequest) -> DataFixture:
        input_path = data_dir / request.param["input"]
        expected_path = data_dir / request.param["expected"]
        expected_json = load_sbom(expected_path)

        return self.DataFixture(
            input=input_path,
            expected=expected_json,
            operations=request.param["operations"],
        )

    def test(
        self,
        data: DataFixture,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ):
        operations = chain.from_iterable(
            ("--operation", op) for op in data["operations"]
        )
        argv(
            "amend",
            *operations,
            str(data["input"]),
        )
        exit_code, actual, _ = run_main(capsys, "json")

        # Verify that command completed successfully
        assert exit_code == Status.OK

        # Verify that output matches what is expected
        assert actual == data["expected"]

    def test_with_operation_arg(
        self,
        data_dir: Path,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ):
        argv(
            "amend",
            "--operation",
            "add-license-text",
            "--license-dir",
            str(data_dir / "license-texts"),
            str(data_dir / "amend.input_licenses.cdx.json"),
        )
        exit_code, actual, _ = run_main(capsys, "json")

        # Verify that command completed successfully
        assert exit_code == Status.OK

        expected = load_sbom(data_dir / "amend.expected_add-license-text.cdx.json")
        assert actual == expected

    def test_missing_operation_arg(
        self, argv: Callable[..., None], capsys: pytest.CaptureFixture[str]
    ):
        argv("amend", "--operation", "add-license-text", "any.cdx.json")
        with pytest.raises(SystemExit) as e:
            run_main()

        assert e.value.code == Status.USAGE_ERROR
        _, stderr = capsys.readouterr()
        assert re.search(r"is required for operation", stderr)

    def test_help_operation(
        self, argv: Callable[..., None], capsys: pytest.CaptureFixture[str]
    ):
        argv("amend", "--help-operation", "add-license-text")
        exit_code, stdout, _ = run_main(capsys=capsys)

        assert exit_code == Status.OK

        # Compare stdout to operation class docstring, stripping out any non-alphanumeric
        # characters. These might differ due to formatting.
        non_alnum = re.compile(r"[\W]+")
        expected = non_alnum.sub("", AddLicenseText.__doc__)  # type: ignore
        actual = non_alnum.sub("", stdout)

        assert actual == expected


class TestBuildPublic:
    class DataFixture(TypedDict):
        input: Path
        schema: Path
        expected: dict

    @pytest.fixture(
        scope="class",
        params=[
            {
                "input": "build-public.input.cdx.json",
                "schema": "build-public.input.schema.json",
                "expected": "build-public.expected.cdx.json",
            }
        ],
    )
    def data(self, data_dir: Path, request: pytest.FixtureRequest) -> DataFixture:
        input_path = data_dir / request.param["input"]
        schema_path = data_dir / request.param["schema"]
        expected_path = data_dir / request.param["expected"]
        expected_json = load_sbom(expected_path)

        return self.DataFixture(
            input=input_path,
            expected=expected_json,
            schema=schema_path,
        )

    def test(
        self,
        data: DataFixture,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ):
        argv(
            "build-public",
            str(data["input"]),
            str(data["schema"]),
        )
        exit_code, actual, _ = run_main(capsys, "json")

        # Verify that command completed successfully
        assert exit_code == Status.OK

        # Verify that output matches what is expected
        assert actual == data["expected"]


class TestMerge:
    class DataFixture(TypedDict):
        inputs: list[Path]
        expected: dict

    @pytest.fixture(
        scope="class",
        params=[
            {
                "inputs": ["merge.input_1.cdx.json", "merge.input_2.cdx.json"],
                "expected": "merge.expected.cdx.json",
            }
        ],
    )
    def data(self, data_dir: Path, request: pytest.FixtureRequest) -> DataFixture:
        input_paths = [data_dir / p for p in request.param["inputs"]]
        expected_path = data_dir / request.param["expected"]
        expected_json = load_sbom(expected_path)

        return self.DataFixture(
            inputs=input_paths,
            expected=expected_json,
        )

    def test(
        self,
        data: DataFixture,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ):
        argv(
            "merge",
            *(str(p) for p in data["inputs"]),
        )
        exit_code, actual, _ = run_main(capsys, "json")

        # Verify that command completed successfully
        assert exit_code == Status.OK

        # Verify that output matches what is expected
        assert actual == data["expected"]

    def test_from_folder(
        self,
        argv: Callable[..., None],
        data_dir: Path,
        caplog: pytest.LogCaptureFixture,
        tmp_path: Path,
    ):
        output_file = tmp_path / "output.cdx.json"
        argv(
            "--verbose",
            "merge",
            str(data_dir / "merge.input_1.cdx.json"),
            "--from-folder",
            str(data_dir),
            "--output",
            str(output_file),
        )
        exit_code, *_ = run_main()

        assert exit_code == Status.OK

        # Assert that several SBOMs have been loaded. The exact number is unimportant because we
        # don't want to update this test whenever new SBOMs are added.
        assert (
            len([entry for entry in caplog.record_tuples if entry[1] == logging.DEBUG])
            > 5
        )

        # We're not comparing the result against a known output because we don't want to update
        # it whenever anything in the data directory changes.
        # Instead, we're validating the result for correctness, that's all.
        argv("validate", "--no-filename-validation", str(output_file))
        exit_code, *_ = run_main()

        assert exit_code == Status.OK

    def test_not_enough_inputs(self, argv: Callable[..., None]):
        argv("merge", "input1.cdx.json")
        with pytest.raises(SystemExit) as e:
            run_main()

        assert e.value.code == Status.USAGE_ERROR

    def test_invalid_folder_path(
        self,
        argv: Callable[..., None],
        data_dir: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        argv(
            "merge",
            str(data_dir / "merge.input_1.cdx.json"),
            "--from-folder",
            "doesnotexist",
        )
        with pytest.raises(SystemExit) as e:
            run_main()

        assert e.value.code == Status.USAGE_ERROR
        _, stderr = capsys.readouterr()
        assert stderr.find("Path not found or is not a directory") >= 0

    def test_empty_folder_path(
        self,
        argv: Callable[..., None],
        data_dir: Path,
        tmp_path: Path,
    ):
        argv(
            "merge",
            str(data_dir / "merge.input_1.cdx.json"),
            "--from-folder",
            str(tmp_path),
        )
        with pytest.raises(SystemExit) as e:
            run_main()

        assert e.value.code == Status.USAGE_ERROR


class TestSet:
    class DataFixture(TypedDict):
        input: Path
        set_file: Path
        expected: dict

    @pytest.fixture
    def input_file(self, data_dir: Path) -> Path:
        return data_dir / "set.input.cdx.json"

    @pytest.fixture(
        scope="class",
        params=[
            {
                "input": "set.input.cdx.json",
                "set_file": "set.input.json",
                "expected": "set.expected.cdx.json",
            }
        ],
    )
    def data(self, data_dir: Path, request: pytest.FixtureRequest) -> DataFixture:
        input_path = data_dir / request.param["input"]
        set_file_path = data_dir / request.param["set_file"]
        expected_path = data_dir / request.param["expected"]
        expected_json = load_sbom(expected_path)

        return self.DataFixture(
            input=input_path,
            expected=expected_json,
            set_file=set_file_path,
        )

    def test_direct(
        self,
        input_file: Path,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ):
        argv(
            "set",
            str(input_file),
            "--purl",
            "pkg:npm/test-app@1.0.0",
            "--key",
            "copyright",
            "--value",
            '"ACME Inc."',
        )
        exit_code, actual, _ = run_main(capsys, "json")

        assert exit_code == Status.OK
        target_component = search_entry(actual, "purl", "pkg:npm/test-app@1.0.0")
        assert target_component is not None
        assert target_component["copyright"] == "ACME Inc."

    def test_from_file(
        self,
        data: DataFixture,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ):
        argv(
            "set",
            "--force",
            "--from-file",
            str(data["set_file"]),
            str(data["input"]),
        )
        exit_code, actual, _ = run_main(capsys, "json")

        # Verify that command completed successfully
        assert exit_code == Status.OK

        # Verify that output matches what is expected
        assert actual == data["expected"]

    @pytest.mark.parametrize(
        "use_only",
        [
            ["name", "purl", "key", "value"],
            ["name", "swid", "key", "value"],
            ["purl", "swid", "key", "value"],
            ["name", "cpe", "key", "value"],
            ["version", "group", "key", "value"],
            ["key", "value"],
            ["name", "key"],
            ["name", "value"],
            ["from-file", "name"],
            ["from-file", "key", "value"],
        ],
        ids=lambda keys: "only: " + ", ".join(keys),
    )
    def test_invalid_option_combinations(
        self, use_only: list[str], input_file: Path, argv: Callable[..., None]
    ):
        options = {
            "name": "comp",
            "version": "1.0.0",
            "group": "acme",
            "purl": "pkg:test/comp@1.0.0",
            "swid": "foo",
            "cpe": "cpe:2.3:a:acme:comp:*:*:*:*:*:*:*:*",
            "key": "copyright",
            "value": "ACME Inc.",
            "from-file": "some-file.json",
        }
        filtered_options = {f"--{k}": v for (k, v) in options.items() if k in use_only}
        argv("set", str(input_file), *filtered_options)
        with pytest.raises(SystemExit) as e:
            run_main()

        assert e.value.code == Status.USAGE_ERROR

    @pytest.mark.parametrize(
        "value",
        [
            "foobar",
            "[1,2,3",
        ],
        ids=["string without quotes", "unclosed array"],
    )
    def test_invalid_json_value(
        self,
        value,
        input_file: Path,
        argv: Callable[..., None],
    ):
        argv("set", str(input_file), "--name", "comp", "--key", "foo", "--value", value)
        with pytest.raises(SystemExit) as e:
            run_main()

        assert e.value.code == Status.USAGE_ERROR

    def test_set_file_not_found(
        self,
        input_file: Path,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ):
        argv("set", str(input_file), "--from-file", "notfound")
        exit_code, _, stderr = run_main(capsys)

        assert exit_code == Status.APP_ERROR
        assert stderr.find("File not found") >= 0

    def test_input_not_found(
        self, argv: Callable[..., None], capsys: pytest.CaptureFixture[str]
    ):
        argv(
            "set",
            "notfound",
            "--name",
            "comp",
            "--key",
            "copyright",
            "--value",
            '"ACME Inc."',
        )
        exit_code, _, stderr = run_main(capsys)

        assert exit_code == Status.APP_ERROR
        assert stderr.find("File not found: notfound") >= 0

    def test_target_not_found(
        self,
        input_file: Path,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ):
        argv(
            "set",
            str(input_file),
            "--name",
            "comp",
            "--key",
            "copyright",
            "--value",
            '"ACME Inc."',
        )
        exit_code, _, stderr = run_main(capsys)

        assert exit_code == Status.APP_ERROR
        assert stderr.find('"COORDINATES[comp]" was not found') >= 0

    def test_target_not_found_ignored(
        self,
        input_file: Path,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ):
        argv(
            "set",
            str(input_file),
            "--name",
            "comp",
            "--key",
            "copyright",
            "--value",
            '"ACME Inc."',
            "--ignore-missing",
        )
        exit_code, _, stderr = run_main(capsys)

        assert exit_code == Status.OK
        assert stderr.find('"COORDINATES[comp]" was not found') >= 0

    def test_allow_protected(
        self,
        input_file: Path,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ):
        argv(
            "set",
            str(input_file),
            "--purl",
            "pkg:npm/test-app@1.0.0",
            "--key",
            "version",
            "--value",
            '"2.0.0"',
            "--force",
        )
        exit_code, _, stderr = run_main(capsys)

        assert exit_code == Status.APP_ERROR
        assert stderr.find("--allow-protected") >= 0

        argv(
            "set",
            str(input_file),
            "--purl",
            "pkg:npm/test-app@1.0.0",
            "--key",
            "version",
            "--value",
            '"2.0.0"',
            "--force",
            "--allow-protected",
        )
        exit_code, *_ = run_main(capsys)

        assert exit_code == Status.OK


class TestValidate:
    # This test function is parametrized by pytest_generate_tests in conftest.py.
    def test(
        self,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
        input,
        schema_type,
        expected_result,
        expected_errors,
    ):
        argv(
            "validate",
            "--schema-type",
            schema_type,
            str(input),
        )
        if expected_errors:
            exit_code, _, stderr = run_main(capsys)
            for e in expected_errors:
                assert e in stderr
        else:
            exit_code, _ = run_main()

        expected_exit_code = {"valid": Status.OK, "invalid": Status.VALIDATION_ERROR}[
            expected_result
        ]
        assert exit_code == expected_exit_code

    def test_warnings_ng(
        self, argv: Callable[..., None], data_dir: Path, tmp_path: Path
    ):
        report_path = tmp_path / "issues.json"
        argv(
            "validate",
            "--report-format",
            "warnings-ng",
            "--output",
            str(report_path),
            str(data_dir / "validate" / "invalid" / "default" / "laravel.cdx.json"),
        )
        exit_code, *_ = run_main()

        assert exit_code == Status.VALIDATION_ERROR

        # Assert that the report file exists and has the expected structure
        assert report_path.is_file()
        with open(report_path) as f:
            report = json.load(f)
        assert "issues" in report
        assert len(report["issues"]) == 1
        assert "origin" in report["issues"][0]

    def test_gitlab_cq(self, argv: Callable[..., None], data_dir: Path, tmp_path: Path):
        report_path = tmp_path / "issues.json"
        argv(
            "validate",
            "--report-format",
            "gitlab-code-quality",
            "--output",
            str(report_path),
            str(data_dir / "validate" / "invalid" / "default" / "laravel.cdx.json"),
        )
        exit_code, *_ = run_main()

        assert exit_code == Status.VALIDATION_ERROR

        # Assert that the report file exists and has the expected structure
        assert report_path.is_file()
        with open(report_path) as f:
            report = json.load(f)
        assert len(report) == 1
        assert "check_name" in report[0]

    def test_custom_filename_pattern(
        self,
        argv: Callable[..., None],
        data_dir: Path,
        caplog: pytest.LogCaptureFixture,
    ):
        argv(
            "validate",
            "--filename-pattern",
            "fail",
            str(data_dir / "validate" / "valid" / "default" / "laravel.cdx.json"),
        )
        exit_code, *_ = run_main()

        assert exit_code == Status.VALIDATION_ERROR
        assert len(caplog.records) == 1
        assert (
            caplog.records[0].msg.description  # type: ignore
            == "filename doesn't match regular expression fail"
        )

    def test_custom_schema(
        self,
        argv: Callable[..., None],
        data_dir: Path,
        caplog: pytest.LogCaptureFixture,
    ):
        argv(
            "validate",
            "--schema-path",
            str(data_dir / "validate.custom_schema.json"),
            str(data_dir / "validate" / "valid" / "default" / "laravel.cdx.json"),
        )
        exit_code, *_ = run_main()

        assert exit_code == Status.VALIDATION_ERROR

        assert len(caplog.records) == 1
        assert caplog.records[0].msg.description.endswith("is not of type 'array'")  # type: ignore

    def test_invalid_option_combinations(self, argv: Callable[..., None]):
        argv(
            "validate",
            "--filename-pattern",
            "test",
            "--no-filename-validation",
            "foo.cdx.json",
        )
        with pytest.raises(SystemExit) as e:
            run_main()

        assert e.value.code == Status.USAGE_ERROR

        argv(
            "validate",
            "--schema-type",
            "default",
            "--schema-path",
            "myschema.json",
            "foo.cdx.json",
        )
        with pytest.raises(SystemExit) as e:
            run_main()

        assert e.value.code == Status.USAGE_ERROR
