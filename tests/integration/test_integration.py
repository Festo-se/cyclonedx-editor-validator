import json
import os
import re
from collections.abc import Callable
from itertools import chain
from pathlib import Path
from typing import TypedDict

import pytest
import toml

from cdxev.__main__ import Status
from tests.integration.helper import delete_non_reproducible, load_sbom, run_main


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
    def data(self, data_dir, request) -> DataFixture:
        input_path = data_dir / request.param["input"]
        expected_path = data_dir / request.param["expected"]
        expected_json = load_sbom(expected_path)

        return self.DataFixture(
            input=input_path,
            expected=expected_json,
            operations=request.param["operations"],
        )

    def test(self, data: DataFixture, argv, tmp_path, capsys):
        operations = chain.from_iterable(
            ("--operation", op) for op in data["operations"]
        )
        argv(
            "amend",
            *operations,
            "--output",
            str(tmp_path),
            str(data["input"]),
        )
        (exit_code, output_file, _) = run_main(capsys, "filename")

        # Verify that command completed successfully
        assert exit_code == 0

        # Verify that output matches what is expected
        output_path = tmp_path / output_file
        with output_path.open() as f:
            actual = json.load(f)
        delete_non_reproducible(actual)
        assert actual == data["expected"]


class TestSet:
    class DataFixture(TypedDict):
        input: Path
        set_file: Path
        expected: dict

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
    def data(self, data_dir, request) -> DataFixture:
        input_path = data_dir / request.param["input"]
        set_file_path = data_dir / request.param["set_file"]
        expected_path = data_dir / request.param["expected"]
        expected_json = load_sbom(expected_path)

        return self.DataFixture(
            input=input_path,
            expected=expected_json,
            set_file=set_file_path,
        )

    def test(self, data, argv, tmp_path, capsys):
        argv(
            "set",
            "--force",
            "--from-file",
            str(data["set_file"]),
            "--output",
            str(tmp_path),
            str(data["input"]),
        )
        (exit_code, output_file, _) = run_main(capsys, "filename")

        # Verify that command completed successfully
        assert exit_code == 0

        # Verify that output matches what is expected
        output_path = tmp_path / output_file
        with output_path.open() as f:
            actual = json.load(f)
        delete_non_reproducible(actual)
        assert actual == data["expected"]


class TestValidate:
    # This test function is parametrized by pytest_generate_tests in conftest.py.
    def test(self, argv, capsys, input, schema_type, expected_result, expected_errors):
        argv(
            "validate",
            "--schema-type",
            schema_type,
            str(input),
        )
        if expected_errors:
            (exit_code, _, stderr) = run_main(capsys)
            for e in expected_errors:
                assert e in stderr
        else:
            (exit_code, _) = run_main()

        expected_exit_code = {"valid": 0, "invalid": 4}[expected_result]
        assert exit_code == expected_exit_code


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
    def data(self, data_dir, request) -> DataFixture:
        input_path = data_dir / request.param["input"]
        schema_path = data_dir / request.param["schema"]
        expected_path = data_dir / request.param["expected"]
        expected_json = load_sbom(expected_path)

        return self.DataFixture(
            input=input_path,
            expected=expected_json,
            schema=schema_path,
        )

    def test(self, data, argv, tmp_path, capsys):
        argv(
            "build-public",
            "--output",
            str(tmp_path),
            str(data["input"]),
            str(data["schema"]),
        )
        (exit_code, output_file, _) = run_main(capsys, "filename")

        # Verify that command completed successfully
        assert exit_code == 0

        # Verify that output matches what is expected
        output_path = tmp_path / output_file
        with output_path.open() as f:
            actual = json.load(f)
        delete_non_reproducible(actual)
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
    def data(self, data_dir, request) -> DataFixture:
        input_paths = [data_dir / p for p in request.param["inputs"]]
        expected_path = data_dir / request.param["expected"]
        expected_json = load_sbom(expected_path)

        return self.DataFixture(
            inputs=input_paths,
            expected=expected_json,
        )

    def test(self, data, argv, tmp_path, capsys):
        argv(
            "merge",
            "--output",
            str(tmp_path),
            *(str(p) for p in data["inputs"]),
        )
        (exit_code, output_file, _) = run_main(capsys, "filename")

        # Verify that command completed successfully
        assert exit_code == 0

        # Verify that output matches what is expected
        output_path = tmp_path / output_file
        with output_path.open() as f:
            actual = json.load(f)
        delete_non_reproducible(actual)
        assert actual == data["expected"]
