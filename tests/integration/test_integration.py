import json
from pathlib import Path
from typing import TypedDict

import pytest

from tests.integration.helper import delete_non_reproducible, load_sbom, run_main


class TestAmend:
    class DataFixture(TypedDict):
        input: Path
        expected: dict

    @pytest.fixture(
        scope="class",
        params=[
            {
                "input": "amend.input.cdx.json",
                "expected": "amend.expected.cdx.json",
            }
        ],
    )
    def data(self, data_dir, request) -> DataFixture:
        input_path = data_dir / request.param["input"]
        expected_path = data_dir / request.param["expected"]
        expected_json = load_sbom(expected_path)

        return self.DataFixture(
            input=input_path,
            expected=expected_json,
        )

    def test(self, data: DataFixture, argv, tmp_path, capsys):
        argv("amend", "--output", str(tmp_path), str(data["input"]))
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
