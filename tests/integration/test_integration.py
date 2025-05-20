# SPDX-License-Identifier: GPL-3.0-or-later

import json
import os
import re
from collections.abc import Callable
from itertools import chain
from pathlib import Path
from typing import TypedDict
from uuid import UUID

import pytest
import toml

from cdxev.__main__ import Status
from cdxev.amend.operations import AddLicenseText
from tests.auxiliary.helper import search_entry
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
    "CI" not in os.environ,
    reason="Often fails in dev installs. Works after clean install.",
)
def test_version_from_pyproject(
    argv: Callable[..., None], capsys: pytest.CaptureFixture[str]
):
    toml_file = Path(__file__).parents[2] / "pyproject.toml"
    toml_content = toml.load(toml_file)
    expected_version = toml_content.get("project", {}).get("version")

    argv("--version")
    with pytest.raises(SystemExit) as e:
        run_main()

    assert e.value.code == Status.OK
    stdout, _ = capsys.readouterr()
    assert expected_version == stdout.strip()


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
    assert expected == actual


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
    assert expected == actual


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
                "expected": "amend.expected_delete-ambiguous-licenses.cdx.json",
                "operations": ["delete-ambiguous-licenses"],
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
        assert expected == actual

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

        assert expected == actual


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
            "--schema-path",
            str(data["schema"]),
            "--ext-ref-regex",
            r"https://acme\.com|https://internal\.festo\.com",
            str(data["input"]),
        )
        exit_code, actual, _ = run_main(capsys, "json")

        # Verify that command completed successfully
        assert exit_code == Status.OK

        # Verify that output matches what is expected
        assert actual == data["expected"]


class TestInitSbom:
    class DataFixture(TypedDict):
        expected: dict

    def test(
        self,
        data_dir: Path,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        argv(
            "init-sbom",
            "--name",
            "software name",
            "--authors",
            "authors name",
            "--supplier",
            "supplier",
            "--version",
            "1.1.1",
            "--email",
            "test@test.com",
        )
        exit_code, actual, _ = run_main(capsys, "json")

        expected = load_sbom(data_dir / "init-sbom.initial_expected.json")

        # Verify that command completed successfully
        assert exit_code == Status.OK

        # Verify bom ref is a valid UUID
        assert UUID(actual["metadata"]["component"]["bom-ref"])

        # Remove randomly generated bom ref for the comparison
        actual["dependencies"][0].pop("ref")
        actual["metadata"]["component"].pop("bom-ref")
        expected["metadata"]["component"].pop("bom-ref")
        expected["dependencies"][0].pop("ref")

        # Verify that output matches what is expected
        assert actual == expected

    def test_no_arguments(
        self,
        data_dir: Path,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        argv(
            "init-sbom",
        )
        exit_code, actual, _ = run_main(capsys, "json")

        expected = load_sbom(data_dir / "init-sbom.initial_default.json")

        # Verify that command completed successfully
        assert exit_code == Status.OK

        # Verify bom ref is a valid UUID
        assert UUID(actual["metadata"]["component"]["bom-ref"])

        # Remove randomly generated bom ref for the comparison
        actual["dependencies"][0].pop("ref")
        actual["metadata"]["component"].pop("bom-ref")
        expected["metadata"]["component"].pop("bom-ref")
        expected["dependencies"][0].pop("ref")

        # Verify that output matches what is expected
        assert actual == expected


class TestListCommand:
    class DataFixture(TypedDict):
        input: Path
        expected: dict

    @pytest.fixture(
        scope="class",
        params=[
            {
                "input": "list-command.input.json",
                "expected": "list-command.expected.json",
            }
        ],
    )
    def data(self, data_dir: Path, request: pytest.FixtureRequest) -> DataFixture:
        input_path = data_dir / request.param["input"]
        expected_path = data_dir / request.param["expected"]
        with open(expected_path, "r") as file:
            expected_json = json.load(file)

        return self.DataFixture(
            input=input_path,
            expected=expected_json,
        )

    def test_list_licenses_csv(
        self,
        data: DataFixture,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        argv("list", "licenses", str(data["input"]))
        exit_code, actual, _ = run_main(capsys)

        # Verify that command completed successfully
        assert exit_code == Status.OK

        # Verify that output matches what is expected
        with open("tests/integration/data/list_command/list_licenses.csv", "r") as file:
            file_contents = file.read()
        assert actual == file_contents

    def test_list_components_csv(
        self,
        data: DataFixture,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        argv("list", "components", str(data["input"]))
        exit_code, actual, _ = run_main(capsys)

        # Verify that command completed successfully
        assert exit_code == Status.OK

        # Verify that output matches what is expected
        with open(
            "tests/integration/data/list_command/list_components.csv", "r"
        ) as file:
            file_contents = file.read()
        assert actual == file_contents

    def test_list_licenses_txt(
        self,
        data: DataFixture,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        argv("list", "licenses", str(data["input"]), "--format", "txt")
        exit_code, actual, _ = run_main(capsys)

        # Verify that command completed successfully
        assert exit_code == Status.OK

        # Verify that output matches what is expected
        with open("tests/integration/data/list_command/list_licenses.txt", "r") as file:
            file_contents = file.read()
        assert actual == file_contents

    def test_list_components_txt(
        self,
        data: DataFixture,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        argv("list", "components", str(data["input"]), "--format", "txt")
        exit_code, actual, _ = run_main(capsys)

        # Verify that command completed successfully
        assert exit_code == Status.OK

        # Verify that output matches what is expected
        with open(
            "tests/integration/data/list_command/list_components.txt", "r"
        ) as file:
            file_contents = file.read()
        assert actual == file_contents


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

    def test_direct(
        self,
        argv: Callable[..., None],
        data_dir: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        input_folder = data_dir / "merge-from-folder"

        input_1 = input_folder / "merge.input_1.cdx.json"
        input_2 = input_folder / "merge.input_2.cdx.json"
        input_3 = input_folder / "merge.input_3.cdx.json"

        argv("merge", str(input_1), str(input_2), str(input_3))
        exit_code, actual, _ = run_main(capsys=capsys, parse_output="json")

        assert exit_code == Status.OK

        expected = load_sbom(data_dir / "merge.expected_from-folder.cdx.json")
        assert expected == actual

    def test_hierarchical(
        self,
        argv: Callable[..., None],
        data_dir: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        input_folder = data_dir

        input_1 = input_folder / "merge.input_1.cdx.json"
        input_2 = input_folder / "merge.input_2.cdx.json"

        argv("merge", str(input_1), str(input_2), "--hierarchical")
        exit_code, actual, _ = run_main(capsys=capsys, parse_output="json")

        assert exit_code == Status.OK

        expected = load_sbom(data_dir / "merge.expected_hierarchical.cdx.json")

        assert expected == actual

    def test_same_sbom_warning_duplicate(
        self,
        argv: Callable[..., None],
        data_dir: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:

        input_1 = data_dir / "merge.input_1.cdx.json"

        argv("merge", str(input_1), str(input_1), "--hierarchical")
        _, _, warnings = run_main(capsys=capsys, parse_output="json")

        assert "Dropping a duplicate component" in warnings

    def test_merge_of_vex(
        self,
        argv: Callable[..., None],
        data_dir: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:

        input_1 = data_dir / "merge.vex.input_1.cdx.json"
        input_2 = data_dir / "merge.vex.input_2.cdx.json"

        argv("merge", str(input_1), str(input_2))
        exit_code, actual, _ = run_main(capsys=capsys, parse_output="json")

        assert exit_code == Status.OK

        expected = load_sbom(data_dir / "merge.vex.expected.cdx.json")
        assert expected == actual

    def test_order(
        self,
        argv: Callable[..., None],
        data_dir: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        input_folder = data_dir / "merge-from-folder"

        input_1 = input_folder / "merge.input_1.cdx.json"
        input_2 = input_folder / "merge.input_2.cdx.json"
        input_3 = input_folder / "merge.input_3.cdx.json"

        argv("merge", str(input_2), str(input_1), str(input_3))
        exit_code, output, _ = run_main(capsys=capsys, parse_output="json")

        assert exit_code == Status.OK

        # Since we changed the input order, we expect the output to NOT match the contents of the
        # file. We don't care what the output is truly, only that it's different from the regular
        # test.
        not_expected = load_sbom(data_dir / "merge.expected_from-folder.cdx.json")
        assert output != not_expected

    def test_from_folder(
        self,
        argv: Callable[..., None],
        data_dir: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        input_folder = data_dir / "merge-from-folder"

        argv("merge", "--from-folder", str(input_folder))
        exit_code, actual, _ = run_main(capsys=capsys, parse_output="json")

        assert exit_code == Status.OK

        expected = load_sbom(data_dir / "merge.expected_from-folder.cdx.json")
        assert expected == actual

    def test_mixed(
        self,
        argv: Callable[..., None],
        data_dir: Path,
        capsys: pytest.CaptureFixture[str],
    ):

        input_folder = data_dir / "merge-from-folder"

        input_1 = input_folder / "merge.input_1.cdx.json"

        argv("merge", "--from-folder", str(input_folder), str(input_1))
        exit_code, actual, _ = run_main(capsys=capsys, parse_output="json")

        assert exit_code == Status.OK

        expected = load_sbom(data_dir / "merge.expected_from-folder.cdx.json")
        assert expected == actual

    def test_not_enough_inputs(self, argv: Callable[..., None]):
        argv("merge")
        with pytest.raises(SystemExit) as e:
            run_main()

        assert e.value.code == Status.USAGE_ERROR

        argv("merge", "input1.cdx.json")
        with pytest.raises(SystemExit) as e:
            run_main()

        assert e.value.code == Status.USAGE_ERROR

    def test_invalid_folder_path(
        self,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ):
        argv(
            "merge",
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
        tmp_path: Path,
    ):
        argv(
            "merge",
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

    def test_direct_range(
        self,
        data_dir: Path,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ):
        argv(
            "set",
            str(data_dir / "set.input_version-ranges.cdx.json"),
            "--name",
            "web-framework",
            "--version-range",
            "vers:generic/>2.0.0|<=3.0.0",
            "--key",
            "copyright",
            "--value",
            '"ACME Inc."',
        )
        exit_code, actual, _ = run_main(capsys, "json")

        assert exit_code == Status.OK

        expected = load_sbom(data_dir / "set.expected_version-ranges.cdx.json")
        assert expected == actual

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
            ["name", "version", "version-range", "key", "value"],
            ["key", "value"],
            ["name", "key"],
            ["name", "value"],
            ["from-file", "name"],
            ["from-file", "key", "value"],
        ],
        ids=lambda keys: "options: " + ", ".join(keys),
    )
    def test_invalid_option_combinations(
        self, use_only: list[str], input_file: Path, argv: Callable[..., None]
    ):
        options = {
            "name": "comp",
            "version": "1.0.0",
            "version-range": "vers:generic/>1.0.0",
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
        value: str,
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

    def test_target_with_range_not_found(
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
            "--version-range",
            "vers:generic/1.0.0",
            "--key",
            "copyright",
            "--value",
            '"ACME Inc."',
        )
        exit_code, _, stderr = run_main(capsys)

        assert exit_code == Status.APP_ERROR
        assert stderr.find('"COORDINATES[comp@vers:generic/1.0.0]" was not found') >= 0

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
        exit_code, *_ = run_main()

        assert exit_code == Status.OK

    def test_component_remapping(
        self,
        data_dir: Path,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ):
        input_sbom = data_dir / "set.input_remap.cdx.json"
        input_set_file = data_dir / "set.input_remap.json"

        argv(
            "set",
            "--allow-protected",
            str(input_sbom),
            "--from-file",
            str(input_set_file),
        )
        exit_code, _, stderr = run_main(capsys)

        assert exit_code == Status.APP_ERROR
        assert (
            'The component "COORDINATES[nested]" was not found and could not be updated.'
            in stderr
        )

    def test_empty_set_file(
        self,
        input_file: Path,
        data_dir: Path,
        argv: Callable[..., None],
        caplog: pytest.LogCaptureFixture,
    ):
        input_set_file = data_dir / "set.input_empty.json"
        argv(
            "--verbose",
            "set",
            str(input_file),
            "--from-file",
            str(input_set_file),
        )
        exit_code, *_ = run_main()

        assert exit_code == Status.OK
        assert caplog.records[0].msg.startswith("No updates to perform.")

    def test_invalid_set_file(
        self,
        input_file: Path,
        data_dir: Path,
        argv: Callable[..., None],
        caplog: pytest.LogCaptureFixture,
    ):
        input_set_file = data_dir / "set.input_invalid.json"
        argv(
            "set",
            str(input_file),
            "--from-file",
            str(input_set_file),
        )
        exit_code, *_ = run_main()

        assert exit_code == Status.APP_ERROR
        assert (
            caplog.records[0].msg.description  # type: ignore
            == "Invalid update record: The update object with id "
            "COORDINATES[delete nested components] is missing the 'set' property."
        )

    def test_ignore_existing(
        self,
        input_file: Path,
        argv: Callable[..., None],
        caplog: pytest.LogCaptureFixture,
    ):
        argv(
            "--verbose",
            "set",
            str(input_file),
            "--purl",
            "pkg:npm/test-app@1.0.0",
            "--key",
            "bom-ref",
            "--value",
            '"should not overwrite"',
            "--ignore-existing",
        )
        exit_code, *_ = run_main()

        assert exit_code == Status.OK
        assert caplog.records[0].msg.startswith("Not overwriting")

    def test_invalid_vers_syntax(
        self,
        input_file: Path,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ):
        argv(
            "set",
            str(input_file),
            "--name",
            "foo",
            "--version-range",
            "invalid",
            "--key",
            "copyright",
            "--value",
            '"foo"',
        )
        with pytest.raises(SystemExit) as e:
            run_main()

        assert e.value.code == Status.USAGE_ERROR
        _, stderr = capsys.readouterr()
        assert "'invalid' must start with the 'vers:' URI scheme." in stderr


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
            exit_code, stdout, _ = run_main(capsys)
            for e in expected_errors:
                assert e in stdout
        else:
            exit_code, _ = run_main()

        expected_exit_code = {"valid": Status.OK, "invalid": Status.VALIDATION_ERROR}[
            expected_result
        ]
        assert expected_exit_code == exit_code

    def test_warnings_ng(
        self, argv: Callable[..., None], data_dir: Path, tmp_path: Path
    ):
        report_path = tmp_path / "issues.json"
        argv(
            "validate",
            "--report-format",
            "warnings-ng",
            "--report-path",
            str(report_path),
            str(data_dir / "validate" / "invalid" / "default" / "laravel_1.4.cdx.json"),
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
            "--report-path",
            str(report_path),
            str(data_dir / "validate" / "invalid" / "default" / "laravel_1.4.cdx.json"),
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
        capsys: pytest.CaptureFixture[str],
    ):
        argv(
            "validate",
            "--filename-pattern",
            "fail",
            str(data_dir / "validate" / "valid" / "default" / "laravel_1.4.cdx.json"),
        )
        exit_code, stdout, _ = run_main(capsys=capsys)

        assert exit_code == Status.VALIDATION_ERROR
        assert "filename doesn't match regular expression fail" in stdout

    def test_implicit_filename_validation(
        self,
        argv: Callable[..., None],
        data_dir: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        argv(
            "validate",
            str(data_dir / "validate.invalid_filename.json"),
        )
        exit_code, stdout, _ = run_main(capsys=capsys)

        assert exit_code == Status.OK
        assert (
            "filename doesn't match regular expression ^(bom\\.json|.+\\.cdx\\.json)$"
            in stdout
        )

    def test_custom_schema(
        self,
        argv: Callable[..., None],
        data_dir: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        argv(
            "validate",
            "--schema-path",
            str(data_dir / "validate.custom_schema.json"),
            str(data_dir / "validate" / "valid" / "default" / "laravel_1.4.cdx.json"),
        )
        exit_code, stdout, _ = run_main(capsys=capsys)

        assert exit_code == Status.VALIDATION_ERROR
        assert stdout.endswith("is not of type 'array'\n")

    def test_invalid_schema(
        self,
        argv: Callable[..., None],
        data_dir: Path,
        caplog: pytest.LogCaptureFixture,
    ):
        argv(
            "validate",
            "--schema-path",
            str(data_dir / "validate.invalid_schema.json"),
            str(data_dir / "validate" / "valid" / "default" / "laravel_1.4.cdx.json"),
        )
        exit_code, *_ = run_main()

        assert exit_code == Status.APP_ERROR
        assert caplog.records[0].msg.description.startswith(  # type: ignore
            "Invalid JSON Schema in schema file"
        )

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

        argv(
            "validate",
            "--report-format",
            "warnings-ng",
            "foo.cdx.json",
        )
        with pytest.raises(SystemExit) as e:
            run_main()

        assert e.value.code == Status.USAGE_ERROR

        argv(
            "validate",
            "--report-path",
            "report.json",
            "foo.cdx.json",
        )
        with pytest.raises(SystemExit) as e:
            run_main()

        assert e.value.code == Status.USAGE_ERROR


class TestVex:
    class DataFixture(TypedDict):
        input: Path
        expected_list_default: list
        expected_list_lightweight: list
        expected_trim_json: dict
        expected_search_json: dict
        expected_extract_json: dict

    @pytest.fixture(
        scope="class",
        params=[
            {
                "input": "vex.embedded.json",
                "expected": "vex.json",
                "expected_search": "vex.expected_search.json",
                "expected_trim": "vex.expected_trim.json",
                "expected_list": "vex.expected_list_default.csv",
            }
        ],
    )
    def data(self, data_dir: Path, request: pytest.FixtureRequest) -> DataFixture:
        input_path = data_dir / request.param["input"]
        expected_path = data_dir / request.param["expected"]
        expected_search_path = data_dir / request.param["expected_search"]
        expected_trim_path = data_dir / request.param["expected_trim"]
        expected_list_path = data_dir / request.param["expected_list"]
        input_vex_embedded_path = input_path

        expected_vex = load_sbom(expected_path)
        expected_search = load_sbom(expected_search_path)
        expected_trim = load_sbom(expected_trim_path)
        with expected_list_path.open() as file:
            expected_list = file.read()

        return self.DataFixture(
            input_vex_embedded_path=input_vex_embedded_path,
            expected_vex=expected_vex,
            expected_search=expected_search,
            expected_list=expected_list,
            expected_trim=expected_trim,
        )

    def test_extract_vex_from_sbom_from_embedded_file(
        self,
        data: DataFixture,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        argv("vex", "extract", str(data["input_vex_embedded_path"]))
        exit_code, actual, _ = run_main(capsys)

        # Verify that command completed successfully
        assert exit_code == Status.OK

        # Verify that output matches what is expected
        expected_output = data["expected_vex"]
        assert json.loads(actual) == expected_output

    def test_search_for_vulnerability(
        self,
        data: DataFixture,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        argv("vex", "search", str(data["input_vex_embedded_path"]), "CVE-1013-0002")
        exit_code, actual, _ = run_main(capsys)

        # Verify that command completed successfully
        assert exit_code == Status.OK

        # Verify that output matches what is expected
        expected_output = data["expected_search"]
        assert json.loads(actual) == expected_output

    def test_trim_vulnerabilities(
        self,
        data: DataFixture,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        argv(
            "vex",
            "trim",
            str(data["input_vex_embedded_path"]),
            "--key=state",
            "--value=not_affected",
        )
        exit_code, actual, _ = run_main(capsys)

        # Verify that command completed successfully
        assert exit_code == Status.OK

        # Verify that output matches what is expected
        expected_output = data["expected_trim"]
        assert json.loads(actual) == expected_output

    def test_list_vulnerability_ids(
        self,
        data: DataFixture,
        argv: Callable[..., None],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        argv("vex", "list", str(data["input_vex_embedded_path"]))
        exit_code, actual, _ = run_main(capsys)

        # Verify that command completed successfully
        assert exit_code == Status.OK

        # Verify that output matches what is expected
        expected_output = data["expected_list"]
        assert actual == expected_output
