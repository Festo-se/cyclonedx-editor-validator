# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.integration.test_integration import TestValidate


@dataclass
class SbomFixture:
    input: Path
    expected: Path
    expected_json: dict


@pytest.fixture(scope="package")
def data_dir():
    """Path to the folder where test fixture data is stored."""
    return _data_dir()


def _data_dir():
    return Path(__file__).parent / "data"


@pytest.fixture
def argv(monkeypatch):
    """
    A function which patches argv to return the specified program arguments.

    argv[0] is automatically prepended and must not be passed to the function.
    """

    def _argv(*argv: str):
        monkeypatch.setattr(sys, "argv", [__name__, *argv])

    return _argv


def pytest_generate_tests(metafunc: pytest.Metafunc):
    """
    Pytest hook to dynamically generate tests. Called during test collection phase.
    """

    # When collecting the validate test function, generate a test for each input file
    # in the data/validate directory.
    if metafunc.function == TestValidate.test:
        path = _data_dir()
        sboms = list(path.glob("validate/**/*.cdx.json"))

        # Some invalid SBOMs might come with a companion json file that contains
        # an array of error messages which are expected in the command output.
        expected_errors = {}
        for sbom in sboms:
            errors_file = sbom.with_suffix(".json.errors")
            if not errors_file.is_file():
                continue

            with errors_file.open() as f:
                expected_errors[sbom] = json.load(f)

        metafunc.parametrize(
            "expected_result,schema_type,input,expected_errors",
            [
                (x.parent.parent.name, x.parent.name, x, expected_errors.get(x))
                for x in sboms
            ],
            ids=lambda item: item.name if isinstance(item, Path) else None,
        )
