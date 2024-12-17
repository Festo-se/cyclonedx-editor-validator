# SPDX-License-Identifier: GPL-3.0-or-later

import json
import typing as t
from pathlib import Path

from pytest import CaptureFixture

import cdxev.pkg
from cdxev.__main__ import main


def load_sbom(path: Path) -> dict:
    with path.open() as f:
        sbom = json.load(f)
    delete_non_reproducible(sbom)
    return sbom


def load_list(path: Path) -> dict:
    with path.open() as f:
        list = f.read()
    return list


def delete_non_reproducible(sbom: dict):
    """
    Deletes any fields from the SBOM that are typically not reproducible between builds.
    These would lead to wrong test results when comparing actual to expected SBOMs.
    """
    _delete_tool_version(sbom)

    if "serialNumber" in sbom:
        del sbom["serialNumber"]
    if "metadata" in sbom:
        if "timestamp" in sbom["metadata"]:
            del sbom["metadata"]["timestamp"]


def _delete_tool_version(sbom: dict):
    tools: t.Optional[t.Union[list, dict]] = sbom.get("metadata", {}).get("tools")

    if tools is None:
        return

    if isinstance(tools, dict):
        tools = tools.get("components", [])

    assert isinstance(tools, list)

    cdxev_tool = next(tool for tool in tools if tool["name"] == cdxev.pkg.NAME)

    if cdxev_tool is not None and "version" in cdxev_tool:
        del cdxev_tool["version"]


@t.overload
def run_main(capsys: None = ..., parse_output: None = ...) -> t.Tuple[int, None]: ...


@t.overload
def run_main(
    capsys: CaptureFixture[str] = ..., parse_output: None = ...
) -> t.Tuple[int, str, str]: ...


@t.overload
def run_main(
    capsys: CaptureFixture[str], parse_output: t.Literal["json"]
) -> t.Tuple[int, dict, str]: ...


@t.overload
def run_main(
    capsys: CaptureFixture[str], parse_output: t.Literal["filename"]
) -> t.Tuple[int, Path, str]: ...


def run_main(
    capsys: t.Optional[CaptureFixture[str]] = None,
    parse_output: t.Optional[t.Union[t.Literal["json"], t.Literal["filename"]]] = None,
):
    """
    Runs the main module of this project and returns the exit code as well as stdout.

    :param capsys: Tests must pass the capsys fixture if they need stdout.
    :param parse_output: If ``"json""`` stdout is parsed as JSON and the parsed ``dict`` is
                         returned.
                         If ``"filename"``, the filename printed to stdout is extracted and
                         returned as a ``pathlib.Path`` object.
                         If ``None``, stdout is returned as-is.
    :returns: A tuple of ``(exit_code, stdout, stderr)``, where *stdout* might be ``None``,
              ``str``, ``Path``, or ``dict`` depending on parameters. *stderr* is always returned
              as-is.
    """
    exit_code = main()

    if capsys is None:
        return (exit_code, None)

    (out, err) = capsys.readouterr()

    if parse_output == "json":
        out = json.loads(out)
        delete_non_reproducible(out)
    elif parse_output == "filename":
        # Parse the output filename from stdout
        out = Path(out.split(":")[1].strip())

    return (exit_code, out, err)
