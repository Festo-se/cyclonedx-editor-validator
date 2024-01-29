import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import List, NoReturn, Optional, Tuple

import cdxev.set
from cdxev import pkg
from cdxev.amend.command import run as amend
from cdxev.auxiliary.identity import Key, KeyType
from cdxev.auxiliary.output import write_sbom
from cdxev.build_public_bom import build_public_bom
from cdxev.error import AppError, InputFileError
from cdxev.log import configure_logging
from cdxev.merge import merge
from cdxev.merge_vex import merge_vex
from cdxev.validator import validate_sbom

logger: logging.Logger
_STATUS_OK = 0
_STATUS_APP_ERROR = 2
_STATUS_USAGE_ERROR = 3
_STATUS_VALIDATION_ERROR = 4


def main() -> int:
    """Main entry point for this tool."""
    args = parse_cli()

    configure_logging(args.quiet, args.verbose)

    global logger
    logger = logging.getLogger(__name__)

    try:
        # Run the handler for the selected command.
        return args.cmd_handler(args)
    except AppError as ex:
        logger.error(ex.details, exc_info=True)
        return _STATUS_APP_ERROR


def read_sbom(sbom_file: Path, file_type: Optional[str] = None) -> Tuple[dict, str]:
    """
    Loads the specified SBOM file.

    CycloneDX SBOMs come in two possible formats: *json* and *xml*. *file_type* specified which
    format to assume when loading the file.
    If *file_type* isn't set, it will be guessed from the file's extension. If that also fails, an
    exception is raised.

    :param str sbom_file: The SBOM file.
    :param str|None file_type: The format of the SBOM file. Can be either `xml` or `json`.

    :return: A tuple of the SBOM dictionary, a path object for the input file and the file format
    of the input.

    :raise FileTypeError: If *file_type* isn't specified and can't be guessed.
    """
    if not sbom_file.is_file():
        raise InputFileError("File not found.")

    if file_type is None:
        file_type = sbom_file.suffix[1:]

    known_loaders = {"json": load_json, "xml": load_xml}

    if file_type not in known_loaders:
        raise InputFileError(
            f'Failed to guess file type from extension ".{file_type}".'
        )

    sbom = known_loaders[file_type](sbom_file)
    return sbom, file_type


def load_json(path: Path) -> dict:
    """Loads a JSON file into a dictionary."""
    try:
        with path.open(encoding="utf-8-sig") as file:
            return json.load(file)
    except json.JSONDecodeError as ex:
        raise InputFileError("Invalid JSON", None, ex.lineno) from ex


def load_xml(path: Path) -> dict:
    """Loads an XML SBOM file into a dictionary."""
    raise InputFileError(
        description="XML files aren't supported, yet. Maybe never ¯\\_(ツ)_/¯",
        module_name=path.name,
    )


def usage_error(msg: str) -> NoReturn:
    print(msg, file=sys.stderr)
    print("Use --help for info on how to use this program.")
    sys.exit(_STATUS_USAGE_ERROR)


def parse_cli() -> argparse.Namespace:
    """
    Parses the CLI options. The parser is configured so that a command is required and a handler
    function for the selected command is automatically added to the returned *args* object.

    :return: The *args* object parsed by :py:mod:argparse.
    """
    parser = create_parser()
    return parser.parse_args()


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cdx-ev",
        description=(
            "This tool performs various actions on CycloneDX SBOMs. The action is determined by "
            "the <command> flag.\n"
            "Global options described in this output must be specified BEFORE the <command>. Each "
            "<command> might have additional options which must be specified AFTER the <command>."
            "\n"
            "For help on a commands options, run the <command> with the --help option."
        ),
    )
    parser.add_argument(
        "--quiet",
        "-q",
        help=(
            "Disable logging output. This has no effect on regular command output to stdout "
            "or the --output or --report-format options."
        ),
        action="store_true",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        help=(
            "Enable verbose logging output. This has no effect on output to stdout or "
            "the --output or --report-format options"
        ),
        action="store_true",
    )
    parser.add_argument("--version", action="version", version=pkg.VERSION)

    subparsers = parser.add_subparsers(
        title="Commands", metavar="<command>", required=True
    )
    create_amend_parser(subparsers)
    create_merge_parser(subparsers)
    create_merge_vex_parser(subparsers)
    create_validation_parser(subparsers)
    create_set_parser(subparsers)
    create_build_public_bom_parser(subparsers)

    return parser


def add_output_argument(parser: argparse.ArgumentParser) -> None:
    """Helper function to create uniform output options for all commands."""
    parser.add_argument(
        "--output",
        "-o",
        metavar="<file>",
        help=(
            "The path to where the output should be written. If this is a file, output is "
            "written there. If it's a directory, output is written to a file with an "
            "auto-generated name inside that directory. If it's not specified, output is written "
            "to stdout."
        ),
        type=Path,
    )


# noinspection PyUnresolvedReferences,PyProtectedMember
def create_amend_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "amend",
        help="Adds missing auto-generatable information to an existing SBOM",
    )
    parser.add_argument(
        "input",
        metavar="<input>",
        help="Path to the SBOM file.",
        type=Path,
    )
    parser.add_argument(
        "--license-path",
        metavar="<license-path>",
        help="Path to a folder with txt-files containing license texts to be copied in the SBOM",
        type=str,
        default="",
    )
    add_output_argument(parser)

    parser.set_defaults(cmd_handler=invoke_amend)
    return parser


# noinspection PyUnresolvedReferences,PyProtectedMember
def create_merge_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser("merge", help="Merges two or more SBOMs into one.")
    parser.add_argument(
        "input",
        metavar="<input>",
        help="Paths to SBOM files to merge. You must specify at least two paths.",
        nargs="+",
        type=Path,
    )
    parser.add_argument(
        "--from-folder",
        metavar="<from-folder>",
        help="Path to a folder with sboms to be merged",
        type=Path,
    )
    add_output_argument(parser)

    parser.set_defaults(cmd_handler=invoke_merge)
    return parser


# noinspection PyUnresolvedReferences,PyProtectedMember
def create_merge_vex_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser("merge-vex", help="Merges a VEX file into an SBOM.")
    parser.add_argument(
        "sbom_file",
        metavar="<sbom_file>",
        help=(
            "Path to SBOM file to merge."
            "The first file is assumed to be the SBOM, the second the vex file"
        ),
        type=Path,
    )
    parser.add_argument(
        "vex_file",
        metavar="<vex_file>",
        help=(
            "Path to VEX file to merge."
            "The first file is assumed to be the SBOM, the second the vex file"
        ),
        type=Path,
    )
    add_output_argument(parser)

    parser.set_defaults(cmd_handler=invoke_merge_vex)
    return parser


# noinspection PyUnresolvedReferences,PyProtectedMember
def create_validation_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "validate", help="Validates a SBOM against a given specification."
    )
    parser.add_argument(
        "input",
        metavar="<input>",
        help="Path to the SBOM file to validate.",
        type=Path,
    )
    parser.add_argument(
        "--report-format",
        help=(
            "Write log output in a specified format. "
            "If it's not specified, output is written to stdout."
        ),
        choices=["stdout", "warnings-ng", "gitlab-code-quality"],
        default="stdout",
    )
    parser.add_argument(
        "--schema-type",
        help=(
            "Decide whether to use the default specification of CycloneDX or a custom schema. "
            "The version will be derived from the specVersion in the provided SBOM. "
            "If no version is provided defaults to 1.3."
        ),
        choices=["default", "strict", "custom"],
        default="default",
    )
    parser.add_argument(
        "--filename-pattern",
        help=(
            "Regex for validation of file name. "
            "If no Regex is given the default 'name_version_hash_timestamp.cdx.json' "
            "or 'bom.json' is used, "
            "where name, version and timestamp are mandatory and taken from metadata. "
            "Hash is optional as this is not a required information"
        ),
    )
    parser.add_argument(
        "--schema-path",
        metavar="<schema-path>",
        help=(
            "Path to a JSON schema to use for validator. "
            "If it's not specified, the program will try"
            " to use one of the embedded schemata."
        ),
        type=str,
    )

    add_output_argument(parser)

    parser.set_defaults(cmd_handler=invoke_validate)
    return parser


# noinspection PyUnresolvedReferences,PyProtectedMember
def create_set_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "set",
        help="Sets properties on specified components in an SBOM.",
        description=(
            "Sets or updates the value of a property on a specified component in the input SBOM. "
            "The target component and property as well as the new value can be specified using "
            "command line options. In that case, only a single property can be updated per "
            "invocation. Alternatively, a JSON file can be provided using the --from-file option, "
            "which can contain any number of component identifiers and key-value-pairs. "
            "If the target field is a primitive value or an object, any existent value will be "
            "overwritten with the new value. If the target is an array and it exists already in "
            "the input SBOM, the new value will be appended to the array."
        ),
        usage=(
            "cdx-ev set [-h] [--output <file>] [--force] "
            "(--from-file <file> | <target> --key <key> --value <value>) <input>"
        ),
    )
    parser.add_argument(
        "input",
        metavar="<input>",
        help="Path to the input SBOM file.",
        type=Path,
    )
    add_output_argument(parser)

    parser.add_argument(
        "--from-file",
        metavar="<file>",
        help=(
            "Read the target components and updated fields from a file or URL. Cannot be used in "
            "conjunction with a target option or the --key and --value options."
        ),
    )
    parser.add_argument(
        "--key",
        metavar="<key>",
        help=(
            "Name of the component field to set or update. "
            "May not be combined with --from-file."
        ),
    )
    parser.add_argument(
        "--value",
        metavar="<value>",
        help=(
            "The new value for the field. If the target field is an array or object, you'll have "
            "to format your value as a valid JSON object or array, too. "
            "May not be combined with --from-file."
        ),
    )
    parser.add_argument(
        "--force",
        "-f",
        help="Quietly overwrite existing information without asking.",
        action="store_true",
    )
    parser.add_argument(
        "--allow-protected",
        help="Allow writing protected fields, e.g., identifiers.",
        action="store_true",
    )
    parser.add_argument(
        "--ignore-missing",
        help="Suppress warnings that a component is not present when using '--from-file' ",
        action="store_true",
    )

    identifiers = parser.add_argument_group(
        "target",
        description=(
            "Identifies the target component. If the --from-file option is not used, exactly one "
            "of these options must be specified. --name, --version and --group act together to "
            "identify a component. "
            "If the --from-file option is used, none of these options may be present."
        ),
    )
    identifiers.add_argument(
        "--cpe",
        metavar="<cpe>",
        help="CPE of target component.",
        type=Key.from_cpe,
    )
    identifiers.add_argument(
        "--purl",
        metavar="<purl>",
        help="PURL of target component.",
        type=Key.from_purl,
    )
    identifiers.add_argument(
        "--swid",
        metavar="<swid>",
        help="SWID of target component.",
        type=Key.from_swid,
    )
    identifiers.add_argument(
        "--name",
        metavar="<name>",
        help="Name of target component. Can be combined with group and version.",
    )
    identifiers.add_argument(
        "--group",
        metavar="<group>",
        help="Group of target component. If specified, name must also be specified.",
    )
    identifiers.add_argument(
        "--version",
        metavar="<version>",
        help="Version of target component. If specified, name must also be specified.",
    )

    parser.set_defaults(cmd_handler=invoke_set)
    return parser


# noinspection PyUnresolvedReferences,PyProtectedMember
def create_build_public_bom_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "build-public",
        help=(
            "Removes components and information with namespace internal"
            "and resolves the dependencies."
        ),
    )
    parser.add_argument(
        "input",
        help="Path to a SBOM file.",
        type=Path,
    )
    parser.add_argument(
        "schema_path",
        metavar="<schema path>",
        help="Path to a json schema, defining when a sbom is considered internal",
        type=Path,
    )
    add_output_argument(parser)
    parser.set_defaults(cmd_handler=invoke_build_public_bom)
    return parser


def invoke_amend(args: argparse.Namespace) -> int:
    sbom, _ = read_sbom(args.input)
    amend(sbom, args.license_path)
    write_sbom(sbom, args.output)
    return _STATUS_OK


def invoke_merge(args: argparse.Namespace) -> int:
    if len(args.input) < 2 and args.from_folder is None:
        usage_error(
            "At least two input files, or a input file"
            " and an folder path must be specified."
        )
    inputs: List[dict] = []
    for input in args.input:
        sbom, _ = read_sbom(input)
        inputs.append(sbom)
    if args.from_folder is not None:
        if not os.path.exists(args.from_folder):
            usage_error("Path to folder does not exist")
        path_to_folder = args.from_folder
        name_governing_sbom = os.path.basename(os.path.normpath(args.input[0]))
        list_folder_content = os.listdir(path_to_folder)
        # use python sorted function to sort the names of the files, the
        # names are compared in lowercase to adhere to alphabetical order
        list_folder_content_sorted = sorted(list_folder_content, key=str.lower)

        for file_name in list_folder_content_sorted:
            if (
                re.search(r"^bom\.json$|.*\.cdx\.json", file_name)  # noqa: W605
                and file_name != name_governing_sbom
            ):
                print(file_name)
                new_sbom, _ = read_sbom(Path(os.path.join(path_to_folder, file_name)))
                inputs.append(new_sbom)
        if len(inputs) == 1:
            usage_error("Provided folder does not contain any sboms files")

    output = merge(inputs)
    write_sbom(output, args.output)
    return _STATUS_OK


def invoke_merge_vex(args: argparse.Namespace) -> int:
    sbom, _ = read_sbom(args.sbom_file)
    vex, _ = read_sbom(args.vex_file)

    output = merge_vex(sbom, vex)
    write_sbom(output, args.output)
    return _STATUS_OK


# noinspection PyTypeChecker,PyUnboundLocalVariable
def invoke_set(args: argparse.Namespace) -> int:
    def has_target() -> bool:
        return (
            args.swid is not None
            or args.cpe is not None
            or args.purl is not None
            or args.name is not None
        )

    if args.from_file is None:
        if not has_target():
            usage_error("<target> is required, unless the --from-file option is used.")
        elif args.key is None:
            usage_error("--key is required, unless the --from-file option is used.")
        elif args.value is None:
            usage_error("--value is required, unless the --from-file option is used.")

        possible_targets = [
            args.swid,
            args.purl,
            args.cpe,
            (
                Key.from_coordinates(
                    name=args.name, version=args.version, group=args.group
                )
                if args.name is not None
                else None
            ),
        ]
        actual_targets = [x for x in possible_targets if x is not None]
        if len(actual_targets) > 1:
            usage_error("Cannot specify more than one <target>.")

        target: Key = actual_targets[0]
        try:
            value = json.loads(args.value)
        except json.JSONDecodeError:
            usage_error(
                "<value> is not valid JSON. Possibly missing double quotes around a string?\n"
                f"Value:\t{args.value}"
            )

        updates = [{"id": {}, "set": {args.key: value}}]
        if target.type is KeyType.CPE:
            updates[0]["id"]["cpe"] = target.key
        elif target.type is KeyType.PURL:
            updates[0]["id"]["purl"] = target.key
        elif target.type is KeyType.SWID:
            updates[0]["id"]["swid"] = target.key
        elif target.type is KeyType.COORDINATES:
            updates[0]["id"]["name"] = target.key.name
            if target.key.group is not None:
                updates[0]["id"]["group"] = target.key.group
            if target.key.version is not None:
                updates[0]["id"]["version"] = target.key.version

    else:
        if has_target() or args.key is not None or args.value is not None:
            usage_error(
                "--from-file cannot be combined with <target>, --key or --value."
            )

        updates = []
        with open(args.from_file) as from_file:
            try:
                updates = json.load(from_file)
            except json.JSONDecodeError as ex:
                raise InputFileError(
                    "Invalid JSON passed to --from-file",
                    None,
                    ex.lineno,
                ) from ex

    sbom, _ = read_sbom(args.input)
    cfg = cdxev.set.SetConfig(
        args.force,
        args.allow_protected,
        [args.input],
        args.from_file,
        args.ignore_missing,
    )
    cdxev.set.run(sbom, updates, cfg)
    write_sbom(sbom, args.output)
    return _STATUS_OK


def invoke_validate(args: argparse.Namespace) -> int:
    sbom, file_type = read_sbom(args.input)
    if args.output is None:
        output = Path("./issues.json")
    else:
        output = args.output
    report_format = args.report_format
    return (
        _STATUS_OK
        if validate_sbom(
            sbom=sbom,
            input_format=file_type,
            file=Path(args.input),
            report_format=report_format,
            output=output,
            schema_type=args.schema_type,
            filename_regex=args.filename_pattern,
            schema_path=args.schema_path,
        )
        == _STATUS_OK
        else _STATUS_VALIDATION_ERROR
    )


def invoke_build_public_bom(args: argparse.Namespace) -> int:
    sbom, _ = read_sbom(args.input)
    output = build_public_bom(sbom, args.schema_path)
    write_sbom(output, args.output)
    return _STATUS_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
