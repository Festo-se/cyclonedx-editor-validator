# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import enum
import inspect
import json
import logging
import re
import shutil
import sys
import textwrap
import typing as t
from collections.abc import MutableSequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterator, NoReturn, Optional, Tuple

import docstring_parser
from natsort import os_sorted

import cdxev.amend.command as amend
import cdxev.set
from cdxev import pkg
from cdxev.amend.operations import Operation
from cdxev.auxiliary.identity import Key, KeyType
from cdxev.auxiliary.output import write_list, write_sbom
from cdxev.build_public_bom import build_public_bom
from cdxev.error import AppError, InputFileError
from cdxev.initialize_sbom import initialize_sbom
from cdxev.list_command import list_command
from cdxev.log import configure_logging
from cdxev.merge import merge
from cdxev.merge_vex import merge_vex
from cdxev.validator import validate_sbom

logger: logging.Logger


class Status(enum.IntEnum):
    OK = 0
    USAGE_ERROR = 2
    APP_ERROR = 3
    VALIDATION_ERROR = 4


def main() -> t.Union[int, t.Any]:
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
        return Status.APP_ERROR


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
        raise InputFileError(f"File not found: {sbom_file}")

    if file_type is None:
        file_type = sbom_file.suffix[1:]

    known_loaders = {"json": load_json, "xml": load_xml}

    if file_type not in known_loaders:
        raise InputFileError(
            f'Failed to guess file type from extension ".{file_type}".'
        )

    sbom = known_loaders[file_type](sbom_file)
    return sbom, file_type


def load_json(path: Path) -> t.Any:
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


def usage_error(
    message: str, parser: Optional[argparse.ArgumentParser] = None
) -> NoReturn:
    if parser is not None:
        parser.print_usage(file=sys.stderr)

    print("error: " + message, file=sys.stderr)
    print(file=sys.stderr)
    print("Use --help for info on how to use this program.", file=sys.stderr)
    sys.exit(Status.USAGE_ERROR)


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
            "the <command> argument."
        ),
        add_help=False,
    )
    group = parser.add_argument_group(
        title="Global options",
        description="These options must be specified BEFORE <command>.",
    )
    group.add_argument(
        "--quiet",
        "-q",
        help=(
            "Disable logging output. This has no effect on regular command output to stdout "
            "or the --output or --report-format options."
        ),
        action="store_true",
    )
    group.add_argument(
        "--verbose",
        "-v",
        help=(
            "Enable verbose logging output. This has no effect on output to stdout or "
            "the --output or --report-format options."
        ),
        action="store_true",
    )
    group.add_argument(
        "--version", action="version", version=pkg.VERSION, help="Print version."
    )
    group.add_argument("--help", "-h", action="help", help="Print this help message.")

    subparsers = parser.add_subparsers(
        title="Commands",
        metavar="<command>",
        required=True,
        description=(
            "Determines the action to perform on the SBOM. Each command might have more options. "
            "To get help on command options, use cdx-ev <command> --help."
        ),
    )
    create_amend_parser(subparsers)
    create_merge_parser(subparsers)
    create_merge_vex_parser(subparsers)
    create_validation_parser(subparsers)
    create_set_parser(subparsers)
    create_build_public_bom_parser(subparsers)
    create_init_sbom_parser(subparsers)
    create_list_command_parser(subparsers)

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


@dataclass
class _AmendOperationDetails:
    cls: type[Operation]
    name: str
    short_description: str
    long_description: str
    options: list[dict]
    is_default: bool


_upper_case_letters_after_first = re.compile(r"(?<!^)(?=[A-Z])")


def get_operation_details(cls: type[Operation]) -> _AmendOperationDetails:
    """
    Gets details about an amend operation which are required for the argument parser.

    :param cls: The operation class. Must be a subclass of :py:class:`Operation`.
    :return: Details about the operation documentation and its options.
    """

    def rest_to_text(rest: Optional[str]) -> Optional[str]:
        if rest is None:
            return None

        return re.sub("`+", "'", rest)

    if TYPE_CHECKING:
        # Shut up mypy. If these assertions don't hold,
        # integration tests will break, so no problem at runtime.
        assert cls.__doc__ is not None  # nosec B101
        assert cls.__init__.__doc__ is not None  # nosec B101
    op_name = re.sub(_upper_case_letters_after_first, "-", cls.__name__).lower()
    op_doc = docstring_parser.parse(cls.__doc__)
    op_short_help = rest_to_text(op_doc.short_description)
    op_long_help = rest_to_text(op_doc.long_description)
    op_is_default = getattr(cls, "_amendDefault", False)
    init_sig = inspect.signature(cls.__init__)
    init_params = {
        name: param
        for name, param in init_sig.parameters.items()
        if name not in ("self", "args", "kwargs")
    }
    init_doc = docstring_parser.parse(cls.__init__.__doc__)

    args = []
    for name, param in init_params.items():
        if name == "self":
            continue

        param_doc = next(p for p in init_doc.params if p.arg_name == name)
        arg = {
            "dest": name,
            "name": "--" + name.replace("_", "-"),
            "type": param.annotation,
            "help": rest_to_text(
                param_doc.description,
            ),
        }
        if param.default != inspect.Parameter.empty:
            arg["default"] = param.default

        args.append(arg)

    return _AmendOperationDetails(
        cls=cls,
        name=op_name,
        short_description=op_short_help or "",
        long_description=op_long_help or "",
        is_default=op_is_default,
        options=args,
    )


def reflow_paragraphs(text: str, indent: int = 8) -> str:
    """
    Reformats a string comprised of several paragraphs to properly output it to the console.

    This function considers double newlines ('\\n\\n') paragraph breaks and will preserve them.
    Any other whitespace, including single newlines will be collapsed.

    The algorithm is barely aware of RestructuredText, so most special formatting will simply be
    treated like any other text. The only exception are simple single-level lists, which are
    specially handled.

    The width of the final string is equal to the terminal width but capped at 160 characters.

    :param text: The string to reformat.
    :param indent: The number of spaces to add before each line.
    :returns: The reformatted string.
    """
    max_width = min(shutil.get_terminal_size()[0], 160)
    textwrapper = textwrap.TextWrapper(
        width=max_width, initial_indent=" " * indent, subsequent_indent=" " * indent
    )
    text = textwrap.dedent(text)
    paragraphs = text.split("\n\n")
    result = []
    for para in paragraphs:
        lines = para.splitlines()
        if all(re.match(r"([*\-+] )|(\s+)", line) for line in lines):
            # This branch is run if the paragraph constitutes a ReST-formatted list.
            # I.e., all lines start with a list symbol or with spaces.
            def listitems(lines: MutableSequence[str]) -> Iterator[str]:
                """
                Merges lines of text which constitutes a single item in a ReST list.

                >>> rest_list = ["- 1st item", "- 2nd item, 1st line", "  2nd item, 2nd line"]
                >>> list(listitems(rest_list))
                ["- 1st item", "- 2nd item, 1st line  2nd item, 2nd line"]

                :param lines: A (Python) list of lines from a single paragraph.
                :returns: A new (Python) list with one entry per (ReST) list item.
                """
                while len(lines) > 0:
                    item = lines.pop(0)
                    while len(lines) > 0 and not lines[0][0] in "*-+":
                        item += lines.pop(0)
                    yield item

            para = "\n".join(textwrapper.fill(item) for item in listitems(lines))

        else:
            # This branch covers all other cases.
            para = textwrapper.fill(para)
        result.append(para)

    return "\n\n".join(result)


# noinspection PyUnresolvedReferences,PyProtectedMember
def create_amend_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    description = (
        "The amend command splits its functionality into several operations.\n"
        "You can select which operations run using the --operation option. "
        "If you don't, operations marked [default] will run.\n"
        "The following operations are available:\n\n"
    )

    operations = amend.get_all_operations()
    operation_details = [get_operation_details(op) for op in operations]
    operation_details = sorted(operation_details, key=lambda op: op.name)

    operations_by_name: dict[str, _AmendOperationDetails] = {}
    argument_groups: dict[str, list[dict]] = {}
    default_operations: list[str] = []
    for op in operation_details:
        setattr(op.cls, "_details", op)

        # Add operation to map
        operations_by_name[op.name] = op

        # Prepare options to add them to the parser later
        if op.options:
            argument_groups[op.name] = op.options

        # Add operation to help text
        if op.is_default:
            default_operations.append(op.name)
            description += f"    {op.name} [default]:\n"
        else:
            description += f"    {op.name}:\n"

        desc = reflow_paragraphs(op.short_description)
        description += desc + "\n\n"

    parser = subparsers.add_parser(
        "amend",
        help="Adds missing auto-generatable information to an existing SBOM",
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "input",
        metavar="<input>",
        help="Path to the SBOM file.",
        type=Path,
        default=None,
        nargs="?",
    )
    parser.add_argument(
        "--operation",
        help=(
            "Select an operation to run. Can be provided more than once to run multiple "
            "operations in one run."
        ),
        choices=list(operations_by_name.keys()),
        metavar="<operation>",
        action="append",
    )
    parser.add_argument(
        "--help-operation",
        help="Displays details about an operation and exits afterwards.",
        choices=list(operations_by_name.keys()),
        metavar="<operation>",
    )

    # Add arguments for operation options
    for group, args in argument_groups.items():
        group_parser = parser.add_argument_group(f"Options for '{group}'")
        for opt in args:
            name = opt["name"]
            group_parser.add_argument(
                name, **{k: v for k, v in opt.items() if k != "name"}
            )

    add_output_argument(parser)

    parser.set_defaults(
        cmd_handler=invoke_amend,
        parser=parser,
        operations_by_name=operations_by_name,
        default_operations=default_operations,
    )
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
        nargs="*",
        type=Path,
    )
    parser.add_argument(
        "--from-folder",
        metavar="<from-folder>",
        help="Path to a folder with sboms to be merged",
        type=Path,
    )
    add_output_argument(parser)

    parser.set_defaults(cmd_handler=invoke_merge, parser=parser)
    return parser


# noinspection PyUnresolvedReferences,PyProtectedMember
def create_merge_vex_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "merge-vex",
        help=(
            "[Deprecated] - This command will be removed in a future version."
            "Note: The `merge-vex` command will be superseded by a new `vex` command."
            "Merges a VEX file into an SBOM."
        ),
    )
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

    parser.set_defaults(cmd_handler=invoke_merge_vex, parser=parser)
    return parser


# noinspection PyUnresolvedReferences,PyProtectedMember
def create_validation_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "validate", help="Validates an SBOM against a given specification."
    )
    parser.add_argument(
        "input",
        metavar="<input>",
        help="Path to the SBOM file to validate.",
        type=Path,
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--schema-type",
        help="Use a built-in schema for validation.",
        choices=["default", "strict", "custom"],
    )
    group.add_argument(
        "--schema-path",
        metavar="<schema-path>",
        help="Path to the JSON schema file to validate against.",
        type=Path,
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--filename-pattern",
        help=(
            "Regex for validation of filename. If not specified, a default regex depending on "
            "the schema is applied. To disable filename validation altogether, use "
            "--no-filename-validation."
        ),
        default="",
    )
    group.add_argument(
        "--no-filename-validation",
        help="Disable filename validation",
        action="store_true",
    )

    parser.add_argument(
        "--report-format",
        help=(
            "Write results to a file in the specified format. Must be combined with the "
            "--report-path option."
        ),
        choices=["warnings-ng", "gitlab-code-quality"],
    )
    parser.add_argument(
        "--report-path",
        metavar="<file>",
        help=(
            "The path to where the report file should be written. Must be combined with the "
            "--report-format option."
        ),
        type=Path,
    )

    parser.set_defaults(cmd_handler=invoke_validate, parser=parser)
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
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--force",
        "-f",
        help="Quietly overwrite existing information without asking.",
        action="store_true",
    )
    group.add_argument(
        "--ignore-existing",
        help="Quietly skip existing information without asking.",
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

    group = identifiers.add_mutually_exclusive_group()
    group.add_argument(
        "--version",
        metavar="<version>",
        help="Version of target component. If specified, name must also be specified.",
    )
    group.add_argument(
        "--version-range",
        metavar="<version>",
        help=(
            "Version range of target components in 'vers' notation. "
            "If specified, name must also be specified."
        ),
    )

    parser.set_defaults(cmd_handler=invoke_set, parser=parser)
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
        "--schema-path",
        metavar="<schema path>",
        help=(
            "Path to a json schema, "
            "defining when the information in an SBOM is considered internal"
        ),
        default=None,
        type=Path,
    )
    add_output_argument(parser)
    parser.set_defaults(cmd_handler=invoke_build_public_bom, parser=parser)
    return parser


# noinspection PyUnresolvedReferences,PyProtectedMember
def create_init_sbom_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "init-sbom",
        help=("Provides the first draft of an SBOM for manual completion."),
        usage=("cdx-ev init-sbom [-h] <metadata> [--output <file>]"),
    )
    submitted_values = parser.add_argument_group(
        "metadata",
        description=(
            "Submitted values that will be written into the SBOM draft. "
            "Field values like the name and version of the software (--name and --version), "
            "the supplier of the software (--supplier-software) "
            "or the supplier of the SBOM (--supplier-sbom) "
            "can be submitted to the program and will be written into the provided draft."
        ),
    )
    submitted_values.add_argument(
        "--name",
        metavar="<name>",
        help=("The name of the component described by the SBOM."),
    )
    submitted_values.add_argument(
        "--version",
        metavar="<version>",
        help=("The component's version."),
    )
    submitted_values.add_argument(
        "--supplier",
        metavar="<supplier-software>",
        help=("The name of the organization that supplied the component."),
    )
    submitted_values.add_argument(
        "--authors",
        metavar="<supplier-sbom>",
        help=("The person who created the SBOM."),
    )
    add_output_argument(parser)
    parser.set_defaults(cmd_handler=invoke_init_sbom, parser=parser)
    return parser


def create_list_command_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "list",
        help=(
            "Lists specific contents of the SBOM."
            "Currently supported are the listing of license information and component information."
        ),
        usage=(
            "cdx-ev list [-h] [--format {txt,csv}] "
            "[--output <file>] <operation> {licenses, components} input"
        ),
    )
    parser.add_argument(
        "operation",
        metavar="<operation>",
        help=("The list operation that shall be performed."),
        choices=["licenses", "components"],
        default=None,
        type=str,
    )
    parser.add_argument(
        "input",
        help="Path to an SBOM file.",
        type=Path,
    )
    parser.add_argument(
        "--format",
        help="The output format of the data, the default is csv.",
        choices=["txt", "csv"],
        default="csv",
        type=str,
    )
    add_output_argument(parser)
    parser.set_defaults(cmd_handler=invoke_list_command, parser=parser)
    return parser


def invoke_amend(args: argparse.Namespace) -> int:
    if args.help_operation:
        short_desc = args.operations_by_name[args.help_operation].short_description
        long_desc = reflow_paragraphs(
            args.operations_by_name[args.help_operation].long_description, indent=0
        )

        print()
        print(short_desc)
        print("-" * len(short_desc))
        print()
        print(long_desc)
        print()

        return Status.OK

    if not args.input:
        usage_error("<input> argument missing.", args.parser)

    # Prepare the operation options that were passed on the command-line
    config = {}
    operations = []
    for op in args.operation or args.default_operations:
        details = args.operations_by_name[op]
        operations.append(details.cls)
        op_arguments = {}
        for opt in details.options:
            dest = opt["dest"]
            op_argument = getattr(args, dest)
            if op_argument is None:
                usage_error(
                    f"Option {opt['name']} is required for operation {details.name}.",
                    args.parser,
                )
            op_arguments[dest] = op_argument

        config[details.cls] = op_arguments

    sbom, _ = read_sbom(args.input)

    amend.run(sbom, operations, config)
    write_sbom(sbom, args.output)
    return Status.OK


def invoke_merge(args: argparse.Namespace) -> int:
    global logger

    inputs = args.input

    if args.from_folder is not None:
        if not args.from_folder.is_dir():
            usage_error(
                "Path not found or is not a directory: " + str(args.from_folder),
                args.parser,
            )

        # Find all SBOMs in source folder (filenames: bom.json or *.cdx.json)
        folder_inputs: list[Path] = list(args.from_folder.glob("*.cdx.json"))
        if (args.from_folder / "bom.json").is_file():
            folder_inputs.append(args.from_folder / "bom.json")

        # Remove any paths which have already been provided as an explicit input
        folder_inputs = os_sorted(p for p in folder_inputs if p not in args.input)

        if len(folder_inputs) == 0:
            logger.warning(f"No additional SBOMs found in folder: {args.from_folder}")

        for input in folder_inputs:
            logger.debug(f"Found in folder: {input}")

        inputs += folder_inputs

    if len(inputs) < 2:
        usage_error(
            f"Not enough inputs. Must be at least 2, you have provided {len(inputs)}."
        )

    inputs = [sbom for (sbom, _) in (read_sbom(input) for input in inputs)]
    output = merge(inputs)
    write_sbom(output, args.output)
    return Status.OK


def invoke_merge_vex(args: argparse.Namespace) -> int:
    sbom, _ = read_sbom(args.sbom_file)
    vex, _ = read_sbom(args.vex_file)

    output = merge_vex(sbom, vex)
    write_sbom(output, args.output)
    return Status.OK


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
            usage_error(
                "<target> is required, unless the --from-file option is used.",
                args.parser,
            )
        elif args.key is None:
            usage_error(
                "--key is required, unless the --from-file option is used.", args.parser
            )
        elif args.value is None:
            usage_error(
                "--value is required, unless the --from-file option is used.",
                args.parser,
            )

        if args.name is not None:
            try:
                coordinates = cdxev.set.UpdateIdentity.from_coordinates(
                    name=args.name,
                    version=args.version,
                    group=args.group,
                    version_range=args.version_range,
                )
            except ValueError as exc:
                usage_error(str(exc))
        else:
            coordinates = None
        possible_targets = [
            args.swid,
            args.purl,
            args.cpe,
            coordinates,
        ]
        actual_targets = [x for x in possible_targets if x is not None]
        if len(actual_targets) > 1:
            usage_error("Cannot specify more than one <target>.", args.parser)

        target: Key = actual_targets[0]
        try:
            value = json.loads(args.value)
        except json.JSONDecodeError:
            usage_error(
                "<value> is not valid JSON. Possibly missing double quotes around a string?\n"
                f"Value:\t{args.value}",
                args.parser,
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
            if (
                isinstance(target.key, cdxev.set.CoordinatesWithVersionRange)
                and target.key.version_range is not None
            ):
                updates[0]["id"]["version-range"] = str(target.key.version_range)

    else:
        if has_target() or args.key is not None or args.value is not None:
            usage_error(
                "--from-file cannot be combined with <target>, --key or --value.",
                args.parser,
            )

        updates = []
        try:
            with open(args.from_file) as from_file:
                updates = json.load(from_file)
        except json.JSONDecodeError as ex:
            raise InputFileError(
                "Invalid JSON passed to --from-file",
                None,
                ex.lineno,
            ) from ex
        except FileNotFoundError as ex:
            raise InputFileError(f"File not found: {args.from_file}", None) from ex

    sbom, _ = read_sbom(args.input)
    cfg = cdxev.set.SetConfig(
        args.force,
        args.allow_protected,
        [args.input],
        args.from_file,
        args.ignore_missing,
        args.ignore_existing,
    )
    cdxev.set.run(sbom, updates, cfg)
    write_sbom(sbom, args.output)
    return Status.OK


def invoke_validate(args: argparse.Namespace) -> int:
    if bool(args.report_format) != bool(args.report_path):
        # This means exactly one of both arguments was passed but not both.
        usage_error(
            "Cannot use --report-format without --report-path or vice-versa.",
            args.parser,
        )

    if args.schema_type is None and args.schema_path is None:
        # Default to built-in stock schema. This case can't be handled by argparse
        # due to an undocumented behavior which keeps options with default values
        # from working correctly in mutually exclusive groups.
        args.schema_type = "default"

    sbom, file_type = read_sbom(args.input)
    return (
        Status.OK
        if validate_sbom(
            sbom=sbom,
            input_format=file_type,
            file=Path(args.input),
            report_format=args.report_format,
            report_path=args.report_path,
            schema_type=args.schema_type,
            filename_regex=(
                None if args.no_filename_validation else args.filename_pattern
            ),
            schema_path=args.schema_path,
        )
        == Status.OK
        else Status.VALIDATION_ERROR
    )


def invoke_build_public_bom(args: argparse.Namespace) -> int:
    sbom, _ = read_sbom(args.input)
    output = build_public_bom(sbom, args.schema_path)
    write_sbom(output, args.output)
    return Status.OK


def invoke_init_sbom(args: argparse.Namespace) -> int:
    sbom = initialize_sbom(
        software_name=args.name,
        authors=args.authors,
        supplier=args.supplier,
        version=args.version,
    )
    write_sbom(sbom, args.output, update_metadata=False)
    return Status.OK


def invoke_list_command(args: argparse.Namespace) -> int:
    sbom, _ = read_sbom(args.input)
    output = list_command(
        sbom=sbom,
        operation=args.operation,
        format=args.format,
    )
    write_list(output, args.output, sbom, format=args.format)

    return Status.OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
