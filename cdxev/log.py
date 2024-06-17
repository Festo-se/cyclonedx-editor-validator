# CycloneDX Editor Validator
# Copyright (C) 2023  Festo SE & Co. KG

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import dataclasses
import logging
import logging.handlers
import traceback
import typing as t


@dataclasses.dataclass
class LogMessage:
    message: str
    """
    A short message, often not even a full sentence. Avoid putting a period at the end.
    """

    description: str
    """A longer description of the error."""

    module_name: t.Optional[str] = None
    """The module where the error occurred."""

    line_start: t.Optional[int] = None
    """The line where the error occurred in :py:attr:`file_name`."""


class LogMessageFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # noqa: N802
        if isinstance(record.msg, str):
            message = record.msg % record.args
        else:
            if not isinstance(record.msg, LogMessage):
                raise TypeError(
                    "This formatter can only process strings and LogMessage instances"
                )

            frame = None
            if record.exc_info is not None:
                tb = traceback.extract_tb(record.exc_info[2])
                frame = tb.pop()

            if record.msg.line_start is not None:
                line_start = record.msg.line_start
            elif frame is not None:
                if frame.lineno is not None:
                    line_start = frame.lineno
            else:
                line_start = None

            if record.msg.module_name is not None:
                component = record.msg.module_name
            else:
                component = None

            location = self._generate_location_str(line_start, component)

            message = record.msg.message + location + " - " + record.msg.description

        return f"{record.levelname}: {message}"

    def _generate_location_str(
        self,
        line_start: t.Optional[int],
        component: t.Optional[str],
    ) -> str:
        if line_start is None and component is None:
            return ""

        location = " ("
        if component is not None:
            location += "component: " + component

        if line_start is not None:
            location += " at line " + str(line_start)
            if "component: " not in location:
                location = location.replace(" at line", "at line")

        location += ")"
        return location


def configure_logging(quiet: bool, verbose: bool) -> None:
    """
    Configures the log level of the module.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    if not quiet:
        stderr_handler = logging.StreamHandler()
        stderr_handler.setLevel(logging.DEBUG)
        stderr_handler.setFormatter(LogMessageFormatter())
        root_logger.addHandler(stderr_handler)
