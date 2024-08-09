# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Optional

from cdxev.log import LogMessage


class AppError(Exception):
    """Parent class of all custom exceptions."""

    def __init__(
        self,
        message: Optional[str] = None,
        description: Optional[str] = None,
        module_name: Optional[str] = None,
        line_start: Optional[int] = None,
        *,
        log_msg: Optional[LogMessage] = None,
    ):
        """
        :param str message: A short message, often not even a full sentence. Avoid putting a
        period at the end.
        :param str description: A longer description of the error.
        :param str module_name: The module where the error occurred. Typically set to `__name__`.
        in the SBOM file, this can be the path to the SBOM.
        :param line_start: The line where the error occurred in *file_name*.
        :type line_start: int or None
        :param log_msg: A LogMessage object can directly be passed to the constructor. If any of
        the other arguments are passed, this LogMessage's respective field will be overwritten
        with the argument.
        """
        super().__init__()
        if log_msg is not None:
            if message is not None:
                log_msg.message = message
            if description is not None:
                log_msg.description = description
            if module_name is not None:
                log_msg.module_name = module_name
            if line_start is not None:
                log_msg.line_start = line_start
            self.details = log_msg
        elif message is None or description is None:
            raise ValueError(
                "Either log_msg or message and description must be passed."
            )
        else:
            self.details = LogMessage(
                message,
                description,
                module_name,
                line_start,
            )

    def __str__(self) -> str:
        return str(self.details)


class InputFileError(AppError):
    """Indicates an error while loading an input."""

    def __init__(
        self,
        description: str,
        module_name: Optional[str] = None,
        line_start: Optional[int] = None,
    ):
        """
        :param str description: A description of the error.
        :param str module_name: The module where the error occurred. Typically set to `__name__`.
        in the SBOM file, this can be the path to the SBOM.
        :param line_start: The line where the error occurred in *file_name*.
        :type line_start: int or None
        """
        super().__init__(
            "Failed to load input file",
            description,
            module_name,
            line_start,
        )
