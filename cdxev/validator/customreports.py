# SPDX-License-Identifier: GPL-3.0-or-later

import hashlib
import json
import logging
import pathlib
import traceback
import typing as t

from cdxev.log import LogMessage


class WarningsNgReporter(logging.Handler):
    """
    Reporter which writes in a JSON format for Jenkins's static analysis model. See
    https://github.com/jenkinsci/analysis-model/blob/master/src/main/java/edu/hm/hafner/analysis/Issue.java
    """

    # noinspection PyDefaultArgument
    def __init__(
        self,
        file_path: pathlib.Path,
        target: t.Union[t.TextIO, pathlib.Path],
        buffer: t.Optional[dict[str, list]] = None,
    ):
        """
        Creates a new handler with the given target.

        :param target: The target can be either a path to a file or a text stream object.
        """
        super().__init__(logging.ERROR)
        self.buffer = buffer if buffer is not None else {"issues": []}
        self.target = target
        self.file_path = file_path

    def emit(self, record: logging.LogRecord) -> None:
        issue = self.format_record(record)
        self.buffer["issues"].append(issue)

    def format_record(self, record: logging.LogRecord) -> dict[str, t.Union[str, int]]:
        if not isinstance(record.msg, LogMessage):
            raise TypeError("JenkinsFormatter cannot process string messages")

        frame = None
        if record.exc_info is not None:
            tb = traceback.extract_tb(record.exc_info[2])
            frame = tb.pop()

        if self.file_path is not None:
            file_name = self.file_path.name
            path_name = str(self.file_path.parent)
            line_start = record.msg.line_start
        elif frame is not None:
            file_path = pathlib.Path(frame.filename)
            file_name = file_path.name
            path_name = str(file_path.parent)
            line_start = frame.lineno
        else:
            file_name = None
            path_name = None
            line_start = record.msg.line_start

        if record.msg.module_name:
            module_name = record.msg.module_name
        else:
            module_name = ""

        issue: dict[str, t.Union[str, int]] = {
            "origin": "CycloneDX Editor Validator",
            "fingerprint": "unknown",
            "type": "SBOM",
            "category": "QA",
            "message": record.msg.message,
            "description": record.msg.description,
            "moduleName": module_name,
            "severity": record.levelname,
            "lineStart": line_start if line_start is not None else 0,
        }

        if file_name is not None:
            issue["fileName"] = file_name

        if path_name is not None:
            issue["pathName"] = path_name

        return issue

    def close(self) -> None:
        """
        Close the handler and write the buffer to the target.
        """
        s = json.dumps(self.buffer, indent=4)
        try:
            if isinstance(self.target, pathlib.Path):
                self.target.write_text(s)
            else:
                self.target.write(s)
        finally:
            super().close()


class GitLabCQReporter(logging.Handler):
    """
    Reporter which writes in a JSON format for GitLab Code Quality Report.
    See https://docs.gitlab.com/ee/ci/testing/code_quality.html#implement-a-custom-tool
    """

    # noinspection PyDefaultArgument
    def __init__(
        self,
        file_path: pathlib.Path,
        target: t.Union[t.TextIO, pathlib.Path],
        buffer: t.Optional[list] = None,
    ):
        """
        Creates a new handler with the given target.

        :param target: The target can be either a path to a file or a text stream object.
        """
        super().__init__(logging.ERROR)

        self.buffer = buffer if buffer is not None else []
        self.target = target
        self.file_path = file_path

    def emit(self, record: logging.LogRecord) -> None:
        issue = self.format_record(record)
        self.buffer.append(issue)

    def format_record(
        self, record: logging.LogRecord
    ) -> dict[str, t.Union[str, int, dict]]:
        if not isinstance(record.msg, LogMessage):
            raise TypeError("GitLabFormatter cannot process string messages")

        frame = None
        if record.exc_info is not None:
            tb = traceback.extract_tb(record.exc_info[2])
            frame = tb.pop()

        if self.file_path is not None:
            file_name = self.file_path.name
            line_start = record.msg.line_start
        elif frame is not None:
            file_path = pathlib.Path(frame.filename)
            file_name = file_path.name
            line_start = frame.lineno
        else:
            file_name = None
            line_start = record.msg.line_start

        issue: dict[str, t.Union[str, int, dict]] = {
            "description": record.msg.description,
            "check_name": "CycloneDX Editor Validator",
            "fingerprint": hashlib.md5(
                "unknown".encode(), usedforsecurity=False
            ).hexdigest(),
            "severity": "blocker",
            "location": {
                "path": file_name,
                "lines": {
                    "begin": line_start if line_start is not None else 0,
                },
            },
        }

        return issue

    def close(self) -> None:
        """
        Close the handler and write the buffer to the target.
        """
        s = json.dumps(self.buffer, indent=4)
        try:
            if isinstance(self.target, pathlib.Path):
                self.target.write_text(s)
            else:
                self.target.write(s)
        finally:
            super().close()
