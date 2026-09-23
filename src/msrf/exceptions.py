"""Exception hierarchy for msrf.

All errors raised deliberately by msrf derive from :class:`MsrfError` so
callers (CLI, MCP server, embedding code) can catch the whole family with a
single ``except``.
"""
from __future__ import annotations


class MsrfError(Exception):
    """Base class for every error raised by msrf."""


class ConfigurationError(MsrfError):
    """Raised when configuration is missing, malformed, or inconsistent."""


class ToolNotFoundError(MsrfError):
    """Raised when a required external tool cannot be located on the system.

    Attributes:
        tool: The logical tool name that was requested (e.g. ``"nmap"``).
        hint: A human-readable installation hint, when one is known.
    """

    def __init__(self, tool: str, hint: str | None = None) -> None:
        self.tool = tool
        self.hint = hint
        message = f"Required tool {tool!r} was not found on this system."
        if hint:
            message = f"{message} {hint}"
        super().__init__(message)


class EngineError(MsrfError):
    """Raised when an engine fails to perform an operation.

    Attributes:
        engine: The engine name that raised the error.
    """

    def __init__(self, engine: str, message: str) -> None:
        self.engine = engine
        super().__init__(f"[{engine}] {message}")


class CommandError(MsrfError):
    """Raised when an external command exits with a non-zero status.

    Attributes:
        command: The argv list that was executed.
        returncode: The process exit code.
        stdout: Captured standard output (may be truncated).
        stderr: Captured standard error (may be truncated).
    """

    def __init__(
        self,
        command: list[str],
        returncode: int,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        printable = " ".join(command)
        detail = stderr.strip() or stdout.strip() or "(no output)"
        super().__init__(
            f"Command failed ({returncode}): {printable}\n{detail}"
        )
