"""Cross-platform helpers: OS detection, tool discovery, subprocess execution.

Everything here is written to behave identically on Linux, macOS and Windows.
No POSIX-only assumptions (no hardcoded ``/usr/bin`` paths, no shell=True).
Tools are located with :func:`shutil.which` so a user's ``PATH`` is honoured on
every platform, and Windows ``.exe``/``.bat`` suffixes are handled automatically
by ``which``.
"""
from __future__ import annotations

import contextlib
import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .exceptions import CommandError, ToolNotFoundError

# ---------------------------------------------------------------------------
# OS / architecture detection
# ---------------------------------------------------------------------------

IS_WINDOWS = os.name == "nt"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

#: Extra subprocess kwargs that stop a console window flashing up on Windows
#: each time the (windowed) desktop app runs a console tool such as adb. Empty
#: on Linux/macOS.
NO_WINDOW: dict = (
    {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}
)


def os_name() -> str:
    """Return a stable short OS identifier: ``windows``, ``macos`` or ``linux``."""
    if IS_WINDOWS:
        return "windows"
    if IS_MACOS:
        return "macos"
    if IS_LINUX:
        return "linux"
    return sys.platform


def normalized_arch() -> str:
    """Return a normalized CPU architecture string.

    Maps the many aliases reported by :func:`platform.machine` onto a small,
    stable set: ``x86_64``, ``x86``, ``arm64``, ``arm``.
    """
    machine = platform.machine().lower()
    mapping = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "x64": "x86_64",
        "i386": "x86",
        "i686": "x86",
        "x86": "x86",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv8": "arm64",
        "armv7l": "arm",
        "armv7": "arm",
    }
    return mapping.get(machine, machine)


def frida_server_arch(abi: str) -> str:
    """Map an Android/iOS device ABI to the frida-server download architecture.

    Args:
        abi: The device ABI as reported by ``adb shell getprop ro.product.cpu.abi``
            (e.g. ``arm64-v8a``) or an iOS arch.

    Returns:
        The frida-server arch token used in release asset names
        (``arm64``, ``arm``, ``x86_64`` or ``x86``).
    """
    abi = abi.lower()
    if "arm64" in abi or "aarch64" in abi:
        return "arm64"
    if "armeabi" in abi or abi.startswith("arm"):
        return "arm"
    if "x86_64" in abi or "x64" in abi:
        return "x86_64"
    if "x86" in abi or "i686" in abi or "i386" in abi:
        return "x86"
    return abi


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------


def which(tool: str, extra_paths: Sequence[Path] | None = None) -> str | None:
    """Locate an executable, honouring ``PATH`` plus optional extra directories.

    Args:
        tool: Executable name without any platform-specific suffix.
        extra_paths: Additional directories to search before ``PATH``.

    Returns:
        The absolute path to the executable, or ``None`` if not found.
    """
    if extra_paths:
        search = os.pathsep.join(str(p) for p in extra_paths)
        search = search + os.pathsep + (os.environ.get("PATH") or "")
        found = shutil.which(tool, path=search)
        if found:
            return found
    return shutil.which(tool)


def require_tool(
    tool: str,
    hint: str | None = None,
    extra_paths: Sequence[Path] | None = None,
) -> str:
    """Locate an executable or raise :class:`ToolNotFoundError`.

    Args:
        tool: Executable name.
        hint: Installation hint surfaced in the error message.
        extra_paths: Additional directories to search.
    """
    found = which(tool, extra_paths=extra_paths)
    if not found:
        raise ToolNotFoundError(tool, hint)
    return found


# ---------------------------------------------------------------------------
# Subprocess execution
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class CommandResult:
    """Outcome of a finished subprocess."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run(
    command: Sequence[str],
    *,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    check: bool = True,
    input_text: str | None = None,
) -> CommandResult:
    """Run a command and capture its output, cross-platform and shell-free.

    ``shell=False`` always: arguments are passed as a list so there is no shell
    quoting or injection surface, and behaviour is identical on every OS.

    Args:
        command: argv list. The first element is resolved as-is (already an
            absolute path, or found on ``PATH`` by the OS).
        cwd: Working directory.
        env: Environment overrides merged onto the current environment.
        timeout: Seconds before the process is killed and an error raised.
        check: When ``True``, raise :class:`CommandError` on non-zero exit.
        input_text: Optional text piped to the process stdin.

    Returns:
        A :class:`CommandResult`.

    Raises:
        CommandError: If ``check`` is true and the command fails, or on timeout.
    """
    argv = [str(part) for part in command]
    merged_env = None
    if env:
        merged_env = {**os.environ, **env}

    try:
        completed = subprocess.run(  # noqa: S603 - argv list, shell=False
            argv,
            **NO_WINDOW,
            cwd=str(cwd) if cwd else None,
            env=merged_env,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - timing
        raise CommandError(
            argv,
            returncode=124,
            stdout=_as_text(exc.stdout),
            stderr=f"Timed out after {timeout}s",
        ) from exc

    result = CommandResult(
        command=argv,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )
    if check and not result.ok:
        raise CommandError(
            argv, result.returncode, result.stdout, result.stderr
        )
    return result


def run_logged(
    command: Sequence[str],
    *,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    check: bool = True,
    input_text: str | None = None,
    log_path: Path | None = None,
    tag: str | None = None,
) -> CommandResult:
    """Run a command, streaming its combined output to ``log_path`` line by line.

    Same contract as :func:`run` (returns a :class:`CommandResult`, raises
    :class:`CommandError` on failure/timeout when ``check``), but instead of
    buffering silently it appends each line to ``log_path`` as it is produced.
    This makes long, chatty steps (SDK downloads, image installs, rooting)
    observable in real time, so a stall is visible in the log rather than
    looking like a freeze. A watchdog kills the process on ``timeout`` even if
    it produces no output.
    """
    import threading

    argv = [str(part) for part in command]
    merged_env = {**os.environ, **env} if env else None
    logf = None
    if log_path is not None:
        # Line-buffered append so a tailing reader sees output immediately.
        logf = open(log_path, "a", buffering=1, encoding="utf-8", errors="replace")  # noqa: SIM115
    collected: list[str] = []
    timed_out = {"hit": False}
    proc: subprocess.Popen | None = None
    watchdog: threading.Timer | None = None
    try:
        if logf and tag:
            logf.write(f"\n$ {tag}\n")
        proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False
            argv,
            **NO_WINDOW,
            cwd=str(cwd) if cwd else None,
            env=merged_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        if input_text is not None and proc.stdin is not None:
            # A process that exits fast can close the pipe first; that is fine.
            with contextlib.suppress(Exception):
                proc.stdin.write(input_text)
                proc.stdin.close()
        if timeout:
            def _kill() -> None:
                # Only a genuine timeout: if the process already finished it has
                # an exit code, so poll() is not None and we must not flag it.
                if proc.poll() is None:
                    timed_out["hit"] = True
                    with contextlib.suppress(Exception):
                        proc.kill()
            watchdog = threading.Timer(timeout, _kill)
            watchdog.start()
        assert proc.stdout is not None
        for line in proc.stdout:
            collected.append(line)
            if logf:
                logf.write(line)
        proc.wait()
    finally:
        if watchdog:
            watchdog.cancel()
        if logf:
            logf.close()
    out = "".join(collected)
    rc = proc.returncode if proc else -1
    if timed_out["hit"]:
        raise CommandError(argv, 124, out, f"Timed out after {timeout}s")
    result = CommandResult(command=argv, returncode=rc, stdout=out, stderr="")
    if check and not result.ok:
        raise CommandError(argv, rc, out, "")
    return result


def spawn(
    command: Sequence[str],
    *,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    stdout: Path | None = None,
) -> subprocess.Popen:
    """Start a long-running background process and return the handle.

    Used for services such as the MobSF server or a mitmproxy capture that must
    outlive a single call. Output is redirected to ``stdout`` when provided,
    otherwise discarded. The caller owns the returned :class:`~subprocess.Popen`
    and is responsible for terminating it.
    """
    argv = [str(part) for part in command]
    merged_env = {**os.environ, **env} if env else None
    out = open(stdout, "ab") if stdout else subprocess.DEVNULL  # noqa: SIM115
    try:
        return subprocess.Popen(  # noqa: S603 - argv list, shell=False
            argv,
            **NO_WINDOW,
            cwd=str(cwd) if cwd else None,
            env=merged_env,
            stdout=out,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
    finally:
        # The child has inherited (dup'd) the fd; the parent's copy must be closed
        # or it leaks one fd per spawn for the lifetime of this process.
        if out is not subprocess.DEVNULL:
            out.close()


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)
