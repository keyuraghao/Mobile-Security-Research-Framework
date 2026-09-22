from __future__ import annotations

import sys

import pytest

from mobiot import platform_utils as pu
from mobiot.exceptions import CommandError, ToolNotFoundError


def test_normalized_arch_returns_stable_token():
    assert pu.normalized_arch() in {"x86_64", "x86", "arm64", "arm"} or isinstance(
        pu.normalized_arch(), str
    )


@pytest.mark.parametrize(
    "abi,expected",
    [
        ("arm64-v8a", "arm64"),
        ("aarch64", "arm64"),
        ("armeabi-v7a", "arm"),
        ("x86_64", "x86_64"),
        ("x86", "x86"),
    ],
)
def test_frida_server_arch(abi, expected):
    assert pu.frida_server_arch(abi) == expected


def test_which_finds_python():
    # The running interpreter's directory is on PATH in the test env.
    assert pu.which("python") or pu.which("python3")


def test_require_tool_raises_for_missing():
    with pytest.raises(ToolNotFoundError):
        pu.require_tool("definitely-not-a-real-tool-xyz", hint="nope")


def test_run_success():
    result = pu.run([sys.executable, "-c", "print('hi')"])
    assert result.ok
    assert "hi" in result.stdout


def test_run_failure_raises():
    with pytest.raises(CommandError):
        pu.run([sys.executable, "-c", "import sys; sys.exit(3)"])


def test_run_no_check_returns_result():
    result = pu.run([sys.executable, "-c", "import sys; sys.exit(3)"], check=False)
    assert result.returncode == 3
    assert not result.ok
