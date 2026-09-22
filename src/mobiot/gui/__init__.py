"""mobiot desktop GUI (PyQt6).

A cross-platform desktop front-end over the same engine layer used by the CLI
and MCP server. Launch with ``mobiot ui`` or the ``mobiot-gui`` entry point.
"""
from __future__ import annotations

__all__ = ["run"]


def run() -> int:
    """Entry point for the desktop GUI (imported lazily so PyQt is optional)."""
    from .main import run as _run

    return _run()
