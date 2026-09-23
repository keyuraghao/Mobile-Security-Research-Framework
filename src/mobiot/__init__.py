"""mobiot — a unified, cross-platform Mobile & IoT SAST/DAST/pentest toolkit.

mobiot wraps and orchestrates best-in-class security engines behind a single
CLI and an MCP (Model Context Protocol) server:

    * SAST / DAST   -> MobSF
    * Instrumentation -> Frida
    * Runtime exploration -> objection
    * Traffic interception -> mitmproxy
    * IoT / firmware -> nmap + binwalk

The design goal is extensibility: every capability is an :class:`Engine`
registered in a central :data:`mobiot.registry.registry`, so new engines can be
added in new releases without touching the CLI or MCP surface.
"""
from __future__ import annotations

__all__ = ["__version__", "get_version"]

__version__ = "0.3.3"


def get_version() -> str:
    """Return the installed package version.

    Falls back to the hard-coded :data:`__version__` when the package metadata
    is unavailable (e.g. running from a source checkout that was never built).
    """
    try:
        from importlib.metadata import version

        return version("mobiot")
    except Exception:  # pragma: no cover - metadata only present when installed
        return __version__
