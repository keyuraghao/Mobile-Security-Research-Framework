"""PyInstaller entry point for the standalone mobiot build.

Dual-purpose: with no arguments it launches the PyQt6 desktop GUI; with
arguments it behaves exactly like the ``mobiot`` CLI (so the single bundled
executable is both the app and the command-line tool, and can also run the MCP
server via ``mobiot serve``).
"""
import sys


def main() -> int:
    if len(sys.argv) > 1:
        from mobiot.cli import run as run_cli

        run_cli()
        return 0
    from mobiot.gui import run as run_gui

    return run_gui()


if __name__ == "__main__":
    sys.exit(main())
