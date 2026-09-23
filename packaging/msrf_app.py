"""PyInstaller entry point for the standalone msrf build.

Dual-purpose: with no arguments it launches the PyQt6 desktop GUI; with
arguments it behaves exactly like the ``msrf`` CLI (so the single bundled
executable is both the app and the command-line tool, and can also run the MCP
server via ``msrf serve``).
"""
import sys


def main() -> int:
    if len(sys.argv) > 1:
        from msrf.cli import run as run_cli

        run_cli()
        return 0
    from msrf.gui import run as run_gui

    return run_gui()


if __name__ == "__main__":
    sys.exit(main())
