"""PyInstaller entry point for the mobiot desktop application.

Bundled as a standalone executable per OS by the release workflow. Launches the
same PyQt6 GUI as ``mobiot ui``.
"""
import sys

from mobiot.gui import run

if __name__ == "__main__":
    sys.exit(run())
