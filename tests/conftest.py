"""Shared test configuration.

Force Qt into headless (offscreen) mode before any GUI test imports PyQt6, so
the suite runs on CI and machines without a display.
"""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
