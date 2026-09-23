"""Light / dark / system themes for the msrf desktop app.

Built on the Fusion style so the app looks consistent on Linux, Windows and
macOS. The stored preference is ``"light"``, ``"dark"`` or ``"system"``
(``system`` follows the OS colour scheme). Apply with :func:`apply`.
"""
from __future__ import annotations

from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication, QStyleFactory, QTableWidgetItem

THEMES: tuple[str, ...] = ("light", "dark", "system")

LIGHT = {
    "window": "#f0f0f0",
    "base": "#ffffff",
    "alt": "#f7f7f7",
    "text": "#1a1a1a",
    "dim": "#6e7781",
    "button": "#e9ecef",
    "accent": "#0a64ad",
    "accent_text": "#ffffff",
    "border": "#a0a0a0",
    "grid": "#d4d4d4",
}
DARK = {
    "window": "#1f2226",
    "base": "#15181c",
    "alt": "#1b1e22",
    "text": "#e6edf3",
    "dim": "#8a9099",
    "button": "#2a2e34",
    "accent": "#1a86d0",
    "accent_text": "#ffffff",
    "border": "#3a3f46",
    "grid": "#30353c",
}

# Severity colours chosen to read on both light and dark backgrounds.
SEVERITY_COLORS = {
    "high": "#e05561",
    "warning": "#d19a00",
    "secure": "#3fb950",
    "good": "#3fb950",
    "info": "#4aa3ff",
    "hotspot": "#d19a00",
    "dangerous": "#e05561",
    "normal": "#3fb950",
}

#: Sort order for severities, most severe first (unknown values sort last).
SEVERITY_RANK = {
    "critical": 0, "high": 1, "dangerous": 1, "warning": 2, "medium": 2,
    "hotspot": 2, "low": 3, "info": 4, "note": 5, "normal": 6, "secure": 7,
    "good": 7,
}


class SeverityItem(QTableWidgetItem):
    """Table cell that sorts by severity rank (high before warning before info)
    instead of alphabetically."""

    def _rank(self) -> int:
        return SEVERITY_RANK.get(self.text().strip().lower(), 99)

    def __lt__(self, other: QTableWidgetItem) -> bool:
        if isinstance(other, SeverityItem) and self._rank() != other._rank():
            return self._rank() < other._rank()
        return self.text() < other.text()


def resolve_mode(mode: str, app: QApplication) -> str:
    if mode != "system":
        return mode if mode in ("light", "dark") else "light"
    try:
        from PyQt6.QtCore import Qt

        scheme = app.styleHints().colorScheme()
        return "dark" if scheme == Qt.ColorScheme.Dark else "light"
    except Exception:
        return "light"


def _stylesheet(c: dict[str, str]) -> str:
    return f"""
QMainWindow, QDialog {{ background: {c["window"]}; }}
QWidget {{ font-size: 12px; }}
QMenuBar, QToolBar, QStatusBar {{ background: {c["window"]}; }}
QMenuBar::item:selected, QMenu::item:selected {{ background: {c["accent"]}; color: {c["accent_text"]}; }}
QMenu {{ background: {c["base"]}; border: 1px solid {c["border"]}; }}
QToolBar {{ border-bottom: 1px solid {c["border"]}; spacing: 3px; padding: 3px; }}
QStatusBar {{ border-top: 1px solid {c["border"]}; }}
QStatusBar QLabel {{ padding: 0 8px; }}
QGroupBox {{
    border: 1px solid {c["border"]}; border-radius: 3px; margin-top: 10px; padding-top: 8px;
    background: {c["window"]}; font-weight: 600;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 8px; padding: 0 4px; color: {c["accent"]}; }}
QTabWidget::pane {{ border: 1px solid {c["border"]}; background: {c["base"]}; }}
QTabBar::tab {{
    background: {c["window"]}; border: 1px solid {c["border"]}; border-bottom: none;
    padding: 5px 12px; margin-right: 1px; color: {c["dim"]};
}}
QTabBar::tab:selected {{ background: {c["base"]}; color: {c["text"]}; }}
QTableView, QTreeView, QListView, QPlainTextEdit, QTextEdit, QLineEdit {{
    background: {c["base"]}; border: 1px solid {c["border"]}; color: {c["text"]};
}}
QTableView {{ gridline-color: {c["grid"]}; alternate-background-color: {c["alt"]};
    selection-background-color: {c["accent"]}; selection-color: {c["accent_text"]}; }}
QHeaderView::section {{
    background: {c["button"]}; color: {c["text"]}; border: none;
    border-right: 1px solid {c["border"]}; border-bottom: 1px solid {c["border"]};
    padding: 4px 6px; font-weight: 600;
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {c["accent"]}; }}
QComboBox, QSpinBox {{ background: {c["base"]}; border: 1px solid {c["border"]};
    border-radius: 4px; padding: 3px 6px; color: {c["text"]}; }}
QComboBox QAbstractItemView {{ background: {c["base"]}; border: 1px solid {c["border"]};
    selection-background-color: {c["accent"]}; selection-color: {c["accent_text"]}; }}
QPushButton {{ background: {c["button"]}; border: 1px solid {c["border"]};
    border-radius: 4px; padding: 4px 12px; min-height: 20px; color: {c["text"]}; }}
QPushButton:hover {{ border-color: {c["accent"]}; }}
QPushButton:disabled {{ color: {c["dim"]}; }}
QPushButton#primary {{ background: {c["accent"]}; color: {c["accent_text"]};
    border-color: {c["accent"]}; font-weight: 600; }}
QPushButton#primary:disabled {{ background: {c["button"]}; color: {c["dim"]};
    border-color: {c["border"]}; }}
QPlainTextEdit, QTextEdit {{ font-family: Consolas, 'DejaVu Sans Mono', monospace; }}
QScrollBar:vertical {{ background: {c["window"]}; width: 12px; }}
QScrollBar::handle:vertical {{ background: {c["border"]}; border-radius: 5px; min-height: 24px; }}
QDockWidget::title {{ background: {c["button"]}; padding: 4px; }}
"""


def apply(app: QApplication, mode: str = "light") -> str:
    """Apply the theme; returns the resolved mode (``light`` or ``dark``)."""
    resolved = resolve_mode(mode, app)
    c = DARK if resolved == "dark" else LIGHT
    if "Fusion" in QStyleFactory.keys():
        app.setStyle(QStyleFactory.create("Fusion"))

    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor(c["window"]))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(c["text"]))
    pal.setColor(QPalette.ColorRole.Base, QColor(c["base"]))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor(c["alt"]))
    pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(c["base"]))
    pal.setColor(QPalette.ColorRole.ToolTipText, QColor(c["text"]))
    pal.setColor(QPalette.ColorRole.Text, QColor(c["text"]))
    pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(c["dim"]))
    pal.setColor(QPalette.ColorRole.Button, QColor(c["button"]))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor(c["text"]))
    pal.setColor(QPalette.ColorRole.Highlight, QColor(c["accent"]))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor(c["accent_text"]))
    pal.setColor(QPalette.ColorRole.Link, QColor(c["accent"]))
    for role in (
        QPalette.ColorRole.WindowText,
        QPalette.ColorRole.Text,
        QPalette.ColorRole.ButtonText,
    ):
        pal.setColor(QPalette.ColorGroup.Disabled, role, QColor(c["dim"]))
    app.setPalette(pal)
    app.setStyleSheet(_stylesheet(c))
    return resolved
