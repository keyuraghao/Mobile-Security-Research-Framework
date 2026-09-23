"""Classic Windows-style light theme for the mobiot desktop app.

Uses Qt's native Windows style where available (``windowsvista``), otherwise
``Fusion`` with a light system palette, so the app has a clean, familiar
classic-Windows look on every OS: grey chrome, white content areas, menu bar,
tool bar and status bar.
"""
from __future__ import annotations

from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication, QStyleFactory

# Classic Windows-ish colours.
WINDOW = "#f0f0f0"
CONTENT = "#ffffff"
BORDER = "#a0a0a0"
TEXT = "#1a1a1a"
ACCENT = "#0a64ad"
ACCENT_LIGHT = "#cfe4f5"
HIGH = "#c0392b"
WARN = "#c07a00"
GOOD = "#1e7e34"
INFO = "#0a64ad"

# Light, restrained QSS refinements over the native/Fusion style.
STYLESHEET = f"""
QMainWindow, QDialog {{ background: {WINDOW}; }}
QWidget {{ font-size: 12px; }}
QMenuBar {{ background: {WINDOW}; }}
QMenuBar::item:selected {{ background: {ACCENT_LIGHT}; }}
QToolBar {{ background: {WINDOW}; border-bottom: 1px solid {BORDER}; spacing: 3px; padding: 3px; }}
QStatusBar {{ background: {WINDOW}; border-top: 1px solid {BORDER}; }}
QStatusBar QLabel {{ padding: 0 8px; }}
QGroupBox {{
    border: 1px solid {BORDER}; border-radius: 3px; margin-top: 10px; padding-top: 8px;
    background: {WINDOW}; font-weight: 600;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 8px; padding: 0 4px; }}
QTabWidget::pane {{ border: 1px solid {BORDER}; background: {CONTENT}; }}
QTabBar::tab {{
    background: {WINDOW}; border: 1px solid {BORDER}; border-bottom: none;
    padding: 5px 12px; margin-right: 1px;
}}
QTabBar::tab:selected {{ background: {CONTENT}; }}
QTableView, QTreeView, QListView, QPlainTextEdit, QTextEdit, QLineEdit {{
    background: {CONTENT}; border: 1px solid {BORDER};
}}
QTableView {{ gridline-color: #d4d4d4; alternate-background-color: #f7f7f7; }}
QHeaderView::section {{
    background: {WINDOW}; border: none; border-right: 1px solid {BORDER};
    border-bottom: 1px solid {BORDER}; padding: 4px 6px; font-weight: 600;
}}
QPushButton {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #fbfbfb, stop:1 #e8e8e8);
    border: 1px solid {BORDER}; border-radius: 3px; padding: 4px 12px; min-height: 20px;
}}
QPushButton:hover {{ border-color: {ACCENT}; }}
QPushButton:pressed {{ background: #dcdcdc; }}
QPushButton:disabled {{ color: #9a9a9a; }}
QPushButton#primary {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #1a86d0, stop:1 {ACCENT});
    color: white; border-color: {ACCENT}; font-weight: 600;
}}
QPushButton#primary:hover {{ background: {ACCENT}; }}
QPlainTextEdit, QTextEdit {{ font-family: Consolas, 'DejaVu Sans Mono', monospace; }}
"""


def apply(app: QApplication) -> None:
    """Apply the classic Windows-style look to the application."""
    styles = {s.lower(): s for s in QStyleFactory.keys()}
    for pref in ("windowsvista", "windows", "fusion"):
        if pref in styles:
            app.setStyle(QStyleFactory.create(styles[pref]))
            break

    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor(WINDOW))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.Base, QColor(CONTENT))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor("#f7f7f7"))
    pal.setColor(QPalette.ColorRole.Text, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.Button, QColor(WINDOW))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.Highlight, QColor(ACCENT))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    pal.setColor(QPalette.ColorRole.ToolTipBase, QColor("#ffffe1"))
    pal.setColor(QPalette.ColorRole.ToolTipText, QColor(TEXT))
    app.setPalette(pal)
    app.setStyleSheet(STYLESHEET)


SEVERITY_COLORS = {
    "high": HIGH,
    "warning": WARN,
    "secure": GOOD,
    "good": GOOD,
    "info": INFO,
    "hotspot": WARN,
    "dangerous": HIGH,
    "normal": GOOD,
}
