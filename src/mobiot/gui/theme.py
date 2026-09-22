"""Dark theme (Qt style sheet) and palette for the mobiot GUI."""
from __future__ import annotations

# Brand-neutral dark palette.
BG = "#0f1419"
BG_ALT = "#161b22"
PANEL = "#1c2330"
BORDER = "#2b3340"
TEXT = "#e6edf3"
MUTED = "#8b949e"
ACCENT = "#3fb6ff"
ACCENT_DIM = "#265d7a"
GOOD = "#3fb950"
WARN = "#d29922"
BAD = "#f85149"
MONO = "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace"

STYLESHEET = f"""
* {{
    font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
    font-size: 13px;
    color: {TEXT};
}}
QMainWindow, QWidget {{ background: {BG}; }}
QLabel#h1 {{ font-size: 20px; font-weight: 700; color: {TEXT}; }}
QLabel#h2 {{ font-size: 15px; font-weight: 600; color: {TEXT}; }}
QLabel#muted {{ color: {MUTED}; }}
QLabel#brand {{ font-size: 18px; font-weight: 800; color: {ACCENT}; }}

QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 8px; top: -1px; background: {BG_ALT}; }}
QTabBar::tab {{
    background: transparent; color: {MUTED};
    padding: 9px 16px; margin-right: 2px;
    border-top-left-radius: 8px; border-top-right-radius: 8px;
    font-weight: 600;
}}
QTabBar::tab:selected {{ color: {TEXT}; background: {BG_ALT}; border: 1px solid {BORDER}; border-bottom: none; }}
QTabBar::tab:hover {{ color: {TEXT}; }}

QPushButton {{
    background: {PANEL}; border: 1px solid {BORDER}; border-radius: 7px;
    padding: 8px 14px; font-weight: 600;
}}
QPushButton:hover {{ border-color: {ACCENT}; }}
QPushButton:pressed {{ background: {BG_ALT}; }}
QPushButton#primary {{ background: {ACCENT_DIM}; border-color: {ACCENT}; color: {TEXT}; }}
QPushButton#primary:hover {{ background: {ACCENT}; color: {BG}; }}
QPushButton:disabled {{ color: {MUTED}; border-color: {BORDER}; background: {BG_ALT}; }}

QLineEdit, QComboBox, QSpinBox {{
    background: {BG}; border: 1px solid {BORDER}; border-radius: 7px; padding: 7px 10px;
    selection-background-color: {ACCENT_DIM};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {ACCENT}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{ background: {PANEL}; border: 1px solid {BORDER}; selection-background-color: {ACCENT_DIM}; }}

QTextEdit, QPlainTextEdit {{
    background: {BG}; border: 1px solid {BORDER}; border-radius: 8px;
    font-family: {MONO}; font-size: 12px; padding: 8px;
}}
QTreeWidget, QTableWidget, QListWidget {{
    background: {BG}; border: 1px solid {BORDER}; border-radius: 8px;
    alternate-background-color: {BG_ALT}; gridline-color: {BORDER};
}}
QHeaderView::section {{
    background: {PANEL}; color: {MUTED}; border: none; border-bottom: 1px solid {BORDER};
    padding: 7px; font-weight: 600;
}}
QGroupBox {{
    border: 1px solid {BORDER}; border-radius: 8px; margin-top: 14px; padding: 12px;
    font-weight: 600; background: {BG_ALT};
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; color: {ACCENT}; }}
QScrollBar:vertical {{ background: {BG}; width: 11px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 5px; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: {MUTED}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
QProgressBar {{ border: 1px solid {BORDER}; border-radius: 6px; background: {BG}; text-align: center; }}
QProgressBar::chunk {{ background: {ACCENT_DIM}; border-radius: 5px; }}
"""
