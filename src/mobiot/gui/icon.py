"""Application icon loader (from the packaged SVG, rendered at several sizes)."""
from __future__ import annotations

from importlib.resources import files

from PyQt6.QtCore import QByteArray, Qt
from PyQt6.QtGui import QIcon, QPainter, QPixmap


def app_icon() -> QIcon:
    """Return the mobiot application icon rendered from the packaged SVG."""
    try:
        data = (files("mobiot.data") / "icon.svg").read_bytes()
    except Exception:
        return QIcon()
    icon = QIcon()
    try:
        from PyQt6.QtSvg import QSvgRenderer

        renderer = QSvgRenderer(QByteArray(data))
        for size in (16, 24, 32, 48, 64, 128, 256):
            pix = QPixmap(size, size)
            pix.fill(Qt.GlobalColor.transparent)
            painter = QPainter(pix)
            renderer.render(painter)
            painter.end()
            icon.addPixmap(pix)
    except Exception:
        pix = QPixmap()
        if pix.loadFromData(data):
            icon.addPixmap(pix)
    return icon
