#!/usr/bin/env python3
"""Generate icon.ico and icon.png from the packaged icon.svg.

Renders the SVG with Qt (offscreen) at 256x256, then writes a multi-size .ico
(for the Windows exe/installer) and a .png (for Linux .desktop / macOS iconset)
next to it under src/msrf/data/.
"""
from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

DATA = Path(__file__).resolve().parent.parent / "src" / "msrf" / "data"


def render_png(svg: bytes, size: int) -> bytes:
    from PyQt6.QtCore import QByteArray, Qt
    from PyQt6.QtGui import QImage, QPainter
    from PyQt6.QtSvg import QSvgRenderer

    renderer = QSvgRenderer(QByteArray(svg))
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    painter = QPainter(img)
    renderer.render(painter)
    painter.end()
    tmp = DATA / f"_icon_{size}.png"
    img.save(str(tmp), "PNG")
    data = tmp.read_bytes()
    tmp.unlink(missing_ok=True)
    return data


def main() -> int:
    from PyQt6.QtWidgets import QApplication

    QApplication([])  # needed for QImage/QPainter
    svg = (DATA / "icon.svg").read_bytes()

    # icon.png (256) for Linux/macOS.
    (DATA / "icon.png").write_bytes(render_png(svg, 256))

    # icon.ico with the standard Windows sizes.
    from io import BytesIO

    from PIL import Image

    base = Image.open(BytesIO(render_png(svg, 256))).convert("RGBA")
    base.save(
        DATA / "icon.ico",
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    print("wrote", DATA / "icon.png", "and", DATA / "icon.ico")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
