"""Lightweight charts drawn with QPainter (no extra dependency).

A small bar chart and donut chart used on the Dashboard to visualise findings
by severity and by source, and engine readiness. Painting by hand keeps the
standalone bundle small and avoids QtCharts, and the widgets read their text
colour from the active palette so they work in light and dark themes.
"""
from __future__ import annotations

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QFont, QFontMetrics, QPainter, QPen
from PyQt6.QtWidgets import QWidget

Datum = tuple[str, float, str]  # (label, value, color hex)


class _ChartBase(QWidget):
    def __init__(self, title: str = "") -> None:
        super().__init__()
        self._title = title
        self._data: list[Datum] = []
        self.setMinimumHeight(180)

    def set_data(self, data: list[Datum]) -> None:
        self._data = [(str(label), float(value), color) for label, value, color in data]
        self.update()

    def _ink(self) -> QColor:
        return self.palette().windowText().color()

    def _muted(self) -> QColor:
        c = self._ink()
        c.setAlpha(150)
        return c

    def _draw_title(self, p: QPainter) -> int:
        if not self._title:
            return 6
        f = QFont(self.font())
        f.setBold(True)
        p.setFont(f)
        p.setPen(self._ink())
        p.drawText(8, 4, self.width() - 16, 20,
                   Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, self._title)
        p.setFont(self.font())
        return 26

    def _draw_empty(self, p: QPainter, top: int) -> None:
        p.setPen(self._muted())
        p.drawText(0, top, self.width(), self.height() - top,
                   Qt.AlignmentFlag.AlignCenter, "No data yet")


class BarChart(_ChartBase):
    """Vertical bars with a value above and a label below each bar."""

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        top = self._draw_title(p)
        total = sum(v for _, v, _ in self._data)
        if not self._data or total == 0:
            self._draw_empty(p, top)
            return
        left, right, bottom = 10, 10, 22
        area_top = top + 16
        w = self.width() - left - right
        h = self.height() - area_top - bottom
        n = len(self._data)
        gap = 14
        bar_w = max(8, (w - gap * (n - 1)) / n)
        vmax = max(v for _, v, _ in self._data) or 1
        fm = QFontMetrics(self.font())
        for i, (label, value, color) in enumerate(self._data):
            x = left + i * (bar_w + gap)
            bh = (value / vmax) * (h - 4) if vmax else 0
            y = area_top + (h - bh)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(color))
            p.drawRoundedRect(QRectF(x, y, bar_w, bh), 3, 3)
            # value above the bar
            p.setPen(self._ink())
            p.drawText(QRectF(x - gap / 2, y - 18, bar_w + gap, 16),
                       Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom,
                       str(int(value)))
            # label below
            p.setPen(self._muted())
            text = fm.elidedText(label, Qt.TextElideMode.ElideRight, int(bar_w + gap))
            p.drawText(QRectF(x - gap / 2, area_top + h + 2, bar_w + gap, 18),
                       Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, text)


class DonutChart(_ChartBase):
    """A donut (ring) with the total in the middle and a legend below."""

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        top = self._draw_title(p)
        total = sum(v for _, v, _ in self._data)
        legend_h = 18 * len(self._data) + 6
        ring_area = self.height() - top - legend_h
        size = max(60, min(self.width(), ring_area) - 12)
        cx = self.width() / 2
        cy = top + ring_area / 2
        rect = QRectF(cx - size / 2, cy - size / 2, size, size)
        thickness = max(14, size * 0.22)

        if total == 0:
            pen = QPen(self._muted())
            pen.setWidthF(thickness)
            p.setPen(pen)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(rect)
        else:
            start = 90 * 16  # start at 12 o'clock, go clockwise
            for _label, value, color in self._data:
                if value <= 0:
                    continue
                span = -int(round(360 * 16 * value / total))
                pen = QPen(QColor(color))
                pen.setWidthF(thickness)
                pen.setCapStyle(Qt.PenCapStyle.FlatCap)
                p.setPen(pen)
                p.drawArc(rect, start, span)
                start += span
        # centre total
        f = QFont(self.font())
        f.setBold(True)
        f.setPointSizeF(self.font().pointSizeF() + 3)
        p.setFont(f)
        p.setPen(self._ink())
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, str(int(total)))
        p.setFont(self.font())

        # legend
        ly = top + ring_area + 2
        for label, value, color in self._data:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(color))
            p.drawRoundedRect(QRectF(10, ly + 3, 11, 11), 2, 2)
            p.setPen(self._ink())
            p.drawText(QRectF(28, ly, self.width() - 34, 16),
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                       f"{label}  ({int(value)})")
            ly += 18
