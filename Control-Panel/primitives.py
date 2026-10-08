"""
Control-Panel/primitives.py
"""
from __future__ import annotations
from datetime import datetime

from PyQt6.QtCore    import Qt, QTimer, QPropertyAnimation, QEasingCurve, pyqtProperty
from PyQt6.QtGui     import QBrush, QColor, QLinearGradient, QPainter, QPen, QTextCursor
from PyQt6.QtWidgets import (QFrame, QGraphicsDropShadowEffect, QLabel,
                              QLineEdit, QPushButton, QTextEdit, QWidget)

from config import C, TERMINAL_FONT


# ══════════════════════════════════════════════════════════════════════════════
class StatusLight(QWidget):
    OFF = 0; ON = 1; ERR = 2; PENDING = 3

    _COL  = {OFF: C.T3,    ON: C.GREEN, ERR: C.RED,   PENDING: C.AMBER}
    _GLOW = {OFF: None,    ON: C.GREEN, ERR: C.RED,   PENDING: C.AMBER}

    def __init__(self, size: int = 8, parent=None):
        super().__init__(parent)
        self.setFixedSize(size + 6, size + 6)
        self._sz  = size
        self._st  = self.OFF
        self._ph  = 0.0
        self._dir = 1
        self._t   = QTimer(self)
        self._t.setInterval(35)
        self._t.timeout.connect(self._tick)

    def setState(self, s: int) -> None:
        self._st = s
        if s in (self.ON, self.ERR, self.PENDING):
            self._t.start()
        else:
            self._t.stop(); self._ph = 0; self.update()

    def _tick(self) -> None:
        self._ph = max(0.0, min(1.0, self._ph + 0.035 * self._dir))
        if self._ph in (0.0, 1.0): self._dir *= -1
        self.update()

    def paintEvent(self, _) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        cx = self.width() // 2
        cy = self.height() // 2
        sz = self._sz

        gc = self._GLOW[self._st]
        if gc and self._ph > 0.01:
            for r_add, alpha_mul in [(5, 0.15), (3, 0.3), (1, 0.5)]:
                g = QColor(gc)
                g.setAlpha(int(200 * self._ph * alpha_mul))
                p.setBrush(QBrush(g))
                r = sz // 2 + r_add
                p.drawEllipse(cx - r, cy - r, r * 2, r * 2)

        dot = QColor(self._COL[self._st])
        p.setBrush(QBrush(dot))
        r = sz // 2
        p.drawEllipse(cx - r, cy - r, r * 2, r * 2)

        # inner highlight
        if self._st != self.OFF:
            hi = QColor(255, 255, 255, int(80 * (0.3 + 0.7 * self._ph)))
            p.setBrush(QBrush(hi))
            r2 = max(1, r // 2)
            p.drawEllipse(cx - r2 // 2, cy - r2, r2, r2)


# ══════════════════════════════════════════════════════════════════════════════
class Btn(QPushButton):
    _STYLES = {
        "success": (C.GREEN,  C.GREEN_B,  "#0A2510", C.T0),
        "danger":  (C.RED,    C.RED_B,    "#280D0D",  C.T0),
        "primary": (C.G2,     C.G_DIM,    C.G_MID,   C.T0),
        "ghost":   (C.BDR2,   C.SURF1,    C.SURF2,   C.T1),
        "gold":    (C.G3,     C.G_DIM,    C.G_MID,   "#0A0800"),
        "gold2":   (C.G4,     C.G_MID,    C.G_GLOW,  "#0A0800"),
    }

    def __init__(self, label: str, variant: str = "primary",
                 w: int | None = None, h: int = 28, parent=None):
        super().__init__(label, parent)
        self._v   = variant
        self._hov = False
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(h)
        if w: self.setFixedWidth(w)
        self._draw()

    def _draw(self) -> None:
        ac, bg_off, bg_on, tc = self._STYLES[self._v]
        bg = bg_on if self._hov else bg_off
        self.setStyleSheet(f"""
            QPushButton {{
                background: {bg};
                color: {tc};
                border: 1px solid {ac}{'88' if self._hov else '44'};
                border-radius: 5px;
                padding: 0 14px;
                font-size: 11px;
                font-weight: 600;
                font-family: {TERMINAL_FONT};
                letter-spacing: 0.3px;
            }}
            QPushButton:pressed {{
                background: {ac}33;
                border-color: {ac}CC;
            }}
            QPushButton:disabled {{
                background: {C.SURF1};
                color: {C.T3};
                border-color: {C.BDR0};
            }}
        """)

    def enterEvent(self, e): self._hov = True;  self._draw(); super().enterEvent(e)
    def leaveEvent(self, e): self._hov = False; self._draw(); super().leaveEvent(e)


# ══════════════════════════════════════════════════════════════════════════════
class Field(QLineEdit):
    def __init__(self, val: str = "", w: int | None = None, parent=None):
        super().__init__(val, parent)
        if w: self.setFixedWidth(w)
        self.setFixedHeight(26)
        self.setStyleSheet(f"""
            QLineEdit {{
                background: {C.SURF0};
                color: {C.T0};
                border: 1px solid {C.BDR1};
                border-radius: 5px;
                padding: 0 10px;
                font-size: 11px;
                font-family: {TERMINAL_FONT};
            }}
            QLineEdit:focus {{
                border-color: {C.G2};
                background: {C.G_DIM};
                color: {C.G4};
            }}
            QLineEdit:hover {{
                border-color: {C.BDR2};
            }}
        """)


# ══════════════════════════════════════════════════════════════════════════════
class Log(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setStyleSheet(f"""
            QTextEdit {{
                background: {C.SURF0};
                color: {C.TCO};
                border: none;
                padding: 10px 16px;
                font-family: {TERMINAL_FONT};
                font-size: 11px;
                line-height: 1.6;
            }}
        """)
        self._append("·", "terminal initialized", C.T2)

    def _ts(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _append(self, icon: str, msg: str, col: str) -> None:
        self.moveCursor(QTextCursor.MoveOperation.End)
        self.insertHtml(
            f'<span style="color:{C.T2};font-size:9px;letter-spacing:0.5px;'
            f'font-family:{TERMINAL_FONT}">{self._ts()}</span>'
            f'&nbsp;&nbsp;&nbsp;'
            f'<span style="color:{col};font-weight:600;font-family:{TERMINAL_FONT}">{icon}</span>'
            f'&nbsp;&nbsp;<span style="color:{col};font-family:{TERMINAL_FONT}">{msg}</span><br>'
        )
        self.moveCursor(QTextCursor.MoveOperation.End)

    def ok(self,   m): self._append("✓", m, C.GREEN)
    def err(self,  m): self._append("✗", m, C.RED)
    def warn(self, m): self._append("▲", m, C.AMBER)
    def info(self, m): self._append("→", m, C.G2)
    def sys(self,  m): self._append("·", m, C.T1)
    def svc(self,  m): self._append("·", m, C.TCO)


# ══════════════════════════════════════════════════════════════════════════════
# Factory helpers
# ══════════════════════════════════════════════════════════════════════════════
def hline(color: str = C.BDR1) -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.Shape.HLine)
    f.setFixedHeight(1)
    f.setStyleSheet(f"background: {color}; border: none;")
    return f

def make_label(text: str, size: int = 11, color: str | None = None,
               bold: bool = False, spacing: float | None = None) -> QLabel:
    lbl = QLabel(text)
    s   = (f"color: {color or C.T1}; font-size: {size}px;"
           f"font-family: {TERMINAL_FONT};")
    if bold:    s += " font-weight: 700;"
    if spacing: s += f" letter-spacing: {spacing}px;"
    lbl.setStyleSheet(s)
    return lbl

def make_chip(text: str, color: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(f"""
        background: {color}22;
        color: {color};
        border: 1px solid {color}55;
        border-radius: 4px;
        padding: 2px 8px;
        font-size: 9px;
        font-weight: 700;
        font-family: {TERMINAL_FONT};
        letter-spacing: 1.2px;
    """)
    return lbl

def make_badge(text: str, color: str) -> QLabel:
    """Round badge — for status display."""
    lbl = QLabel(text)
    lbl.setStyleSheet(f"""
        background: {color}22;
        color: {color};
        border: 1px solid {color}55;
        border-radius: 3px;
        padding: 1px 7px;
        font-size: 9px;
        font-weight: 800;
        font-family: {TERMINAL_FONT};
        letter-spacing: 0.8px;
    """)
    return lbl