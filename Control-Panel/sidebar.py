"""
Control-Panel/sidebar.py
"""
from __future__ import annotations

from PyQt6.QtCore    import Qt, pyqtSignal
from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QLabel,
                              QSizePolicy, QVBoxLayout, QWidget)

from config    import C, TERMINAL_FONT
from primitives import StatusLight


# ══════════════════════════════════════════════════════════════════════════════
class SidebarBtn(QWidget):
    clicked = pyqtSignal(int)

    def __init__(self, icon: str, tip: str, idx: int, col: str, parent=None):
        super().__init__(parent)
        self._idx = idx
        self._col = col
        self._sel = False
        self._hov = False

        self.setFixedWidth(C.SB_W)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(tip)

        vl = QVBoxLayout(self)
        vl.setContentsMargins(0, 8, 0, 8)
        vl.setSpacing(5)
        vl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._icon_lbl = QLabel(icon)
        self._icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._icon_lbl.setFixedSize(36, 28)

        lw = QWidget(); lw.setFixedSize(C.SB_W, 8)
        from PyQt6.QtWidgets import QHBoxLayout as HBL
        ll = HBL(lw); ll.setContentsMargins(0, 0, 0, 0)
        ll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._light = StatusLight(6)
        ll.addWidget(self._light)

        vl.addStretch()
        vl.addWidget(self._icon_lbl, 0, Qt.AlignmentFlag.AlignCenter)
        vl.addWidget(lw, 0, Qt.AlignmentFlag.AlignCenter)
        vl.addStretch()
        self._refresh()

    def _refresh(self) -> None:
        if self._sel:
            self.setStyleSheet(f"""
                SidebarBtn {{
                    background: {C.SB_SEL};
                    border-right: 2px solid {self._col};
                    border-left: 2px solid transparent;
                }}
            """)
            self._icon_lbl.setStyleSheet(
                f"color: {self._col}; font-size: 18px; background: transparent;"
                f"font-family: {TERMINAL_FONT};"
            )
        elif self._hov:
            self.setStyleSheet(f"""
                SidebarBtn {{
                    background: {C.SB_SEL}88;
                    border-right: 2px solid {self._col}44;
                    border-left: 2px solid transparent;
                }}
            """)
            self._icon_lbl.setStyleSheet(
                f"color: {C.T1}; font-size: 18px; background: transparent;"
                f"font-family: {TERMINAL_FONT};"
            )
        else:
            self.setStyleSheet("""
                SidebarBtn {
                    background: transparent;
                    border-right: 2px solid transparent;
                    border-left: 2px solid transparent;
                }
            """)
            self._icon_lbl.setStyleSheet(
                f"color: {C.T2}; font-size: 18px; background: transparent;"
                f"font-family: {TERMINAL_FONT};"
            )

    def setSelected(self, v: bool) -> None:
        self._sel = v; self._refresh()

    def light(self) -> StatusLight:
        return self._light

    def enterEvent(self, e): self._hov = True;  self._refresh(); super().enterEvent(e)
    def leaveEvent(self, e): self._hov = False; self._refresh(); super().leaveEvent(e)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._idx)
        super().mousePressEvent(e)


# ══════════════════════════════════════════════════════════════════════════════
class SidebarActionBtn(QWidget):
    clicked = pyqtSignal()

    def __init__(self, icon: str, color: str, tip: str, parent=None):
        super().__init__(parent)
        self.setFixedSize(C.SB_W, 44)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(tip)
        self._col = color
        self._hov = False

        from PyQt6.QtWidgets import QVBoxLayout as VBL
        vl = VBL(self)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl = QLabel(icon)
        self._lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl.setStyleSheet(
            f"color: {color}; font-size: 15px; background: transparent;"
            f"font-family: {TERMINAL_FONT};"
        )
        vl.addWidget(self._lbl)
        self._refresh()

    def _refresh(self) -> None:
        if self._hov:
            self.setStyleSheet(f"background: {self._col}22; border-radius: 0px;")
        else:
            self.setStyleSheet("background: transparent;")

    def enterEvent(self, e): self._hov = True;  self._refresh(); super().enterEvent(e)
    def leaveEvent(self, e): self._hov = False; self._refresh(); super().leaveEvent(e)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(e)

    def setEnabled(self, v: bool) -> None:
        super().setEnabled(v)
        alpha = "ff" if v else "33"
        self._lbl.setStyleSheet(
            f"color: {self._col}{alpha}; font-size: 15px; background: transparent;"
            f"font-family: {TERMINAL_FONT};"
        )


# ══════════════════════════════════════════════════════════════════════════════
class Sidebar(QWidget):
    service_selected = pyqtSignal(int)

    def __init__(self, entries: list[tuple[str, str, str]], parent=None):
        super().__init__(parent)
        self.setFixedWidth(C.SB_W)
        self.setStyleSheet(f"""
            background: {C.SB_BG};
            border-right: 1px solid {C.BDR1};
        """)

        vl = QVBoxLayout(self)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        # Logo / brand area
        logo = QLabel("⬡")
        logo.setFixedHeight(48)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet(f"""
            color: {C.G3};
            font-size: 20px;
            background: {C.SB_BG};
            border-bottom: 1px solid {C.BDR1};
        """)
        vl.addWidget(logo)

        self._btns: list[SidebarBtn] = []
        for i, (icon, tip, col) in enumerate(entries):
            b = SidebarBtn(icon, tip, i, col)
            b.clicked.connect(self._on_click)
            self._btns.append(b)
            vl.addWidget(b, stretch=1)

        vl.addStretch()

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background: {C.BDR1}; border: none;")
        vl.addWidget(sep)

        # Action buttons
        self.btn_start_all = SidebarActionBtn("▶", C.GREEN, "Start All")
        self.btn_stop_all  = SidebarActionBtn("■", C.RED,   "Stop All")
        vl.addWidget(self.btn_start_all)
        vl.addWidget(self.btn_stop_all)
        vl.addSpacing(8)

        if self._btns:
            self._btns[0].setSelected(True)

    def _on_click(self, idx: int) -> None:
        for b in self._btns: b.setSelected(False)
        self._btns[idx].setSelected(True)
        self.service_selected.emit(idx)

    def light(self, idx: int) -> StatusLight:
        return self._btns[idx].light()