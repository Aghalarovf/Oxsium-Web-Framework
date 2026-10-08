"""
start.py  —  Oxsium Service Manager
"""
from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore    import Qt, QTimer, pyqtSignal
from PyQt6.QtGui     import QColor, QPainter, QLinearGradient
from PyQt6.QtWidgets import (
    QApplication, QHBoxLayout, QLabel, QMainWindow,
    QSplitter, QStackedWidget, QVBoxLayout, QWidget, QFrame,
)

PANEL_DIR = Path(__file__).resolve().parent / "Control-Panel"
if str(PANEL_DIR) not in sys.path:
    sys.path.insert(0, str(PANEL_DIR))

from config         import C, DEFAULT_PORTS, FILES, QSS, SERVICE_DEFS, SIDEBAR_ENTRIES
from env_utils      import build_env
from service_runner import ServiceRunner
from web_controller import WebController
from primitives     import Btn, Field, Log, StatusLight, hline, make_chip, make_label, make_badge
from sidebar        import Sidebar


# ══════════════════════════════════════════════════════════════════════════════
# GradientHeader — top title bar (with gold gradient line)
# ══════════════════════════════════════════════════════════════════════════════
class GradientHeader(QWidget):
    def __init__(self, ctrl, parent=None):
        super().__init__(parent)
        self._ctrl = ctrl
        self.setFixedHeight(58)

        hl = QHBoxLayout(self)
        hl.setContentsMargins(20, 0, 20, 0)
        hl.setSpacing(12)

        self._light = StatusLight(10)
        hl.addWidget(self._light)

        # Service name
        name = QLabel(ctrl.name)
        name.setStyleSheet(f"""
            color: {C.T0};
            font-size: 15px;
            font-weight: 700;
            letter-spacing: 0.5px;
        """)
        hl.addWidget(name)

        # Tag chip
        tag = make_chip(ctrl.tag, ctrl.tag_col)
        hl.addWidget(tag)

        # Hint
        hint = QLabel(ctrl.hint)
        hint.setStyleSheet(f"color: {C.T2}; font-size: 10px; letter-spacing: 0.3px;")
        hl.addWidget(hint)

        hl.addStretch()

        # Status badge (right side)
        self._status_lbl = QLabel("OFFLINE")
        self._status_lbl.setStyleSheet(f"""
            color: {C.T3};
            font-size: 9px;
            font-weight: 800;
            letter-spacing: 1.5px;
        """)
        hl.addWidget(self._status_lbl)

    def paintEvent(self, e):
        super().paintEvent(e)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        # background
        p.fillRect(self.rect(), QColor(C.SURF1))

        # bottom gold line — gradient
        g = QLinearGradient(0, self.height() - 1, self.width(), self.height() - 1)
        g.setColorAt(0.0, QColor(C.G_DIM))
        g.setColorAt(0.3, QColor(C.G2))
        g.setColorAt(0.7, QColor(C.G3))
        g.setColorAt(1.0, QColor(C.G_DIM))
        p.fillRect(0, self.height() - 1, self.width(), 1, g)

    def set_status(self, s: int) -> None:
        labels = {0: ("OFFLINE", C.T3), 1: ("ONLINE", C.GREEN),
                  2: ("ERROR",   C.RED), 3: ("STARTING", C.AMBER)}
        txt, col = labels.get(s, ("OFFLINE", C.T3))
        self._status_lbl.setText(txt)
        self._status_lbl.setStyleSheet(f"""
            color: {col};
            font-size: 9px;
            font-weight: 800;
            letter-spacing: 1.5px;
        """)
        self._light.setState(s)


# ══════════════════════════════════════════════════════════════════════════════
# ControlBar — host/port + buttons
# ══════════════════════════════════════════════════════════════════════════════
class ControlBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(52)
        self.setStyleSheet(f"background: {C.SURF0};")

        hl = QHBoxLayout(self)
        hl.setContentsMargins(20, 0, 20, 0)
        hl.setSpacing(10)

        # Host
        host_lbl = QLabel("HOST")
        host_lbl.setStyleSheet(f"""
            color: {C.T2}; font-size: 9px;
            font-weight: 700; letter-spacing: 1px;
        """)
        self.host = Field("127.0.0.1", w=120)

        # Port
        port_lbl = QLabel("PORT")
        port_lbl.setStyleSheet(f"""
            color: {C.T2}; font-size: 9px;
            font-weight: 700; letter-spacing: 1px;
        """)
        self.port_field = Field("", w=80)

        hl.addWidget(host_lbl)
        hl.addWidget(self.host)
        hl.addSpacing(8)
        hl.addWidget(port_lbl)
        hl.addWidget(self.port_field)
        hl.addSpacing(16)

        self.btn_start = Btn("▶  START", "gold2",  h=30)
        self.btn_stop  = Btn("■  STOP",  "danger", h=30)
        hl.addWidget(self.btn_start)
        hl.addWidget(self.btn_stop)
        hl.addStretch()

        # File path
        self.path_lbl = QLabel("")
        self.path_lbl.setStyleSheet(f"""
            color: {C.TPATH}; font-size: 9px;
            font-family: 'Cascadia Code','Consolas',monospace;
        """)
        hl.addWidget(self.path_lbl)

    def paintEvent(self, e):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(C.SURF0))
        p.fillRect(0, self.height() - 1, self.width(), 1, QColor(C.BDR0))


# ══════════════════════════════════════════════════════════════════════════════
# ServiceController
# ══════════════════════════════════════════════════════════════════════════════
class ServiceController:
    def __init__(self, key, name, hint, fpath: Path, port_def, tag, tag_col):
        self.key = key; self.name = name; self.hint = hint
        self.fpath = fpath; self.port_def = port_def
        self.tag = tag; self.tag_col = tag_col
        self._runner: ServiceRunner | None = None
        self._up = False
        self.on_state = None; self.on_log = None

    @property
    def running(self): return self._up

    def start(self, host, port, glog):
        if self._up: return
        if not self.fpath.exists():
            self._e_log("✗", f"File not found: {self.fpath}", C.RED)
            glog.err(f"[{self.key.upper()}] File not found.")
            self._e_state(2); return

        from config import PYTHON
        env = build_env({"PORT": str(port), "HOST": host})
        self._runner = ServiceRunner(
            [str(PYTHON), str(self.fpath), "--host", host, "--port", str(port)],
            self.fpath.parent, env)
        self._runner.started.connect(self._on_started)
        self._runner.failed.connect(self._on_failed)
        self._runner.log_line.connect(self._on_line)
        self._runner.finished_clean.connect(self._on_finished)
        self._e_state(3); self._runner.start()

    def stop(self, glog):
        if self._runner: self._runner.stop(); self._runner = None
        self._up = False; self._e_state(0)
        self._e_log("▲", "Stopped.", C.AMBER)
        glog.warn(f"[{self.key.upper()}] Stopped.")

    def kill_nowait(self):
        if self._runner: self._runner.stop(); self._runner = None
        self._up = False

    def _on_started(self, pid):
        self._up = True; self._e_state(1)
        self._e_log("✓", f"Started  ·  PID {pid}  ·  :{self.port_def}", C.GREEN)
    def _on_failed(self, msg):
        self._up = False; self._e_state(2)
        self._e_log("✗", f"Error: {msg}", C.RED)
    def _on_line(self, line): self._e_log("·", line, C.TCO)
    def _on_finished(self):
        self._up = False; self._e_state(0)
        self._e_log("▲", "Process exited.", C.AMBER)
    def _e_state(self, s):
        if self.on_state: self.on_state(s)
    def _e_log(self, icon, msg, col):
        if self.on_log: self.on_log(icon, msg, col)


# ══════════════════════════════════════════════════════════════════════════════
# ServicePanel
# ══════════════════════════════════════════════════════════════════════════════
class ServicePanel(QWidget):
    request_start = pyqtSignal(str, int)
    request_stop  = pyqtSignal()

    def __init__(self, ctrl, parent=None):
        super().__init__(parent)
        self._ctrl = ctrl
        self._build()
        self._apply_stopped()

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        self._hdr = GradientHeader(self._ctrl)
        root.addWidget(self._hdr)

        self._cbar = ControlBar()
        self._cbar.port_field.setText(str(self._ctrl.port_def))
        self._cbar.path_lbl.setText(str(self._ctrl.fpath))
        self._cbar.path_lbl.setToolTip(str(self._ctrl.fpath))
        self._cbar.btn_start.clicked.connect(self._on_start)
        self._cbar.btn_stop.clicked.connect(self.request_stop)
        root.addWidget(self._cbar)
        root.addWidget(hline(C.BDR0))

        self._log = Log()
        root.addWidget(self._log, stretch=1)

    def _apply_stopped(self):
        self._cbar.btn_start.setEnabled(True)
        self._cbar.btn_stop.setEnabled(False)
    def _apply_running(self):
        self._cbar.btn_start.setEnabled(False)
        self._cbar.btn_stop.setEnabled(True)
    def _apply_pending(self):
        self._cbar.btn_start.setEnabled(False)
        self._cbar.btn_stop.setEnabled(False)
    def _apply_error(self):
        self._cbar.btn_start.setEnabled(True)
        self._cbar.btn_stop.setEnabled(False)

    def apply_state(self, s):
        {0: self._apply_stopped, 1: self._apply_running,
         2: self._apply_error,   3: self._apply_pending}.get(s, self._apply_stopped)()
        self._hdr.set_status(s)

    def append_log(self, icon, msg, col):
        self._log._append(icon, msg, col)

    def _on_start(self):
        try: port = int(self._cbar.port_field.text())
        except ValueError: self._log.err("Invalid port!"); return
        self.request_start.emit(self._cbar.host.text().strip(), port)


# ══════════════════════════════════════════════════════════════════════════════
# WebPanel
# ══════════════════════════════════════════════════════════════════════════════
class WebPanel(QWidget):
    request_start = pyqtSignal(str, int)
    request_stop  = pyqtSignal()

    def __init__(self, ctrl: WebController, parent=None):
        super().__init__(parent)
        self._ctrl = ctrl
        self._build()
        self._apply_stopped()

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        self._hdr = GradientHeader(self._ctrl)
        root.addWidget(self._hdr)

        # Control bar (simplified for web)
        cbar = QWidget(); cbar.setFixedHeight(52)
        cbar.setStyleSheet(f"background: {C.SURF0};")
        cl = QHBoxLayout(cbar); cl.setContentsMargins(20,0,20,0); cl.setSpacing(10)

        port_lbl = QLabel("PORT")
        port_lbl.setStyleSheet(f"color:{C.T2};font-size:9px;font-weight:700;letter-spacing:1px;")
        self._port = Field(str(self._ctrl.port_def), w=80)

        self._btn_start = Btn("▶  START",   "gold2",  h=30)
        self._btn_stop  = Btn("■  STOP",    "danger", h=30)
        self._btn_open  = Btn("↗  BROWSER", "ghost",  h=30)

        self._btn_start.clicked.connect(self._on_start)
        self._btn_stop.clicked.connect(self.request_stop)
        self._btn_open.clicked.connect(self._ctrl.open_file)

        cl.addWidget(port_lbl); cl.addWidget(self._port)
        cl.addSpacing(16)
        cl.addWidget(self._btn_start); cl.addWidget(self._btn_stop)
        cl.addWidget(self._btn_open); cl.addStretch()

        path_lbl = QLabel(str(self._ctrl.fpath))
        path_lbl.setStyleSheet(f"color:{C.TPATH};font-size:9px;font-family:'Cascadia Code','Consolas',monospace;")
        path_lbl.setToolTip(str(self._ctrl.fpath))
        cl.addWidget(path_lbl)

        root.addWidget(cbar)
        root.addWidget(hline(C.BDR0))

        self._log = Log()
        root.addWidget(self._log, stretch=1)

    def _apply_stopped(self):
        self._btn_start.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._btn_open.setEnabled(False)
    def _apply_running(self):
        self._btn_start.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._btn_open.setEnabled(True)
    def _apply_error(self):
        self._btn_start.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._btn_open.setEnabled(False)

    def apply_state(self, s):
        {0: self._apply_stopped, 1: self._apply_running,
         2: self._apply_error}.get(s, self._apply_stopped)()
        self._hdr.set_status(s)

    def append_log(self, icon, msg, col): self._log._append(icon, msg, col)

    def _on_start(self):
        try: port = int(self._port.text())
        except ValueError: self._log.err("Invalid port!"); return
        self.request_start.emit("127.0.0.1", port)


# ══════════════════════════════════════════════════════════════════════════════
# ServiceManager
# ══════════════════════════════════════════════════════════════════════════════
class ServiceManager:
    def __init__(self, glog):
        self._glog = glog
        self.controllers = []; self.panels = []

    def register_service(self, ctrl, panel):
        ctrl.on_state = panel.apply_state; ctrl.on_log = panel.append_log
        panel.request_start.connect(lambda h, p, c=ctrl: c.start(h, p, self._glog))
        panel.request_stop.connect(lambda c=ctrl: c.stop(self._glog))
        self.controllers.append(ctrl); self.panels.append(panel)

    def register_web(self, ctrl, panel):
        ctrl.on_state = panel.apply_state; ctrl.on_log = panel.append_log
        panel.request_start.connect(lambda h, p, c=ctrl: c.start(h, p, self._glog))
        panel.request_stop.connect(lambda c=ctrl: c.stop(self._glog))
        self.controllers.append(ctrl); self.panels.append(panel)

    def start_all(self):
        for c, panel in zip(self.controllers, self.panels):
            if c.running: continue
            if isinstance(panel, ServicePanel):
                try: port = int(panel._cbar.port_field.text())
                except: port = c.port_def
                c.start(panel._cbar.host.text().strip(), port, self._glog)
            elif isinstance(panel, WebPanel):
                try: port = int(panel._port.text())
                except: port = c.port_def
                c.start("127.0.0.1", port, self._glog)

    def stop_all(self):
        for c in self.controllers:
            if c.running: c.stop(self._glog)

    def kill_all_nowait(self):
        for c in self.controllers: c.kill_nowait()


# ══════════════════════════════════════════════════════════════════════════════
# GlobalLogBar — bottom log panel header
# ══════════════════════════════════════════════════════════════════════════════
class GlobalLogBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(28)
        hl = QHBoxLayout(self)
        hl.setContentsMargins(18, 0, 18, 0)

        lbl = QLabel("GLOBAL LOG")
        lbl.setStyleSheet(f"""
            color: {C.T2}; font-size: 9px;
            font-weight: 700; letter-spacing: 1.8px;
        """)
        hl.addWidget(lbl)
        hl.addStretch()

        dot = QLabel("●")
        dot.setStyleSheet(f"color: {C.G2}; font-size: 8px;")
        hl.addWidget(dot)

    def paintEvent(self, e):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(C.SURF1))
        p.fillRect(0, 0, self.width(), 1, QColor(C.BDR1))


# ══════════════════════════════════════════════════════════════════════════════
# MainWindow
# ══════════════════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Oxsium  ·  Service Manager")
        self.resize(1120, 700)
        self.setMinimumSize(860, 520)

        central = QWidget()
        self.setCentralWidget(central)
        ml = QHBoxLayout(central)
        ml.setContentsMargins(0, 0, 0, 0)
        ml.setSpacing(0)

        # Sidebar
        self._sidebar = Sidebar(SIDEBAR_ENTRIES)
        ml.addWidget(self._sidebar)

        # Right side
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(3)

        self._stack = QStackedWidget()
        splitter.addWidget(self._stack)

        # Global log section
        glog_wrap = QWidget()
        gv = QVBoxLayout(glog_wrap)
        gv.setContentsMargins(0, 0, 0, 0)
        gv.setSpacing(0)

        self._glog = Log()
        gv.addWidget(GlobalLogBar())
        gv.addWidget(self._glog)
        splitter.addWidget(glog_wrap)
        splitter.setSizes([490, 180])

        rl.addWidget(splitter, stretch=1)
        ml.addWidget(right, stretch=1)

        # Build controllers and panels
        self._mgr = ServiceManager(self._glog)

        for key, name, hint, fk, pk, tag, tag_col in SERVICE_DEFS:
            ctrl  = ServiceController(key, name, hint, FILES[fk],
                                      DEFAULT_PORTS[pk], tag, tag_col)
            panel = ServicePanel(ctrl)
            self._mgr.register_service(ctrl, panel)
            self._stack.addWidget(panel)

        # Web Viewer — always last (sidebar index = len(SERVICE_DEFS))
        web_ctrl  = WebController(DEFAULT_PORTS["http"])
        web_panel = WebPanel(web_ctrl)
        self._mgr.register_web(web_ctrl, web_panel)
        self._stack.addWidget(web_panel)

        # Sidebar connections
        self._sidebar.service_selected.connect(self._stack.setCurrentIndex)
        self._sidebar.btn_start_all.clicked.connect(self._mgr.start_all)
        self._sidebar.btn_stop_all.clicked.connect(self._mgr.stop_all)

        # Sidebar LED — bind to panel state
        for i, panel in enumerate(self._mgr.panels):
            def make_apply(orig, idx):
                def apply(s):
                    orig(s)
                    self._sidebar.light(idx).setState(s)
                return apply
            panel.apply_state = make_apply(panel.apply_state, i)

        self._glog.sys("Oxsium Service Manager started.")

    def closeEvent(self, e):
        self._mgr.kill_all_nowait(); e.accept()


# ══════════════════════════════════════════════════════════════════════════════
def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(QSS)
    app.setApplicationName("Oxsium Service Manager")
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()