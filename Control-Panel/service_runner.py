"""
core/service_runner.py
──────────────────────
ServiceRunner — single QThread; spawns a process and reads stdout.

When stop() is called:
  1. The process is terminated/killed.
  2. stdout is closed.
  3. The for-loop inside run() exits on its own → thread finishes.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal


class ServiceRunner(QThread):
    started        = pyqtSignal(int)   # pid
    failed         = pyqtSignal(str)   # error message
    log_line       = pyqtSignal(str)   # stdout line
    finished_clean = pyqtSignal()      # process exited on its own

    def __init__(self, cmd: list, cwd: Path, env: dict, parent=None):
        super().__init__(parent)
        self._cmd  = cmd
        self._cwd  = cwd
        self._env  = env
        self._proc: subprocess.Popen | None = None

    # ── public ────────────────────────────────────────────────────────────────

    def stop(self) -> None:
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.poll() is None:
                if os.name == "nt":
                    proc.kill()
                else:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
        except Exception:
            pass
        try:
            if proc.stdout and not proc.stdout.closed:
                proc.stdout.close()
        except Exception:
            pass

    # ── QThread.run ───────────────────────────────────────────────────────────

    def run(self) -> None:
        flags = ({"creationflags": subprocess.CREATE_NO_WINDOW}
                 if os.name == "nt"
                 else {"start_new_session": True})

        try:
            self._proc = subprocess.Popen(
                self._cmd,
                cwd=str(self._cwd),
                env=self._env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                **flags,
            )
        except Exception as exc:
            self.failed.emit(str(exc))
            return

        self.started.emit(self._proc.pid)

        try:
            for raw in self._proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip()
                if not line:
                    continue
                self.log_line.emit(line)
        except Exception:
            pass

        if self._proc and self._proc.poll() is not None:
            self.finished_clean.emit()