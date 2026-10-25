import sys
import threading
import time

from core.logger import OxLogger

SPINNER_FRAMES = ["|", "/", "-", "\\"]


class ScanAnimator:
    def __init__(self, label: str = "Scanning in progress", interval: float = 0.12):
        self.label = label
        self.interval = interval
        self._logger = OxLogger.get()
        self._thread = None
        self._stop_event = threading.Event()
        self._start_time = None
        self._enabled = sys.stderr.isatty()
        self._progress_total = 0
        self._progress_done = 0
        self._progress_lock = threading.Lock()

    def set_total(self, total: int):
        with self._progress_lock:
            self._progress_total = total

    def tick(self):
        with self._progress_lock:
            self._progress_done += 1

    def start(self):
        if not self._enabled:
            return
        self._start_time = time.time()
        self._logger.begin_overlay()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _progress_text(self) -> str:
        with self._progress_lock:
            total = self._progress_total
            done = self._progress_done
        if total <= 0:
            return ""
        return f" | targets {done}/{total}"

    def _run(self):
        frame_index = 0
        while not self._stop_event.is_set():
            elapsed = time.time() - self._start_time
            frame = SPINNER_FRAMES[frame_index % len(SPINNER_FRAMES)]
            text = f"[{frame}] {self.label}... elapsed {elapsed:0.1f}s{self._progress_text()}"
            self._logger.update_overlay(text)
            frame_index += 1
            self._stop_event.wait(self.interval)

    def stop(self):
        if not self._enabled:
            return
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        self._logger.end_overlay()
