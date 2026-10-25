import logging
import sys
import threading

LEVEL_SUCCESS = 25
logging.addLevelName(LEVEL_SUCCESS, "SUCCESS")

COLOR_RESET = "\033[0m"
COLOR_MAP = {
    "DEBUG": "\033[90m",
    "INFO": "\033[94m",
    "SUCCESS": "\033[92m",
    "WARNING": "\033[93m",
    "ERROR": "\033[91m",
    "CRITICAL": "\033[97;41m",
}


class OxFormatter(logging.Formatter):
    def __init__(self, use_color=True):
        super().__init__()
        self.use_color = use_color

    def format(self, record):
        level = record.levelname
        target = getattr(record, "target", None)
        module = getattr(record, "module_name", None)
        prefix = f"[{level}]"
        if target:
            prefix += f"[{target}]"
        if module:
            prefix += f"[{module}]"
        message = record.getMessage()
        line = f"{prefix} {message}"
        if self.use_color:
            color = COLOR_MAP.get(level, "")
            line = f"{color}{line}{COLOR_RESET}"
        return line


class OxLogger:
    _instance = None
    _lock = threading.Lock()

    def __init__(self, name="OxSMB", level=logging.INFO, use_color=True):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(level)
        self._logger.propagate = False
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(OxFormatter(use_color=use_color))
            self._logger.addHandler(handler)
        self._print_lock = threading.Lock()
        self._overlay_active = False
        self._overlay_width = 0

    @classmethod
    def get(cls, level=logging.INFO, use_color=True):
        with cls._lock:
            if cls._instance is None:
                cls._instance = OxLogger(level=level, use_color=use_color)
            return cls._instance

    def begin_overlay(self):
        with self._print_lock:
            self._overlay_active = True
            self._overlay_width = 0

    def end_overlay(self):
        with self._print_lock:
            if self._overlay_active and self._overlay_width:
                sys.stderr.write("\r" + " " * self._overlay_width + "\r")
                sys.stderr.flush()
            self._overlay_active = False
            self._overlay_width = 0

    def update_overlay(self, text):
        with self._print_lock:
            if not self._overlay_active:
                return
            padded = text
            if len(padded) < self._overlay_width:
                padded = padded + " " * (self._overlay_width - len(padded))
            sys.stderr.write("\r" + padded)
            sys.stderr.flush()
            self._overlay_width = max(self._overlay_width, len(text))

    def _log(self, level, message, target=None, module_name=None):
        with self._print_lock:
            if self._overlay_active and self._overlay_width:
                sys.stderr.write("\r" + " " * self._overlay_width + "\r")
            self._logger.log(
                level,
                message,
                extra={"target": target, "module_name": module_name},
            )
            sys.stderr.flush()

    def debug(self, message, target=None, module_name=None):
        self._log(logging.DEBUG, message, target, module_name)

    def info(self, message, target=None, module_name=None):
        self._log(logging.INFO, message, target, module_name)

    def success(self, message, target=None, module_name=None):
        self._log(LEVEL_SUCCESS, message, target, module_name)

    def warning(self, message, target=None, module_name=None):
        self._log(logging.WARNING, message, target, module_name)

    def error(self, message, target=None, module_name=None):
        self._log(logging.ERROR, message, target, module_name)

    def critical(self, message, target=None, module_name=None):
        self._log(logging.CRITICAL, message, target, module_name)

    def set_level(self, level):
        self._logger.setLevel(level)
