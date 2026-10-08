import logging
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from colorama import Fore, Style, init as colorama_init


class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    SUCCESS = "SUCCESS"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


_LEVEL_COLORS = {
    LogLevel.DEBUG:    (Fore.CYAN,    "[DBG]"),
    LogLevel.INFO:     (Fore.BLUE,    "[INF]"),
    LogLevel.SUCCESS:  (Fore.GREEN,   "[OK ]"),
    LogLevel.WARNING:  (Fore.YELLOW,  "[WRN]"),
    LogLevel.ERROR:    (Fore.RED,     "[ERR]"),
    LogLevel.CRITICAL: (Fore.MAGENTA, "[CRT]"),
}


class Logger:
    def __init__(
        self,
        verbose: bool = False,
        no_color: bool = False,
        log_file: Optional[str] = None,
    ):
        colorama_init(autoreset=True)
        self._verbose = verbose
        self._no_color = no_color
        self._file_logger: Optional[logging.Logger] = None

        if log_file:
            self._setup_file_logger(log_file)

    def _setup_file_logger(self, log_file: str):
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        self._file_logger = logging.getLogger("smosint.file")
        self._file_logger.setLevel(logging.DEBUG)
        handler = logging.FileHandler(log_file, encoding="utf-8")
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        )
        self._file_logger.addHandler(handler)
        self._file_logger.propagate = False

    def _format_console(self, level: LogLevel, message: str) -> str:
        timestamp = datetime.now().strftime("%H:%M:%S")
        color, prefix = _LEVEL_COLORS[level]

        if self._no_color:
            return f"{timestamp} {prefix} {message}"
        return f"{Fore.WHITE}{timestamp}{Style.RESET_ALL} {color}{prefix}{Style.RESET_ALL} {message}"

    def _write_file(self, level: LogLevel, message: str):
        if not self._file_logger:
            return
        mapping = {
            LogLevel.DEBUG:    self._file_logger.debug,
            LogLevel.INFO:     self._file_logger.info,
            LogLevel.SUCCESS:  self._file_logger.info,
            LogLevel.WARNING:  self._file_logger.warning,
            LogLevel.ERROR:    self._file_logger.error,
            LogLevel.CRITICAL: self._file_logger.critical,
        }
        mapping[level](message)

    def _log(self, level: LogLevel, message: str, stream=sys.stdout):
        if level == LogLevel.DEBUG and not self._verbose:
            return
        print(self._format_console(level, message), file=stream)
        self._write_file(level, message)

    def debug(self, message: str):
        self._log(LogLevel.DEBUG, message)

    def info(self, message: str):
        self._log(LogLevel.INFO, message)

    def success(self, message: str):
        self._log(LogLevel.SUCCESS, message)

    def warning(self, message: str):
        self._log(LogLevel.WARNING, message, stream=sys.stderr)

    def error(self, message: str):
        self._log(LogLevel.ERROR, message, stream=sys.stderr)

    def critical(self, message: str):
        self._log(LogLevel.CRITICAL, message, stream=sys.stderr)

    def section(self, title: str):
        width = 60
        bar = "─" * width
        if self._no_color:
            print(f"\n{bar}\n  {title}\n{bar}")
        else:
            print(f"\n{Fore.CYAN}{bar}{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}{Style.BRIGHT}{title}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{bar}{Style.RESET_ALL}")

    def finding(self, key: str, value: str):
        if self._no_color:
            print(f"    {key}: {value}")
        else:
            print(f"    {Fore.WHITE}{Style.BRIGHT}{key}:{Style.RESET_ALL} {Fore.GREEN}{value}{Style.RESET_ALL}")

    def table(self, headers: list[str], rows: list[list[str]]):
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))

        def _row_str(cells):
            return "  ".join(str(c).ljust(w) for c, w in zip(cells, col_widths))

        separator = "  ".join("-" * w for w in col_widths)

        if self._no_color:
            print(_row_str(headers))
            print(separator)
            for row in rows:
                print(_row_str(row))
        else:
            print(f"{Fore.CYAN}{_row_str(headers)}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{separator}{Style.RESET_ALL}")
            for row in rows:
                print(_row_str(row))