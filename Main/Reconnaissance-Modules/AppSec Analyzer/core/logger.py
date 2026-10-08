"""
core/logger.py - Centralised logging configuration.

All modules obtain their logger through get_logger() so that formatting,
level, and output destination are consistent across the whole tool.
"""

import logging
import sys

# ANSI escape codes – used only when stdout is a real terminal (not a pipe/file)
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_GREY   = "\033[90m"


class _ColourFormatter(logging.Formatter):
    """
    Formatter that prepends a coloured severity badge to every log line.
    Falls back to plain text when output is not a TTY.
    """

    _LEVEL_COLOURS = {
        logging.DEBUG:    (_GREY,   "DBG"),
        logging.INFO:     (_CYAN,   "INF"),
        logging.WARNING:  (_YELLOW, "WRN"),
        logging.ERROR:    (_RED,    "ERR"),
        logging.CRITICAL: (_RED,    "CRT"),
    }

    def format(self, record: logging.LogRecord) -> str:
        colour, badge = self._LEVEL_COLOURS.get(record.levelno, (_RESET, "???"))
        message = super().format(record)

        if sys.stdout.isatty():
            # Coloured output for interactive terminals
            return f"{colour}{_BOLD}[{badge}]{_RESET} {message}"
        else:
            # Plain output for log redirection
            return f"[{badge}] {message}"


def get_logger(name: str, level: int = logging.DEBUG) -> logging.Logger:
    """
    Return a named logger that writes coloured, timestamped lines to stdout.

    Parameters
    ----------
    name  : Logical name shown in each log record (e.g. "engine", "waf").
    level : Minimum severity to capture; defaults to DEBUG so every message
            produced inside the tool is visible during analysis.

    Returns
    -------
    logging.Logger
        A configured logger instance.  Calling this function more than once
        with the same *name* returns the same object (standard Python behaviour).
    """
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers if the module is imported more than once
    if logger.handlers:
        return logger

    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    formatter = _ColourFormatter(
        fmt="%(asctime)s  %(name)-12s  %(message)s",
        datefmt="%H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Prevent the root logger from printing duplicate lines
    logger.propagate = False

    return logger