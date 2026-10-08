import logging
import sys

_quiet_mode = False


def set_quiet(quiet: bool) -> None:
    global _quiet_mode
    _quiet_mode = quiet
    logger = logging.getLogger("tool")
    if quiet:
        logger.setLevel(logging.CRITICAL)
        for h in logger.handlers:
            h.setLevel(logging.CRITICAL)


def get_logger(name: str = "tool") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger