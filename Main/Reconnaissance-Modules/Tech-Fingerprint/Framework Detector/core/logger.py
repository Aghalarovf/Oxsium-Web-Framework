import logging
import sys

LOGGER_NAME = "orkestr"


def build_logger(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler(stream=sys.stderr)
        formatter = logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    else:
        logger.handlers[0].setLevel(logging.DEBUG if verbose else logging.INFO)

    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)
