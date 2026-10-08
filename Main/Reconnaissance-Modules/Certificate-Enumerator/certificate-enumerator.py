#!/usr/bin/env python3
import sys
import os
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.cli      import parse_args
from core.logger   import get_logger
from core.scanner  import Scanner


def main() -> int:
    args = parse_args()

    output_path = getattr(args, "output",  None)
    as_json     = getattr(args, "json", False) or (
        isinstance(output_path, str) and output_path.lower().endswith(".json")
    )

    log_stream = sys.stderr if (as_json and not output_path) else sys.stdout

    logger = get_logger(
        verbose=getattr(args, "verbose",   False),
        no_color=getattr(args, "no_color", False),
        stream=log_stream,
    )

    _real_stdout = sys.stdout
    if as_json and not output_path:
        sys.stdout = sys.stderr

    try:
        scanner  = Scanner(args, logger)
        exporter = scanner.run()
    finally:
        sys.stdout = _real_stdout

    if output_path:
        try:
            exporter.save(output_path, as_json=as_json)
            logger.info(f"Results saved to: {output_path}")
        except OSError as exc:
            logger.error(f"Could not write output file: {exc}")
            return 1

    if as_json and not output_path:
        _real_stdout.write(exporter.to_json() + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())