import sys
import os

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.cli import CLIParser
from core.engine import ScanEngine


def main():
    parser = CLIParser()
    config = parser.parse()

    engine = ScanEngine(config)
    result = engine.run()
    if result is None:
        sys.exit(1)


if __name__ == "__main__":
    main()
