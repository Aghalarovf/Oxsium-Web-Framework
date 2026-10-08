#!/usr/bin/env python3

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.cli import CLI


def main():
    cli = CLI()
    cli.run()


if __name__ == "__main__":
    main()