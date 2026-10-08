import sys
from datetime import datetime
from typing import Optional


class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"


class Logger:
    def __init__(self, verbose: bool = False):
        self._verbose = verbose

    def set_verbose(self, verbose: bool):
        self._verbose = verbose

    def _timestamp(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _write(self, level: str, color: str, message: str):
        ts = self._timestamp()
        line = (
            f"{Colors.GRAY}{ts}{Colors.RESET} "
            f"{color}{Colors.BOLD}{level}{Colors.RESET} "
            f"{message}"
        )
        print(line, file=sys.stdout, flush=True)

    def info(self, message: str):
        self._write("INFO ", Colors.CYAN, message)

    def success(self, message: str):
        self._write("OK   ", Colors.GREEN, message)

    def warning(self, message: str):
        self._write("WARN ", Colors.YELLOW, message)

    def error(self, message: str):
        self._write("ERR  ", Colors.RED, message)

    def debug(self, message: str):
        if self._verbose:
            self._write("DBG  ", Colors.GRAY, message)

    def dork(self, dork: str, description: Optional[str] = None):
        label = f"{Colors.MAGENTA}DORK {Colors.RESET}"
        ts = self._timestamp()
        line = (
            f"{Colors.GRAY}{ts}{Colors.RESET} "
            f"{label} {Colors.CYAN}{dork}{Colors.RESET}"
        )
        if description:
            line += f"\n       {Colors.GRAY}{description}{Colors.RESET}"
        print(line, flush=True)

    def result(self, url: str, dork: str):
        ts = self._timestamp()
        line = (
            f"{Colors.GRAY}{ts}{Colors.RESET} "
            f"{Colors.GREEN}{Colors.BOLD}HIT  {Colors.RESET}"
            f"{Colors.WHITE}{url}{Colors.RESET}\n"
            f"       {Colors.GRAY}via: {dork}{Colors.RESET}"
        )
        print(line, flush=True)