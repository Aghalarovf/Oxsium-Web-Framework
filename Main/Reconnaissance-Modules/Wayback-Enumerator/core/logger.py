import sys
import time
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = "{}{}WebArchive Scanner{} {}v1.0{} — Passive Archive-Based Reconnaissance\n{}  Wayback · CommonCrawl · OTX · URLScan{}\n"

C_INFO    = Fore.CYAN
C_SUCCESS = Fore.GREEN
C_WARNING = Fore.YELLOW
C_ERROR   = Fore.RED
C_DEBUG   = Fore.MAGENTA
C_BOLD    = Style.BRIGHT
C_DIM     = Style.DIM
C_RESET   = Style.RESET_ALL


class Logger:

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._start_time: float | None = None

    def _ts(self) -> str:
        return f"{C_DIM}{datetime.now().strftime('%H:%M:%S')}{C_RESET}"

    def _fmt(self, level_color: str, symbol: str, level: str, msg: str) -> str:
        return f"{self._ts()} {level_color}{C_BOLD}[{symbol}]{C_RESET} {msg}"

    def banner(self):
        print(BANNER.format(
            Fore.CYAN, Style.BRIGHT, C_RESET,
            C_DIM, C_RESET,
            C_DIM, C_RESET,
        ))

    def info(self, msg: str):
        print(self._fmt(C_INFO, "*", "INFO", msg))

    def success(self, msg: str):
        print(self._fmt(C_SUCCESS, "+", "OK", msg))

    def warning(self, msg: str):
        print(self._fmt(C_WARNING, "!", "WARN", msg))

    def error(self, msg: str):
        print(self._fmt(C_ERROR, "✗", "ERR", msg), file=sys.stderr)

    def debug(self, msg: str):
        if self.verbose:
            print(self._fmt(C_DEBUG, "~", "DBG", msg))

    def section(self, title: str):
        print(f"\n{C_BOLD}{Fore.CYAN}── {title} {C_RESET}")

    def result(self, key: str, value, color: str = Fore.WHITE):
        print(f"  {C_DIM}{key:<30}{C_RESET} {color}{value}{C_RESET}")

    def table_row(self, cells: list, widths: list[int]):
        row = "  "
        for cell, w in zip(cells, widths):
            row += f"{str(cell):<{w}}"
        print(row)

    def start_timer(self):
        self._start_time = time.time()

    def elapsed(self) -> str:
        if self._start_time is None:
            return "0.00s"
        return f"{time.time() - self._start_time:.2f}s"

    def summary(self, stats: dict):
        self.section("SUMMARY")
        for key, val in stats.items():
            color = C_SUCCESS if isinstance(val, int) and val > 0 else Fore.WHITE
            self.result(key, val, color)
        print(f"\n  {C_DIM}Total time: {self.elapsed()}{C_RESET}\n")

    def dump_results(self, results: dict):
        if not results:
            return
        self.section("RESULTS")
        for name, data in results.items():
            print(f"{C_BOLD}{Fore.CYAN}[{name.upper()}]{C_RESET}")
            self._dump_value(data, indent=2)
            print()

    def _dump_value(self, value, indent: int):
        pad = " " * indent
        if isinstance(value, list):
            if not value:
                print(f"{pad}{C_DIM}(empty){C_RESET}")
                return
            for item in value:
                if isinstance(item, (dict, list)):
                    self._dump_value(item, indent)
                else:
                    print(f"{pad}{item}")
        elif isinstance(value, dict):
            for key, sub in value.items():
                if isinstance(sub, (dict, list)) and sub:
                    print(f"{pad}{C_DIM}{key}:{C_RESET}")
                    self._dump_value(sub, indent + 2)
                else:
                    print(f"{pad}{C_DIM}{key}:{C_RESET} {sub}")
        else:
            print(f"{pad}{value}")

    def progress(self, current: int, total: int, label: str = ""):
        if total == 0:
            return
        pct = int((current / total) * 100)
        filled = int(pct / 5)
        bar = f"{'█' * filled}{'░' * (20 - filled)}"
        line = (
            f"\r  {C_INFO}{bar}{C_RESET} "
            f"{C_BOLD}{pct:>3}%{C_RESET} "
            f"{C_DIM}({current}/{total}){C_RESET} "
            f"{label:<40}"
        )
        sys.stdout.write(line)
        sys.stdout.flush()
        if current >= total:
            sys.stdout.write("\n")
            sys.stdout.flush()