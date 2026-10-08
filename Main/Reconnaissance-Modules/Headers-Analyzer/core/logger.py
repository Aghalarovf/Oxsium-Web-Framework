import sys
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)


class Logger:
    LEVELS = {"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3, "CRITICAL": 4}

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._min_level = "DEBUG" if verbose else "INFO"

    def _should_print(self, level: str) -> bool:
        return self.LEVELS.get(level, 0) >= self.LEVELS.get(self._min_level, 1)

    def _timestamp(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _format(self, level: str, color: str, message: str) -> str:
        ts = self._timestamp()
        label = f"{color}[{level}]{Style.RESET_ALL}"
        return f"{Fore.LIGHTBLACK_EX}{ts}{Style.RESET_ALL} {label} {message}"

    def debug(self, message: str):
        if self._should_print("DEBUG"):
            print(self._format("DEBUG", Fore.CYAN, message))

    def info(self, message: str):
        if self._should_print("INFO"):
            print(self._format("INFO", Fore.GREEN, message))

    def warn(self, message: str):
        if self._should_print("WARN"):
            print(self._format("WARN", Fore.YELLOW, message))

    def error(self, message: str):
        if self._should_print("ERROR"):
            print(self._format("ERROR", Fore.RED, message), file=sys.stderr)

    def critical(self, message: str):
        if self._should_print("CRITICAL"):
            print(self._format("CRITICAL", Fore.MAGENTA + Style.BRIGHT, message), file=sys.stderr)

    def banner(self):
        banner = f"""
{Fore.CYAN}{Style.BRIGHT}
 ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ███████╗
 ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝
 ███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝███████╗
 ██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗╚════██║
 ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║███████║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝
{Style.RESET_ALL}
{Fore.WHITE} HTTP Headers Passive Enumeration Tool{Style.RESET_ALL}
{Fore.LIGHTBLACK_EX} Web Pentesting Suite — Headers Module{Style.RESET_ALL}
        """
        print(banner)

    def section(self, title: str):
        width = 60
        line = "─" * width
        print(f"\n{Fore.CYAN}{line}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{Style.BRIGHT} {title}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")

    def subsection(self, title: str):
        print(f"\n{Fore.LIGHTBLUE_EX}{Style.BRIGHT} > {title}{Style.RESET_ALL}")

    def finding(self, severity: str, header: str, detail: str, force: bool = False):
        if not self.verbose and not force and severity.upper() in ("LOW", "INFO", "OK"):
            return
        severity_colors = {
            "CRITICAL": Fore.MAGENTA + Style.BRIGHT,
            "HIGH":   Fore.RED + Style.BRIGHT,
            "MEDIUM": Fore.YELLOW,
            "LOW":    Fore.CYAN,
            "INFO":   Fore.WHITE,
            "OK":     Fore.GREEN,
        }
        color = severity_colors.get(severity.upper(), Fore.WHITE)
        sev_label = f"{color}[{severity.upper()}]{Style.RESET_ALL}"
        header_str = f"{Fore.LIGHTWHITE_EX}{header}{Style.RESET_ALL}"
        print(f"  {sev_label} {header_str}: {detail}")

    def result_line(self, key: str, value: str, highlight: bool = False):
        key_str = f"{Fore.LIGHTBLACK_EX}{key}{Style.RESET_ALL}"
        val_color = Fore.YELLOW if highlight else Fore.WHITE
        val_str = f"{val_color}{value}{Style.RESET_ALL}"
        print(f"  {key_str}: {val_str}")

    def success(self, message: str):
        print(f"  {Fore.GREEN}✔{Style.RESET_ALL} {message}")

    def failure(self, message: str):
        print(f"  {Fore.RED}✘{Style.RESET_ALL} {message}")

    def grade_display(self, grade: str, score: int):
        grade_colors = {
            "A+": Fore.GREEN + Style.BRIGHT,
            "A":  Fore.GREEN,
            "B":  Fore.YELLOW + Style.BRIGHT,
            "C":  Fore.YELLOW,
            "D":  Fore.RED,
            "F":  Fore.RED + Style.BRIGHT,
        }
        color = grade_colors.get(grade, Fore.WHITE)
        print(f"\n  {Fore.WHITE}Security Grade: {color}{grade}{Style.RESET_ALL}  |  Score: {Fore.CYAN}{score}/100{Style.RESET_ALL}")
