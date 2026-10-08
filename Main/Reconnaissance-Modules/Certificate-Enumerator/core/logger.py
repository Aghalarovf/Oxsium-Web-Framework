import io
import logging
import sys
from colorama import Fore, Style, init as colorama_init

# Windows terminalları (cp1252 kimi) Unicode qutu simvollarını render edə bilmir.
# stdout-u UTF-8-ə məcbur edirik.
if hasattr(sys.stdout, "buffer") and (
    sys.stdout.encoding is None
    or sys.stdout.encoding.lower().replace("-", "") not in ("utf8", "utf8bom")
):
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace"
    )

colorama_init(autoreset=True)

LEVEL_COLORS = {
    "DEBUG":    Fore.CYAN,
    "INFO":     Fore.GREEN,
    "WARNING":  Fore.YELLOW,
    "ERROR":    Fore.RED,
    "CRITICAL": Fore.MAGENTA,
}

STATUS_COLORS = {
    "PASS":  Fore.GREEN,
    "FAIL":  Fore.RED,
    "WARN":  Fore.YELLOW,
    "INFO":  Fore.CYAN,
    "SKIP":  Fore.WHITE,
}


class ColorFormatter(logging.Formatter):
    def __init__(self, use_color=True):
        super().__init__()
        self.use_color = use_color

    def format(self, record):
        level = record.levelname
        msg = record.getMessage()
        if self.use_color:
            color = LEVEL_COLORS.get(level, "")
            return f"{color}[{level}]{Style.RESET_ALL} {msg}"
        return f"[{level}] {msg}"


class ScanLogger:
    def __init__(self, verbose=False, no_color=False, log_file=None, stream=None):
        self.verbose = verbose
        self.no_color = no_color
        self._logger = logging.getLogger("tls_scanner")
        self._logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self._logger.handlers.clear()

        console_handler = logging.StreamHandler(stream or sys.stdout)
        console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        console_handler.setFormatter(ColorFormatter(use_color=not no_color))
        self._logger.addHandler(console_handler)

        if log_file:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(
                logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s",
                                  datefmt="%Y-%m-%d %H:%M:%S")
            )
            self._logger.addHandler(file_handler)

    def debug(self, msg):
        self._logger.debug(msg)

    def info(self, msg):
        self._logger.info(msg)

    def warning(self, msg):
        self._logger.warning(msg)

    def error(self, msg):
        self._logger.error(msg)

    def critical(self, msg):
        self._logger.critical(msg)

    def result(self, status, label, value="", indent=0):
        color = STATUS_COLORS.get(status, "") if not self.no_color else ""
        reset = Style.RESET_ALL if not self.no_color else ""
        prefix = "  " * indent
        tag = f"{color}[{status}]{reset}"
        if value:
            print(f"{prefix}{tag} {label}: {value}")
        else:
            print(f"{prefix}{tag} {label}")

    def section(self, title):
        width = 60
        bar = "=" * width
        if not self.no_color:
            print(f"\n{Fore.CYAN}{bar}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  {title}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{bar}{Style.RESET_ALL}")
        else:
            print(f"\n{bar}")
            print(f"  {title}")
            print(f"{bar}")

    def subsection(self, title):
        if not self.no_color:
            print(f"\n{Fore.YELLOW}  -- {title} --{Style.RESET_ALL}")
        else:
            print(f"\n  -- {title} --")

    def banner(self, domain, port, sni):
        if self.no_color:
            print(f"""
TLS Scanner
Target : {domain}:{port}
SNI    : {sni}
""")
            return
        print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║              TLS / SSL Security Scanner                  ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}

  {Fore.WHITE}Target :{Style.RESET_ALL} {Fore.GREEN}{domain}:{port}{Style.RESET_ALL}
  {Fore.WHITE}SNI    :{Style.RESET_ALL} {Fore.GREEN}{sni}{Style.RESET_ALL}
""")


_logger_instance = None


def get_logger(verbose=False, no_color=False, log_file=None, stream=None):
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = ScanLogger(verbose=verbose, no_color=no_color, log_file=log_file, stream=stream)
    return _logger_instance