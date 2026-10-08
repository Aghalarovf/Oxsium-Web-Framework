import sys
import io
import threading
import builtins
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from core.ui import C, info, signal
from core.exporter import export_json

from modules.general_recon import GeneralReconModule
from modules.zone_transfer import ZoneTransferModule
from modules.dangling_dns import DanglingDNSModule
from modules.modern_dns import ModernDNSModule
from modules.ttl_anomaly import TTLAnomalyModule


MODULE_WORKERS = 3


class Engine:
    def __init__(self, args, resolver, session):
        self.args     = args
        self.resolver = resolver
        self.session  = session
        raw           = args.domain.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
        self.domain   = raw
        # Ensure args.domain is always a plain hostname (no scheme)
        args.domain   = raw
        self.report   = {
            "target":    self.domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "results":   {},
        }

    def _build_tasks(self):
        args      = self.args
        domain    = self.domain
        resolver  = self.resolver
        session   = self.session
        dot_port  = args.port if args.port != 53 else 853
        rec_types = args.record_types.upper().split(",") if args.record_types else None

        recon   = GeneralReconModule(domain, resolver, session)
        zt      = ZoneTransferModule(domain, resolver, session)
        dangle  = DanglingDNSModule(domain, resolver, session)
        modern  = ModernDNSModule(domain, resolver, session)
        ttl     = TTLAnomalyModule(domain, resolver, session)

        tasks = []
        if args.records:
            tasks.append(("records",        lambda: recon.query_records(rec_types)))
        if args.axfr:
            tasks.append(("axfr",           lambda: zt.attempt_axfr()))
        if args.reverse:
            tasks.append(("reverse",        lambda: recon.reverse_lookup()))
        if args.dangling:
            tasks.append(("dangling",       lambda: dangle.check_dangling_cname()))
        if args.sec:
            tasks.append(("dnssec",         lambda: modern.validate_dnssec()))
        if args.anomaly:
            tasks.append(("ttl_anomalies",  lambda: ttl.check_ttl_anomalies()))

        return tasks

    def run(self):
        args = self.args

        if args.all:
            args.records = args.axfr = args.reverse = args.dangling = True
            args.sec = True
            args.anomaly = True

        tasks = self._build_tasks()

        if not tasks:
            from core.ui import warn
            warn("No modules selected. Use --all or specify flags.")
            print(f"\n  Run:  {C.BOLD}python3 main.py --help{C.RESET}  for usage.\n")
            return self.report

        if not args.all:
            self._run_sequential(tasks)
        else:
            self._run_parallel(tasks)

        return self.report

    def _run_sequential(self, tasks):
        for key, fn in tasks:
            self.report["results"][key] = fn()
            signal(key)

    def _run_parallel(self, tasks):
        builtins_print = builtins.print
        _print_lock    = threading.Lock()
        _real_print    = builtins_print
        _real_stdout   = sys.stdout
        _tls           = threading.local()

        class _ThreadLocalStdout:
            def write(self, data):
                buf = getattr(_tls, "buf", None)
                if buf is not None:
                    buf.write(data)
                else:
                    _real_stdout.write(data)

            def flush(self):
                buf = getattr(_tls, "buf", None)
                if buf is not None:
                    buf.flush()
                else:
                    _real_stdout.flush()

            def fileno(self):
                return _real_stdout.fileno()

        sys.stdout = _ThreadLocalStdout()

        def _run_module(key: str, fn) -> tuple:
            _tls.buf = io.StringIO()
            try:
                result = fn()
            except Exception as e:
                result = {"error": str(e)}
            captured = _tls.buf.getvalue()
            _tls.buf = None
            signal(key)
            return key, result, captured

        def _flush_output(key: str, text: str):
            with _print_lock:
                if text:
                    _real_print(text, end="")
                _real_print(
                    f"\n{C.DIM}  {'─'*56}{C.RESET}\n"
                    f"  {C.GREEN}✔{C.RESET}  {C.BOLD}{key}{C.RESET} completed\n",
                    end=""
                )

        info(f"Running {len(tasks)} module(s) with {MODULE_WORKERS} concurrent workers …\n")

        with ThreadPoolExecutor(max_workers=MODULE_WORKERS) as pool:
            ordered_futures = [
                (key, pool.submit(_run_module, key, fn))
                for key, fn in tasks
            ]
            for key, future in ordered_futures:
                _, result, output = future.result()
                self.report["results"][key] = result
                _flush_output(key, output)

        sys.stdout = _real_stdout