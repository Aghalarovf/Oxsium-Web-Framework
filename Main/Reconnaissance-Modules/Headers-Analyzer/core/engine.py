import json
import re
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from .cli import ScanConfig
from .logger import Logger
from .intercept_reader import InterceptReader, InterceptError, HTTPResponse
from .exporter import Exporter

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "OK": 5}
COOKIE_MODULE_NAME = "Cookie & JWT Analyzer"
MAX_SUMMARY_IDS = 5
QUIET_SEVERITIES = ("INFO", "OK")

_DIRECTION_PREFIX = re.compile(r"^(Value )?(?:Set-Cookie|Cookie) \(")
_VOLATILE_DETAIL = (
    (re.compile(r"opaque \d+-character state token"), "opaque state token"),
    (re.compile(r"(opaque random token), estimated .*$"), r"\1"),
    (re.compile(r"(16-hex segment )'[^']*'"), r"\1"),
)


def _dedupe_key(module_name: str, finding: Dict[str, Any]) -> Tuple[str, str, str, str]:
    severity = finding.get("severity", "INFO")
    header = finding.get("header", "")
    detail = finding.get("detail", "")
    if severity in ("INFO", "OK"):
        header = _DIRECTION_PREFIX.sub(lambda m: f"{m.group(1) or ''}Cookie (", header)
    for pattern, replacement in _VOLATILE_DETAIL:
        detail = pattern.sub(replacement, detail)
    return module_name, severity, header, detail


class ModuleResult:
    def __init__(self, module_name: str):
        self.module_name = module_name
        self.findings: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {}
        self.error: Optional[str] = None

    def add_finding(self, severity: str, header: str, detail: str, extra: Optional[Dict] = None):
        entry = {
            "severity": severity.upper(),
            "header": header,
            "detail": detail,
        }
        if extra:
            entry.update(extra)
        self.findings.append(entry)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module_name,
            "findings": self.findings,
            "metadata": self.metadata,
            "error": self.error,
        }


class ScanEngine:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.logger = Logger(verbose=config.verbose)

    def _load_modules(self):
        modules = []

        if self.config.headers or self.config.secure:
            from modules.sec_headers import SecurityHeadersModule
            modules.append(SecurityHeadersModule())

        if self.config.leak:
            from modules.information_leak import InfoLeakModule
            modules.append(InfoLeakModule())

        if self.config.leaks:
            from modules.headers_leaks import HeaderLeaksModule
            modules.append(HeaderLeaksModule())

        if self.config.cors:
            from modules.cors_checker import CORSModule
            modules.append(CORSModule())

        if self.config.score:
            from modules.score_evaluator import SecurityScoreModule
            modules.append(SecurityScoreModule())

        if self.config.ws:
            from modules.websocket_analyzer import WebSocketModule
            modules.append(WebSocketModule())

        if self.config.cookies:
            from modules.cookie_analyzer import CookieModule
            modules.append(CookieModule())

        if self.config.redirect:
            from modules.redirect_analyzer import RedirectAnalyzerModule
            modules.append(RedirectAnalyzerModule())

        if self.config.cache:
            from modules.cache_analyzer import CacheAnalyzerModule
            modules.append(CacheAnalyzerModule())

        if self.config.ratelimit:
            from modules.rate_limit_analyzer import RateLimitModule
            modules.append(RateLimitModule())

        return modules

    def _run_module(self, module, response: HTTPResponse) -> ModuleResult:
        try:
            return module.run(response)
        except Exception as exc:
            result = ModuleResult(module.name)
            result.error = str(exc)
            return result

    def _analyze_response(self, modules, response: HTTPResponse) -> Dict[str, Any]:
        module_results: Dict[str, ModuleResult] = {}
        for module in modules:
            if not module.applies_to(response):
                continue
            module_results[module.name] = self._run_module(module, response)

        score_data = None
        for result in module_results.values():
            if not result.error and "score_summary" in result.metadata:
                score_data = result.metadata["score_summary"]
                break

        return {
            "id": response.entry_id,
            "source": response.source,
            "method": response.method,
            "url": response.url,
            "status_code": response.status_code,
            "modules": {name: result.to_dict() for name, result in module_results.items()},
            "score": score_data,
        }

    def _unique_entries(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen_findings = set()
        seen_errors = set()
        seen_scores = set()
        unique: List[Dict[str, Any]] = []

        for entry in entries:
            modules: Dict[str, Any] = {}
            for module_name, module_data in entry["modules"].items():
                findings = []
                for finding in module_data["findings"]:
                    if finding.get("header") == "Cookie Inventory":
                        continue
                    if self._is_quiet(module_name, finding.get("severity")):
                        continue
                    key = _dedupe_key(module_name, finding)
                    if key in seen_findings:
                        continue
                    seen_findings.add(key)
                    findings.append(finding)

                error = module_data["error"]
                if error:
                    error_key = (module_name, error)
                    if error_key in seen_errors:
                        error = None
                    else:
                        seen_errors.add(error_key)

                if findings or error:
                    modules[module_name] = {
                        "module": module_name,
                        "findings": findings,
                        "error": error,
                    }

            score = entry.get("score")
            if score:
                score_key = json.dumps(score, sort_keys=True, default=str)
                if score_key in seen_scores:
                    score = None
                else:
                    seen_scores.add(score_key)

            if not modules and not score:
                continue

            unique.append({
                "id": entry["id"],
                "source": entry["source"],
                "method": entry["method"],
                "url": entry["url"],
                "status_code": entry["status_code"],
                "modules": modules,
                "score": score,
            })

        return unique

    def _is_quiet(self, module_name: str, severity: Any) -> bool:
        return not self.config.verbose and severity in QUIET_SEVERITIES

    def _export_summary(self, summary: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [item for item in summary if not self._is_quiet(item["module"], item["severity"])]

    def _export_cookie_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        if self.config.verbose:
            return report
        trimmed = dict(report)
        trimmed["cookies"] = [
            {**cookie, "findings": [f for f in cookie["findings"] if f["severity"] not in QUIET_SEVERITIES]}
            for cookie in report["cookies"]
        ]
        trimmed["general_findings"] = [
            f for f in report["general_findings"] if f["severity"] not in QUIET_SEVERITIES
        ]
        return trimmed

    def _hides_cookie_module(self, module_name: str) -> bool:
        return self.config.cookies and module_name == COOKIE_MODULE_NAME

    def _visible_modules(self, entry: Dict[str, Any]) -> List[str]:
        return [name for name in entry["modules"] if not self._hides_cookie_module(name)]

    def _print_entry(self, entry: Dict[str, Any]):
        url = entry["url"]
        if len(url) > 110:
            url = url[:107] + "..."
        self.logger.section(f"#{entry['id']} {entry['method']} {url} -> {entry['status_code']}")

        for module_name, module_data in entry["modules"].items():
            if self._hides_cookie_module(module_name):
                continue
            self.logger.subsection(module_name)
            if module_data["error"]:
                self.logger.error(f"Module error: {module_data['error']}")
                continue
            if not module_data["findings"]:
                self.logger.info("No findings for this module.")
                continue
            for finding in module_data["findings"]:
                self.logger.finding(
                    severity=finding.get("severity", "INFO"),
                    header=finding.get("header", ""),
                    detail=finding.get("detail", ""),
                    force=module_name == COOKIE_MODULE_NAME,
                )

        score = entry.get("score")
        if score:
            self.logger.grade_display(grade=score.get("grade", "N/A"), score=score.get("score", 0))

    def _build_summary(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        aggregated: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

        for entry in entries:
            for module_name, module_data in entry["modules"].items():
                for finding in module_data["findings"]:
                    severity = finding.get("severity", "INFO")
                    if severity == "OK" and module_name != COOKIE_MODULE_NAME:
                        continue
                    key = _dedupe_key(module_name, finding)
                    bucket = aggregated.setdefault(key, {
                        "module": module_name,
                        "severity": severity,
                        "header": key[2],
                        "detail": key[3],
                        "count": 0,
                        "entry_ids": [],
                    })
                    bucket["count"] += 1
                    if entry["id"] not in bucket["entry_ids"]:
                        bucket["entry_ids"].append(entry["id"])

        for bucket in aggregated.values():
            bucket["entries_total"] = len(bucket["entry_ids"])
            bucket["entry_ids"] = bucket["entry_ids"][:MAX_SUMMARY_IDS]

        return sorted(
            aggregated.values(),
            key=lambda item: (SEVERITY_ORDER.get(item["severity"], 99), -item["count"], item["module"]),
        )

    def _print_summary(self, summary: List[Dict[str, Any]], analyzed: int):
        summary = [item for item in summary if not self._hides_cookie_module(item["module"])]
        if self.config.cookies and not self._has_non_cookie_module():
            return
        self.logger.section(f"Summary - unique findings across {analyzed} response(s)")
        if not summary:
            self.logger.info("No findings.")
            return

        counts: Dict[str, int] = {}
        for item in summary:
            counts[item["severity"]] = counts.get(item["severity"], 0) + 1

        for item in summary:
            self.logger.finding(
                severity=item["severity"],
                header=item["header"],
                detail=f"{item['detail']} (x{item['count']})",
                force=item["module"] == COOKIE_MODULE_NAME,
            )

        ordered = sorted(counts.items(), key=lambda pair: SEVERITY_ORDER.get(pair[0], 99))
        self.logger.info("Unique findings by severity: " + ", ".join(f"{sev}={n}" for sev, n in ordered))

    def _has_non_cookie_module(self) -> bool:
        cfg = self.config
        return any((cfg.headers, cfg.secure, cfg.leak, cfg.leaks, cfg.cors, cfg.score,
                    cfg.ws, cfg.redirect, cfg.cache, cfg.ratelimit))

    def run(self):
        self.logger.banner()

        modules = self._load_modules()
        if not modules:
            self.logger.warn("No modules selected. Use --headers, --leak, --leaks, --cors, --score, --ws, --cookies, --redirect, --cache, --ratelimit, or --all")
            return None

        reader = InterceptReader(self.config.intercept, self.config.domain)
        t_start = time.time()

        try:
            responses = reader.read()
        except InterceptError as exc:
            self.logger.critical(str(exc))
            return None

        for warning in reader.warnings:
            self.logger.warn(warning)

        if self.config.domain:
            matched_total = sum(reader.host_matches.values())
            self.logger.info(f"Domain  : {self.config.domain} (matched {matched_total} record(s))")

        self.logger.info(f"Files   : {len(reader.files_read)}")
        for file_path in reader.files_read:
            self.logger.result_line("  ->", file_path)
        self.logger.info(f"Records : {reader.total_records} read, {len(responses)} with usable responses")
        self.logger.info("Modules : " + ", ".join(module.name for module in modules))

        if not responses:
            self.logger.critical("No analyzable responses found in the intercept files")
            return None

        entries: List[Dict[str, Any]] = []
        for response in responses:
            entry = self._analyze_response(modules, response)
            if not entry["modules"]:
                continue
            entries.append(entry)

        if not entries:
            self.logger.warn("No entries matched the selected modules")

        unique_entries = self._unique_entries(entries)
        for entry in unique_entries:
            if self._visible_modules(entry):
                self._print_entry(entry)

        hidden = len(entries) - len(unique_entries)
        if hidden:
            self.logger.info(f"{hidden} response(s) hidden: no findings that were not already reported")

        ws_overview = None
        if self.config.ws:
            from modules.websocket_analyzer import build_overview, print_overview
            ws_overview = build_overview(entries)
            print_overview(self.logger, ws_overview)

        summary = self._build_summary(entries)
        self._print_summary(summary, len(entries))

        cookie_report = None
        if self.config.cookies:
            from modules.cookie_report import build_cookie_report, print_cookie_report
            cookie_report = build_cookie_report(entries)
            print_cookie_report(self.logger, cookie_report)

        elapsed = round((time.time() - t_start) * 1000, 2)

        scan_result = {
            "domain": self.config.domain,
            "intercept_files": reader.files_read,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "elapsed_ms": elapsed,
            "records_read": reader.total_records,
            "responses_analyzed": len(entries),
            "entries_with_unique_results": len(unique_entries),
            "entries": unique_entries,
            "summary": self._export_summary(summary),
        }
        if ws_overview is not None:
            scan_result["websocket"] = ws_overview
        if cookie_report is not None:
            scan_result["cookie_report"] = self._export_cookie_report(cookie_report)

        if self.config.output:
            try:
                exporter = Exporter(self.config.output, self.config.output_format)
                exporter.export(scan_result)
                self.logger.success(f"Report saved to: {self.config.output}")
            except Exception as exc:
                self.logger.error(f"Export failed: {exc}")

        self.logger.info(f"Analysis completed in {elapsed}ms")
        return scan_result