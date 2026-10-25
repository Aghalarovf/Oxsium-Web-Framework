import json
import sys
import threading
from datetime import datetime, timezone

COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_DIM = "\033[2m"
COLOR_OK = "\033[92m"
COLOR_ERROR = "\033[91m"
COLOR_WARN = "\033[93m"
COLOR_HEADER = "\033[96m"

COLOR_CRITICAL = "\033[1;97;41m"
COLOR_HIGH = "\033[1;91m"
COLOR_MEDIUM = "\033[1;93m"
COLOR_LOW = "\033[1;96m"
COLOR_INFO = "\033[2m"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR = {
    "critical": COLOR_CRITICAL,
    "high": COLOR_HIGH,
    "medium": COLOR_MEDIUM,
    "low": COLOR_LOW,
    "info": COLOR_INFO,
}

REPORT_WIDTH = 79

BAD_WHEN_YES_KEYS = {
    "null_session_allowed",
    "guest_access_allowed",
    "anonymous_access_allowed",
    "smb1_enabled",
    "smbv1_enabled",
    "signing_disabled",
    "encryption_disabled",
    "vulnerable",
    "is_vulnerable",
    "admin_share_access",
    "downgrade_possible",
    "downgrade_accepted",
    "os_version_disclosed",
    "anonymous_logon_allowed",
    "description_disclosed",
}

GOOD_WHEN_YES_KEYS = {
    "signing_enabled",
    "signing_required",
    "encryption_supported",
    "encryption_enabled",
    "encryption_required",
    "credentials_valid",
}

SECURITY_RELEVANT_YES_NO_KEYS = BAD_WHEN_YES_KEYS | GOOD_WHEN_YES_KEYS

GOOD_WORDS = {
    "not_vulnerable", "notvulnerable", "secure", "enabled", "required",
    "supported", "patched", "strong", "ok", "pass", "passed",
}
BAD_WORDS = {
    "vulnerable", "insecure", "disabled", "unsupported", "unpatched",
    "weak", "fail", "failed", "denied", "exposed",
}
WARN_WORDS = {
    "partial", "unknown", "possible", "degraded", "optional",
}

KEY_VALUE_COLORS = {
    "eternalblue_wannacry_precondition": {"met": COLOR_ERROR, "not_met": COLOR_OK},
    "version_dialect_consistency": {
        "inconsistent_possible_honeypot": COLOR_WARN,
        "consistent": COLOR_OK,
        "unknown": COLOR_DIM,
    },
    "socket_behavior": {
        "tcp_rst": COLOR_WARN,
        "no_response_timeout": COLOR_WARN,
        "tcp_fin_graceful_close": COLOR_OK,
        "response_received": COLOR_OK,
    },
}

MODULE_DISPLAY_NAMES = {
    "smbdialectprober": "SMB Dialect Prober",
    "smbsigningauditor": "SMB Signing Auditor",
    "smbcapabilityscanner": "SMB Capability Scanner",
    "smbv1detector": "SMBv1 Detector",
    "smbencryptionchecker": "SMB Encryption Checker",
    "smbportmapper": "SMB Port Mapper",
    "smbdialectdowngradechecker": "SMB Dialect Downgrade Checker",
    "guestaccessprober": "Guest Access Prober",
    "smbserverstringextractor": "SMB Server String Extractor",
    "smbtimeoutbehaviorprober": "SMB Timeout Behavior Prober",
    "credentialvalidator": "Credential Validator",
    "netbiosnamescanner": "NetBIOS Name Scanner",
    "smbfingerprintmapper": "SMB Fingerprint Mapper",
    "rpcendpointmapper": "RPC Endpoint Mapper",
    "namedpipeenumerator": "Named Pipe Enumerator",
    "systemtimereader": "System Time Reader",
    "computerdescriptionreader": "Computer Description Reader",
    "installedserviceslister": "Installed Services Lister",
    "antivirusdetector": "Antivirus Detector",
    "uacconfigreader": "UAC Config Reader",
    "hotfixenumerator": "Hotfix Enumerator",
    "networkinterfaceenumerator": "Network Interface Enumerator",
    "wmiaccessprober": "WMI Access Prober",
}

ACRONYMS = {"smb", "rpc", "ntlm", "os", "guid", "id", "dcerpc", "lsa", "sam", "tcp"}

MODULE_NAME_WORDS = [
    "smb", "v1", "dialect", "prober", "signing", "auditor", "null", "session",
    "guest", "anonymous", "access", "share", "enum", "enumerator", "rpc",
    "domain", "info", "version", "login", "password", "policy", "printer",
    "spool", "relay", "check", "scanner", "lister", "capability", "detector",
    "encryption", "checker", "port", "mapper", "downgrade", "prober",
    "server", "string", "extractor", "timeout", "behavior",
]


def _humanize_module_name(name: str) -> str:
    if name in MODULE_DISPLAY_NAMES:
        return MODULE_DISPLAY_NAMES[name]

    remaining = name.lower()
    words = []
    while remaining:
        match = next((w for w in sorted(MODULE_NAME_WORDS, key=len, reverse=True) if remaining.startswith(w)), None)
        if match:
            words.append(match)
            remaining = remaining[len(match):]
        else:
            words.append(remaining)
            remaining = ""

    return " ".join(w.upper() if w in ACRONYMS else w.capitalize() for w in words)


KEY_WORD_ACRONYMS = {
    "smb", "smb1", "smbv1", "guid", "ntlm", "dfs", "os", "id", "lz77", "lznt1",
}

KEY_LABEL_OVERRIDES = {
    "eternalblue_wannacry_precondition": "EternalBlue/WannaCry Precondition",
    "smb_relay_verdict": "SMB Relay Verdict",
}


def _humanize_key(key: str) -> str:
    if key in KEY_LABEL_OVERRIDES:
        return KEY_LABEL_OVERRIDES[key]
    words = str(key).replace("-", "_").split("_")
    return " ".join(w.upper() if w.lower() in KEY_WORD_ACRONYMS else w.capitalize() for w in words if w)


def _format_value(value):
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple)):
        if not value:
            return "-"
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        if not value:
            return "-"
        return ", ".join(f"{k}={v}" for k, v in value.items())
    if value is None or value == "":
        return "-"
    return str(value)


def _verdict_color(key, formatted_value):
    key_lower = (key or "").lower()
    value_lower = formatted_value.lower()

    if key_lower in KEY_VALUE_COLORS and value_lower in KEY_VALUE_COLORS[key_lower]:
        return KEY_VALUE_COLORS[key_lower][value_lower]

    if value_lower in ("yes", "no") and key_lower in SECURITY_RELEVANT_YES_NO_KEYS:
        bad_on_yes = key_lower in BAD_WHEN_YES_KEYS
        is_yes = value_lower == "yes"
        is_good = (is_yes and not bad_on_yes) or (not is_yes and bad_on_yes)
        return COLOR_OK if is_good else COLOR_ERROR

    normalized = value_lower.replace(" ", "_").replace("-", "_")

    if normalized in GOOD_WORDS:
        return COLOR_OK
    if normalized in BAD_WORDS:
        return COLOR_ERROR
    if normalized in WARN_WORDS:
        return COLOR_WARN

    if normalized.startswith("not_") and normalized[4:] in BAD_WORDS:
        return COLOR_OK

    if any(word in normalized for word in BAD_WORDS):
        return COLOR_ERROR
    if any(word in normalized for word in GOOD_WORDS):
        return COLOR_OK
    if any(word in normalized for word in WARN_WORDS):
        return COLOR_WARN

    return None


def _severity_badge(severity: str) -> str:
    return f"[{severity.upper():<8}]"


class HumanReporter:
    def __init__(self, use_color: bool = True):
        self.use_color = use_color

    def _c(self, color: str, text: str) -> str:
        if not self.use_color or not color:
            return text
        return f"{color}{text}{COLOR_RESET}"

    def _rule(self, char: str = "=") -> str:
        return char * REPORT_WIDTH

    def _banner_box(self, out, title: str, char: str = "="):
        out.write("\n" + self._c(COLOR_HEADER, self._rule(char)) + "\n")
        out.write(self._c(COLOR_HEADER, self._c(COLOR_BOLD, f"  {title}")) + "\n")
        out.write(self._c(COLOR_HEADER, self._rule(char)) + "\n")

    def print_report(self, results: list, meta: dict = None, security_by_target: dict = None, verbosity: int = 1):
        out = sys.stdout
        security_by_target = security_by_target or {}

        if meta:
            mode = meta.get("mode", "?")
            threads = meta.get("threads", "?")
            target_count = meta.get("target_count", "?")
            elapsed = meta.get("elapsed_seconds", "?")
            summary = (
                f"Mode: {self._c(COLOR_BOLD, str(mode))}    "
                f"Threads: {self._c(COLOR_BOLD, str(threads))}    "
                f"Targets: {self._c(COLOR_BOLD, str(target_count))}    "
                f"Elapsed: {self._c(COLOR_BOLD, f'{elapsed}s')}"
            )
            out.write("\n" + summary + "\n")

        if not results:
            out.write("\n" + self._c(COLOR_ERROR, "No results collected.") + "\n")
            return

        all_remediations = {}
        affected_targets_by_finding = {}

        for entry in results:
            target = entry.get("target", "?")
            analysis = security_by_target.get(target, {})
            findings = analysis.get("findings", [])
            attack_vectors = analysis.get("attack_vectors", [])
            remediations = analysis.get("remediations", [])

            risk_label = self._overall_risk_label(findings)
            header_text = f"Target: {target}"
            if risk_label:
                header_text += f"    Overall Risk: {risk_label}"

            self._banner_box(out, header_text)

            for module_result in entry.get("modules", []):
                self._print_module(out, module_result)

            self._print_findings_summary(out, findings)

            if verbosity >= 2 and attack_vectors:
                self._print_attack_vectors(out, attack_vectors)

            for remediation in remediations:
                finding_id = remediation["finding_id"]
                all_remediations[finding_id] = remediation
                affected_targets_by_finding.setdefault(finding_id, []).append(target)

        if verbosity >= 2 and all_remediations:
            self._print_consolidated_remediation(out, all_remediations, affected_targets_by_finding)

        out.write("\n")

    def _overall_risk_label(self, findings: list) -> str:
        if not findings:
            return ""
        best = min((SEVERITY_ORDER.get(f["severity"], 99) for f in findings), default=99)
        for severity, rank in SEVERITY_ORDER.items():
            if rank == best:
                return self._c(SEVERITY_COLOR.get(severity, ""), severity.upper())
        return ""

    def _print_module(self, out, module_result: dict):
        name = module_result.get("module", "?")
        status = module_result.get("status", "?")

        if status == "ok":
            marker = self._c(COLOR_OK, "[+]")
        else:
            marker = self._c(COLOR_ERROR, "[-]")

        display_name = _humanize_module_name(name)
        out.write(f"\n  {marker} {self._c(COLOR_BOLD, display_name)}\n")

        if status == "ok":
            data = module_result.get("data") or {}
            if not data:
                out.write(f"      {self._c(COLOR_DIM, 'no data returned')}\n")
                return

            labels = {key: _humanize_key(key) for key in data.keys()}
            width = max(len(label) for label in labels.values())
            for key, value in data.items():
                formatted = _format_value(value)
                color = _verdict_color(key, formatted)
                value_text = self._c(color, formatted) if color else formatted
                label = self._c(COLOR_DIM, f"{labels[key]:<{width}} :")
                out.write(f"      {label} {value_text}\n")
        else:
            error = module_result.get("error", "unknown error")
            label = self._c(COLOR_DIM, "error:")
            out.write(f"      {label} {self._c(COLOR_ERROR, str(error))}\n")

    def _print_findings_summary(self, out, findings: list):
        out.write("\n" + self._c(COLOR_HEADER, self._rule("-")) + "\n")
        out.write(self._c(COLOR_BOLD, "  SECURITY FINDINGS SUMMARY") + "\n")
        out.write(self._c(COLOR_HEADER, self._rule("-")) + "\n")

        if not findings:
            out.write("  " + self._c(COLOR_OK, "No significant weaknesses identified on this target.") + "\n")
            return

        counts = {}
        for finding in findings:
            counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1

        count_parts = []
        for severity in ("critical", "high", "medium", "low", "info"):
            if severity in counts:
                count_parts.append(self._c(SEVERITY_COLOR.get(severity, ""), f"{severity.title()}: {counts[severity]}"))
        out.write("  " + "   ".join(count_parts) + "\n\n")

        for finding in findings:
            badge = self._c(SEVERITY_COLOR.get(finding["severity"], ""), _severity_badge(finding["severity"]))
            out.write(f"  {badge} {self._c(COLOR_BOLD, finding['title'])}\n")
            module_label = _humanize_module_name(finding["module"])
            evidence = f"{_humanize_key(finding['evidence_field'])} = {_format_value(finding['evidence_value'])}"
            out.write(f"             {self._c(COLOR_DIM, f'module: {module_label}  |  evidence: {evidence}')}\n")

    def _print_attack_vectors(self, out, attack_vectors: list):
        out.write("\n" + self._c(COLOR_HEADER, self._rule("-")) + "\n")
        out.write(self._c(COLOR_BOLD, "  ATTACK VECTOR ANALYSIS") + "\n")
        out.write(self._c(COLOR_HEADER, self._rule("-")) + "\n")

        for vector in attack_vectors:
            badge = self._c(SEVERITY_COLOR.get(vector["severity"], ""), _severity_badge(vector["severity"]))
            out.write(f"\n  {badge} {self._c(COLOR_BOLD, vector['title'])}\n")

            mitre = vector.get("mitre_attack") or {}
            if mitre:
                out.write(
                    f"      {self._c(COLOR_DIM, 'MITRE ATT&CK:')} "
                    f"{mitre.get('tactic', '-')} -- {mitre.get('technique', '-')}\n"
                )

            out.write(f"      {self._c(COLOR_DIM, 'Summary:')} {vector['summary']}\n")

            if vector.get("narrative"):
                out.write(f"      {self._c(COLOR_DIM, 'Exploitation Path:')}\n")
                for index, step in enumerate(vector["narrative"], start=1):
                    out.write(f"        {index}. {step}\n")

            if vector.get("impact"):
                out.write(f"      {self._c(COLOR_WARN, 'Impact:')} {vector['impact']}\n")

            if vector.get("references"):
                out.write(f"      {self._c(COLOR_DIM, 'References:')} {', '.join(vector['references'])}\n")

    def _print_consolidated_remediation(self, out, remediations_by_finding: dict, affected_targets_by_finding: dict):
        out.write("\n" + self._c(COLOR_HEADER, self._rule("=")) + "\n")
        out.write(self._c(COLOR_BOLD, "  REMEDIATION") + "\n")
        out.write(self._c(COLOR_HEADER, self._rule("=")) + "\n")

        ordered = sorted(
            remediations_by_finding.values(),
            key=lambda entry: SEVERITY_ORDER.get(entry.get("priority", "info"), 99),
        )

        for remediation in ordered:
            badge = self._c(SEVERITY_COLOR.get(remediation["priority"], ""), _severity_badge(remediation["priority"]))
            out.write(f"\n  {badge} {self._c(COLOR_BOLD, remediation['title'])}\n")
            out.write(f"      {self._c(COLOR_DIM, 'Finding:')} {remediation['finding_title']}\n")

            targets = affected_targets_by_finding.get(remediation["finding_id"], [])
            if targets:
                out.write(f"      {self._c(COLOR_DIM, 'Affected targets:')} {', '.join(targets)}\n")

            out.write(f"      {self._c(COLOR_DIM, 'Recommendation:')} {remediation['recommendation']}\n")

            if remediation.get("steps"):
                out.write(f"      {self._c(COLOR_DIM, 'Remediation Steps:')}\n")
                for index, step in enumerate(remediation["steps"], start=1):
                    out.write(f"        {index}. {step}\n")

            if remediation.get("references"):
                out.write(f"      {self._c(COLOR_DIM, 'References:')} {', '.join(remediation['references'])}\n")

        out.write("\n" + self._c(COLOR_HEADER, self._rule("=")) + "\n")


class JSONOutputWriter:
    def __init__(self, output_path: str = None):
        self.output_path = output_path
        self._results = []
        self._lock = threading.Lock()

    def add_result(self, target: str, module_results: list):
        with self._lock:
            self._results.append(
                {
                    "target": target,
                    "modules": module_results,
                }
            )

    def get_results(self) -> list:
        with self._lock:
            return list(self._results)

    def build_document(self, meta: dict = None, security_by_target: dict = None) -> dict:
        with self._lock:
            results = [dict(entry) for entry in self._results]

        if security_by_target:
            for entry in results:
                analysis = security_by_target.get(entry["target"])
                if analysis is not None:
                    entry["security_analysis"] = analysis

        return {
            "tool": "OxSMB",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "meta": meta or {},
            "results": results,
        }

    def write(self, meta: dict = None, security_by_target: dict = None):
        document = self.build_document(meta, security_by_target=security_by_target)
        serialized = json.dumps(document, indent=2, ensure_ascii=False)
        if self.output_path:
            with open(self.output_path, "w", encoding="utf-8") as handle:
                handle.write(serialized)
        else:
            sys.stdout.write(serialized + "\n")

    def to_string(self, meta: dict = None, security_by_target: dict = None) -> str:
        return json.dumps(self.build_document(meta, security_by_target=security_by_target), indent=2, ensure_ascii=False)
