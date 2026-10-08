from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from modules.base import BaseJSModule, Finding


LIB_FINGERPRINTS: list[tuple[str, re.Pattern]] = [
    ("jquery",        re.compile(r"""[Jj]Query\s*v?([\d]+\.[\d]+\.[\d]+)""")),
    ("jquery",        re.compile(r"""jquery[.-]([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js""")),
    ("react",         re.compile(r"""[Rr]eact\s+v?([\d]+\.[\d]+\.[\d]+)""")),
    ("react",         re.compile(r"""react@([\d]+\.[\d]+\.[\d]+)""")),
    ("angular",       re.compile(r"""Angular(?:JS)?\s+v?([\d]+\.[\d]+\.[\d]+)""")),
    ("angular",       re.compile(r"""angular(?:js)?[.-]([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js""")),
    ("vue",           re.compile(r"""Vue\.js\s+v([\d]+\.[\d]+\.[\d]+)""")),
    ("vue",           re.compile(r"""vue(?:\.runtime)?[.-]([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js""")),
    ("lodash",        re.compile(r"""(?:lodash|_)\s+v?([\d]+\.[\d]+\.[\d]+)""")),
    ("lodash",        re.compile(r"""lodash[.-]([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js""")),
    ("moment",        re.compile(r"""moment(?:\.js)?\s+v?([\d]+\.[\d]+\.[\d]+)""")),
    ("bootstrap",     re.compile(r"""[Bb]ootstrap\s+v([\d]+\.[\d]+\.[\d]+)""")),
    ("bootstrap",     re.compile(r"""bootstrap[.-]([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.(?:js|css)""")),
    ("axios",         re.compile(r"""axios/([\d]+\.[\d]+\.[\d]+)""")),
    ("d3",            re.compile(r"""d3\s+v([\d]+\.[\d]+\.[\d]+)""")),
    ("threejs",       re.compile(r"""three\.js\s+r(\d+)""")),
    ("prototype",     re.compile(r"""Prototype\s+JavaScript\s+framework,\s+version\s+([\d.]+)""")),
    ("mootools",      re.compile(r"""MooTools\s+([\d]+\.[\d]+\.[\d]+)""")),
]

MANIFEST_KEYS: tuple[str, ...] = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
    "bundledDependencies",
)

LOCK_VERSION_PATTERN = re.compile(
    r""""([^"]+)":\s*\{[^}]*?"version":\s*"([^"]+)"[^}]*?\}""",
    re.DOTALL,
)

OSV_BATCH_URL   = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT_SEC = 8
OSV_ECOSYSTEM   = "npm"


class DependenciesModule(BaseJSModule):

    def analyze(self, content: str, filename: str = "") -> list[Finding]:
        self.findings = []

        if filename.endswith(("package.json", "bower.json", "package-lock.json", "yarn.lock")):
            deps = self.parse_packagelock(content, filename)
            self._enrich_with_cves(deps)
        else:
            libs = self.fingerprint_libs(content)
            self._enrich_with_cves(libs)

        return self.findings

    def fingerprint_libs(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for lib_name, pattern in LIB_FINGERPRINTS:
            for match in pattern.finditer(content):
                version     = match.group(1)
                fingerprint = f"{lib_name}:{version}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                findings.append(self._finding(
                    type       = f"lib_fingerprint_{lib_name}",
                    value      = f"{lib_name}@{version}",
                    severity   = self.SEVERITY_INFO,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "library":          lib_name,
                        "version":          version,
                        "detection_method": "inline_fingerprint",
                    },
                ))

        return findings

    def parse_packagelock(self, content: str, filename: str = "package.json") -> list[Finding]:
        findings: list[Finding] = []

        try:
            manifest: dict[str, Any] = json.loads(content)
        except json.JSONDecodeError:
            return self._parse_lockfile_with_regex(content, filename)

        if "packages" in manifest:
            for pkg_path, pkg_data in manifest["packages"].items():
                if not pkg_path or not isinstance(pkg_data, dict):
                    continue
                name    = pkg_path.lstrip("node_modules/").split("/node_modules/")[-1]
                version = pkg_data.get("version", "unknown")
                findings.append(self._make_dep_finding(name, version, filename, pkg_data))
            return findings

        for section in MANIFEST_KEYS:
            deps = manifest.get(section)
            if not isinstance(deps, dict):
                continue
            for name, version_spec in deps.items():
                version = self._clean_version(str(version_spec))
                findings.append(self._make_dep_finding(name, version, filename, {
                    "section":  section,
                    "raw_spec": version_spec,
                }))

        return findings

    def query_cve_db(self, packages: list[dict[str, str]]) -> list[Finding]:
        if not packages:
            return []

        findings: list[Finding] = []

        queries = [
            {
                "version": pkg["version"],
                "package": {
                    "name":      pkg["name"],
                    "ecosystem": OSV_ECOSYSTEM,
                },
            }
            for pkg in packages
            if pkg.get("name") and pkg.get("version") and pkg["version"] != "unknown"
        ]

        if not queries:
            return []

        try:
            osv_results = self._osv_batch_query(queries)
        except Exception:
            return []

        for pkg, result in zip(packages, osv_results):
            for vuln in result.get("vulns", []):
                vuln_id  = vuln.get("id", "UNKNOWN")
                aliases  = vuln.get("aliases", [])
                summary  = vuln.get("summary", "No summary available")
                severity = self._osv_severity_to_level(vuln)
                cve_ids  = [a for a in aliases if a.startswith("CVE-")]

                findings.append(self._finding(
                    type       = "known_vulnerability",
                    value      = f"{pkg['name']}@{pkg['version']} -> {vuln_id}",
                    severity   = severity,
                    context    = summary[:256],
                    line       = 0,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "package": pkg["name"],
                        "version": pkg["version"],
                        "vuln_id": vuln_id,
                        "cve_ids": cve_ids,
                        "osv_url": f"https://osv.dev/vulnerability/{vuln_id}",
                        "summary": summary[:512],
                    },
                ))

        return findings

    def _enrich_with_cves(self, dep_findings: list[Finding]) -> None:
        packages = [
            {
                "name":    f.meta.get("library") or f.meta.get("package", ""),
                "version": f.meta.get("version", "unknown"),
            }
            for f in dep_findings
            if f.meta.get("version") and f.meta["version"] != "unknown"
        ]

        self.findings.extend(dep_findings)
        self.findings.extend(self.query_cve_db(packages))

    def _make_dep_finding(
        self,
        name: str,
        version: str,
        filename: str,
        extra_meta: dict[str, Any],
    ) -> Finding:
        return self._finding(
            type       = "dependency_detected",
            value      = f"{name}@{version}",
            severity   = self.SEVERITY_INFO,
            context    = filename,
            line       = 0,
            confidence = self.CONFIDENCE_HIGH,
            meta       = {
                "package":     name,
                "version":     version,
                "source_file": filename,
                **extra_meta,
            },
        )

    def _parse_lockfile_with_regex(self, content: str, filename: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for match in LOCK_VERSION_PATTERN.finditer(content):
            name, version = match.group(1), match.group(2)
            key = f"{name}:{version}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(self._make_dep_finding(name, version, filename, {
                "detection_method": "regex_fallback",
            }))

        return findings

    @staticmethod
    def _clean_version(spec: str) -> str:
        cleaned   = re.sub(r"^[~^>=<*]+", "", spec.strip())
        ver_match = re.match(r"[\d]+\.[\d]+(?:\.[\d]+)?", cleaned)
        return ver_match.group(0) if ver_match else cleaned or "unknown"

    @staticmethod
    def _osv_batch_query(queries: list[dict]) -> list[dict]:
        payload = json.dumps({"queries": queries}).encode()
        req     = urllib.request.Request(
            OSV_BATCH_URL,
            data    = payload,
            headers = {"Content-Type": "application/json"},
            method  = "POST",
        )
        with urllib.request.urlopen(req, timeout=OSV_TIMEOUT_SEC) as resp:
            body = json.loads(resp.read())
        return body.get("results", [{}] * len(queries))

    @staticmethod
    def _osv_severity_to_level(vuln: dict) -> str:
        for entry in vuln.get("severity", []):
            vector = entry.get("score", "")
            if "AV:N" in vector and "PR:N" in vector:
                return "critical" if "UI:N" in vector else "high"
            if vector:
                return "medium"
        if vuln.get("id", "").startswith("GHSA-"):
            return "high"
        return "medium"