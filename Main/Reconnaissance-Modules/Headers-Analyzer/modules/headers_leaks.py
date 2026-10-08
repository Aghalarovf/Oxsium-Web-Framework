import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Pattern, Tuple
from urllib.parse import urlparse

from .base import BaseHeaderModule
from core.engine import ModuleResult, SEVERITY_ORDER
from core.intercept_reader import HTTPResponse


CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

NON_PRODUCTION = re.compile(
    r"\b(?:dev|develop|development|staging|stage|test|testing|qa|uat|sandbox|local|debug|preprod|pre-prod|integration)\b",
    re.IGNORECASE,
)
TRUTHY_VALUES = {"1", "true", "yes", "on", "enabled"}
FLAG_ENVIRONMENT_HEADERS = {"x-staging", "x-development-mode"}

SKIP_VALUE_SCAN = {
    "set-cookie", "date", "expires", "last-modified", "etag", "content-length", "content-type",
    "content-encoding", "content-language", "cache-control", "age", "vary", "accept-ranges",
    "connection", "keep-alive", "transfer-encoding", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "x-xss-protection", "referrer-policy", "permissions-policy", "pragma",
    "content-range", "content-md5", "digest", "www-authenticate", "proxy-authenticate",
}
URL_HEADERS = {
    "location", "content-location", "link", "refresh", "content-security-policy",
    "content-security-policy-report-only", "report-to", "reporting-endpoints", "nel", "x-sourcemap",
    "sourcemap", "access-control-allow-origin", "alt-svc", "content-disposition", "x-original-url",
    "x-rewrite-url",
}
PUBLIC_IP_NAME_HINTS = (
    "host", "server", "backend", "upstream", "origin", "node", "ip", "addr", "client",
    "remote", "forward", "real", "pod", "instance",
)

REFLECTION_REQUEST_HEADERS = (
    "x-forwarded-host", "x-host", "x-forwarded-server", "x-original-host", "x-http-host-override", "forwarded",
)
REFLECTION_SKIP_RESPONSE = {"vary", "access-control-allow-headers", "access-control-expose-headers"}
MIN_REFLECTED_LENGTH = 4

IPV4_TOKEN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)")


@dataclass(frozen=True)
class HeaderRule:
    category: str
    severity: str
    detail: str
    names: frozenset
    prefixes: Tuple[str, ...]
    show_value: bool
    mask: bool
    environment: bool
    ignore_values: frozenset


def _rule(category: str, severity: str, detail: str, names=(), prefixes=(), show_value: bool = True,
          mask: bool = False, environment: bool = False, ignore=()) -> HeaderRule:
    return HeaderRule(category, severity, detail, frozenset(names), tuple(prefixes), show_value, mask, environment, frozenset(ignore))


RULES: List[HeaderRule] = [
    _rule(
        "debug", HIGH,
        "Debug or error detail header exposed; it can reveal source paths, queries, stack traces and request internals",
        names=(
            "x-debug-token-link", "x-debug-exception", "x-debug-exception-message", "x-debug-exception-stack",
            "x-debug-error", "x-debug-path", "x-debug-info", "x-dump-data", "x-dump-detail", "x-error-url",
            "x-error-message", "x-exception", "x-exception-message", "x-stack-trace", "x-stacktrace",
            "x-sql-query", "x-sql", "x-query", "x-db-query", "x-last-query", "x-database", "x-db-host",
            "x-db-name", "x-db-user", "x-trace-url", "x-php-error", "x-xdebug-profile-filename",
        ),
    ),
    _rule(
        "debug", HIGH,
        "Debug or profiler switch/identifier exposed; debug tooling appears to be enabled and may serve request profiles",
        names=(
            "x-debug", "x-debug-token", "x-dump", "x-debug-mode", "x-profiler", "x-profile", "x-symfony-debug",
            "x-miniprofiler-ids", "x-debugbar-id", "phpdebugbar-id",
        ),
        prefixes=("x-debug-", "x-dump-"),
        show_value=False,
    ),
    _rule(
        "credentials", CRITICAL,
        "Secret or private key material returned in a response header; it must be rotated and removed from responses",
        names=(
            "x-api-secret", "x-secret", "x-secret-key", "x-client-secret", "x-admin-secret", "x-hasura-admin-secret",
            "x-amz-security-token", "x-password", "x-passwd", "x-private-key", "x-signing-key", "x-encryption-key",
            "x-master-key", "x-app-secret", "x-shared-secret", "x-origin-verify", "x-webhook-secret",
            "x-db-password", "x-database-password",
        ),
        mask=True,
    ),
    _rule(
        "credentials", HIGH,
        "Credential-bearing header returned in the response; tokens and keys can be cached, logged or captured by intermediaries",
        names=(
            "x-api-key", "x-apikey", "x-auth-key", "x-access-key", "x-access-token", "x-auth-token", "x-session-token",
            "x-session-id", "x-token", "x-jwt", "x-jwt-token", "x-user-token", "x-refresh-token", "x-admin-token",
            "x-service-token", "x-bearer-token", "authorization", "proxy-authorization", "x-amzn-oidc-data",
            "x-amzn-oidc-accesstoken", "x-auth-request-access-token", "x-forwarded-access-token",
        ),
        mask=True,
    ),
    _rule(
        "exposed-service", HIGH,
        "Header characteristic of an exposed infrastructure API (Kubernetes, Consul, etcd, Nomad); the management interface appears reachable",
        names=("x-raft-index", "x-nomad-index", "x-nomad-knownleader", "x-nomad-lastcontact"),
        prefixes=("x-kubernetes-", "x-consul-", "x-etcd-"),
        show_value=False,
    ),
    _rule(
        "exposed-service", MEDIUM,
        "Header characteristic of an exposed internal service or admin tool; it fingerprints the product and may reveal its version or ports",
        names=(
            "x-application-context", "x-jenkins", "x-jenkins-session", "x-jenkins-cli-port", "x-jenkins-agent-port",
            "x-hudson", "x-hudson-cli-port", "x-ssh-endpoint", "x-instance-identity", "docker-distribution-api-version",
            "docker-content-digest", "x-elastic-product", "x-couchdb-body-time", "x-influxdb-version", "x-influxdb-build",
            "x-magento-cache-debug",
        ),
        prefixes=("fastly-debug-",),
    ),
    _rule(
        "topology", MEDIUM,
        "Internal topology header exposed; it can reveal backend hostnames, node or pod names and infrastructure layout",
        names=(
            "x-internal", "x-internal-host", "x-internal-ip", "x-internal-server", "x-backend", "x-backend-server",
            "x-backend-host", "x-backend-url", "x-upstream", "x-upstream-addr", "x-upstream-server", "x-upstream-host",
            "x-real-server", "x-origin-server", "x-origin-host", "x-origin-ip", "x-server-name", "x-server-host",
            "x-server-id", "x-server-ip", "x-server-address", "x-node", "x-node-name", "x-node-id", "x-pod",
            "x-pod-name", "x-pod-ip", "x-host", "x-hostname", "x-app-server", "x-web-server", "x-instance",
            "x-instance-id", "x-container-id", "x-cluster", "x-cluster-name", "x-datacenter", "x-dc", "x-machine",
            "x-machine-name", "x-worker", "x-worker-id", "x-forwarded-server", "x-nginx-upstream", "x-real-host",
            "x-private-ip", "x-local-ip",
        ),
        prefixes=("x-internal-", "x-backend-", "x-upstream-", "x-origin-"),
    ),
    _rule(
        "environment", MEDIUM,
        "Environment or configuration header exposed; it reveals the deployment stage and configuration details",
        names=(
            "x-env", "x-environment", "x-app-env", "x-app-environment", "x-stage", "x-staging", "x-development-mode",
            "x-deployment-env", "x-runtime-env", "x-node-env", "x-rails-env", "x-config", "x-settings",
        ),
        prefixes=("x-env-", "x-config-", "x-settings-"),
        environment=True,
    ),
    _rule(
        "identity", MEDIUM,
        "Identity or authorization context header exposed; it can leak user, tenant, role or account identifiers",
        names=(
            "x-user", "x-user-id", "x-userid", "x-user-name", "x-username", "x-user-email", "x-user-role", "x-user-roles",
            "x-role", "x-roles", "x-permissions", "x-account-id", "x-tenant-id", "x-tenant", "x-customer-id", "x-org-id",
            "x-organization-id", "x-auth-user", "x-remote-user", "x-forwarded-user", "x-forwarded-email",
            "x-forwarded-groups", "x-forwarded-preferred-username", "x-authenticated-userid", "x-authenticated-scope",
            "x-consumer-id", "x-consumer-username", "x-consumer-custom-id", "x-credential-identifier",
            "x-auth-request-user", "x-auth-request-email", "x-auth-request-groups", "x-ms-client-principal",
            "x-ms-client-principal-name", "x-ms-client-principal-id", "x-amzn-oidc-identity", "x-ausername",
        ),
        prefixes=("x-hasura-",),
        ignore=("anonymous",),
    ),
    _rule(
        "version", LOW,
        "Version header exposed; exact versions let an attacker match known vulnerabilities and outdated API versions",
        names=(
            "x-version", "x-api-version", "x-app-version", "x-build-version", "x-software-version", "x-release",
            "x-release-version", "x-api-release", "x-service-version", "x-server-version", "x-framework-version",
            "x-aspnetmvc-version", "x-aspnetwebpages-version",
        ),
    ),
    _rule(
        "build", LOW,
        "Commit, revision or build identifier exposed; it pins the exact deployed code and deployment history",
        names=(
            "x-commit", "x-commit-id", "x-commit-sha", "x-git-commit", "x-git-sha", "x-git-hash", "x-git-branch",
            "x-git-tag", "x-revision", "x-build", "x-build-id", "x-build-number", "x-build-sha", "x-build-time",
            "x-source-version", "x-deploy-id", "x-deployment-id",
        ),
    ),
    _rule(
        "tracing", LOW,
        "Trace baggage header returned in the response; it can carry environment, release and tracing credentials",
        names=("baggage", "sentry-trace"),
    ),
    _rule(
        "tracing", INFO,
        "Request, trace or correlation identifier exposed; its format can reveal the tracing stack and internal request flow",
        names=(
            "x-request-id", "x-correlation-id", "x-trace-id", "x-trace", "x-span-id", "x-b3-traceid", "x-b3-spanid",
            "x-b3-parentspanid", "x-b3-sampled", "b3", "traceparent", "tracestate", "x-amzn-trace-id", "x-amzn-requestid",
            "x-cloud-trace-context", "x-datadog-trace-id", "x-datadog-parent-id", "uber-trace-id", "request-id",
            "x-request-start", "x-queue-start", "x-vcap-request-id", "x-ot-span-context",
        ),
        prefixes=("x-correlation-", "x-trace-", "x-b3-"),
        show_value=False,
    ),
    _rule(
        "timing", LOW,
        "Timing or performance header exposed; it enables timing side channels and can reveal backend components and latency",
        names=(
            "server-timing", "x-response-time", "x-runtime", "x-processing-time", "x-elapsed-time", "x-request-duration",
            "x-page-generation-time", "x-envoy-upstream-service-time", "x-kong-upstream-latency",
            "x-kong-proxy-latency", "x-timer",
        ),
        show_value=False,
    ),
    _rule(
        "forwarding", LOW,
        "Proxy or client-IP header returned in the response; it can reveal the proxy chain and how client addresses are trusted",
        names=(
            "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port", "x-forwarded-scheme",
            "x-real-ip", "x-client-ip", "x-cluster-client-ip", "true-client-ip", "cf-connecting-ip", "x-originating-ip",
            "x-remote-ip", "x-remote-addr", "x-remote-host", "forwarded", "x-original-forwarded-for",
            "x-envoy-external-address",
        ),
    ),
    _rule(
        "cache-metadata", MEDIUM,
        "Cache debug header exposed; it reveals cache keys, tags or internal routing used by the caching layer",
        names=("x-cache-debug",),
    ),
    _rule(
        "cache-metadata", LOW,
        "Cache tag or surrogate key header exposed; tags often embed entity identifiers and internal object names",
        names=("surrogate-key", "x-cache-tags", "x-cache-keys", "x-magento-tags", "x-drupal-cache-tags"),
    ),
    _rule(
        "cloud", LOW,
        "User-defined object metadata served from cloud storage; custom metadata often contains internal names or identifiers",
        prefixes=("x-amz-meta-", "x-goog-meta-", "x-ms-meta-"),
    ),
    _rule(
        "cloud", INFO,
        "Cloud or CDN fingerprint header exposed; it identifies the provider, storage service or edge node",
        names=(
            "x-amz-id-2", "x-amz-request-id", "x-amz-cf-id", "x-amz-cf-pop", "x-amz-bucket-region", "x-amz-version-id",
            "x-azure-ref", "x-ms-request-id", "x-ms-version", "x-ms-blob-type", "x-goog-generation",
            "x-goog-metageneration", "x-guploader-uploadid", "x-served-by",
        ),
        show_value=False,
    ),
]


NAME_INDEX: Dict[str, HeaderRule] = {}
PREFIX_RULES: List[Tuple[str, HeaderRule]] = []
for _entry in RULES:
    for _name in _entry.names:
        NAME_INDEX.setdefault(_name, _entry)
    for _prefix in _entry.prefixes:
        PREFIX_RULES.append((_prefix, _entry))
PREFIX_RULES.sort(key=lambda item: -len(item[0]))


@dataclass(frozen=True)
class ValueScanner:
    key: str
    pattern: Pattern
    severity: str
    detail: str
    mask: bool = False
    token: bool = False
    skip_url_headers: bool = False
    skip_categories: Tuple[str, ...] = ()
    suppressed_by: Tuple[str, ...] = ()


VALUE_SCANNERS: Tuple[ValueScanner, ...] = (
    ValueScanner("private-key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"), CRITICAL, "Private key material in header value", mask=True),
    ValueScanner("aws-key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"), CRITICAL, "AWS access key ID in header value", mask=True),
    ValueScanner("slack-token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}"), CRITICAL, "Slack token in header value", mask=True),
    ValueScanner("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"), CRITICAL, "GitHub token in header value", mask=True),
    ValueScanner("stripe-key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}"), CRITICAL, "Stripe live key in header value", mask=True),
    ValueScanner("sendgrid-key", re.compile(r"\bSG\.[\w-]{16,}\.[\w-]{16,}"), CRITICAL, "SendGrid API key in header value", mask=True),
    ValueScanner("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), HIGH, "Google API key in header value", mask=True),
    ValueScanner(
        "url-credentials",
        re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@[^\s/]+", re.IGNORECASE),
        CRITICAL, "Credentials embedded in a URL", mask=True,
    ),
    ValueScanner(
        "connection-string",
        re.compile(r"\b(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqps?|mssql|jdbc:[a-z]+)://[^\s\"']+", re.IGNORECASE),
        HIGH, "Database or broker connection string in header value", suppressed_by=("url-credentials",),
    ),
    ValueScanner(
        "bearer-token",
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"),
        MEDIUM, "Bearer token in header value", mask=True, token=True, skip_categories=("credentials",),
    ),
    ValueScanner(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
        MEDIUM, "JWT in header value", mask=True, token=True, skip_categories=("credentials",), suppressed_by=("bearer-token",),
    ),
    ValueScanner(
        "secret-assignment",
        re.compile(
            r"\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[=:]\s*[^\s&;,\"']{4,}",
            re.IGNORECASE,
        ),
        HIGH, "Secret-like key/value pair in header value", mask=True, skip_categories=("credentials",),
    ),
    ValueScanner(
        "stack-trace",
        re.compile(
            r"Traceback \(most recent call last\)"
            r"|\bat [\w.$<>]+\([\w$.]+\.(?:java|kt|scala|cs|vb|groovy):\d+\)"
            r"|\b(?:java|javax|org|com)\.[\w.]+(?:Exception|Error)\b"
            r"|\bSystem\.\w+Exception\b"
            r"|Stack trace:"
            r"|Uncaught \w*(?:Error|Exception)"
            r"|\bat \S+ \([^)\s]+\.(?:js|ts|mjs):\d+:\d+\)"
            r"|Fatal error: .{0,120} on line \d+",
            re.IGNORECASE,
        ),
        HIGH, "Stack trace or exception detail in header value", skip_categories=("debug",),
    ),
    ValueScanner(
        "sql-error",
        re.compile(
            r"SQLSTATE\[|\bORA-\d{5}\b|You have an error in your SQL syntax|\bPG::\w+|psycopg2\.\w+"
            r"|syntax error at or near|Unclosed quotation mark|SQLite\w*Exception|mysql_(?:fetch|query|connect)\w*|\bSQL(?:Server)?Exception\b",
            re.IGNORECASE,
        ),
        HIGH, "Database error text in header value", skip_categories=("debug",),
    ),
    ValueScanner(
        "windows-path",
        re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|]{2,}|\\\\[\w.-]+\\[\w$.-]+"),
        MEDIUM, "Windows filesystem or UNC path in header value", skip_url_headers=True,
    ),
    ValueScanner(
        "unix-path",
        re.compile(r"(?<![\w:/.~-])/(?:var|usr|opt|etc|srv|root|mnt|home|Users|tmp|proc|app|workspace|build)/[\w.@/-]+"),
        MEDIUM, "Unix filesystem path in header value", skip_url_headers=True,
    ),
    ValueScanner(
        "internal-hostname",
        re.compile(r"\b(?:[a-z0-9-]+\.)+(?:internal|local|localdomain|lan|corp|intranet|private|svc)\b|\blocalhost\b", re.IGNORECASE),
        MEDIUM, "Internal hostname in header value",
    ),
    ValueScanner(
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"),
        LOW, "Email address in header value", skip_url_headers=True, skip_categories=("identity",),
    ),
)


def _display(name: str) -> str:
    return "-".join(part.capitalize() for part in name.split("-"))


def _evidence(text: str, mask: bool) -> str:
    if mask:
        return f"{text[:4]}...[{len(text)} chars]"
    return text if len(text) <= 60 else text[:57] + "..."


def _preview(value: str) -> str:
    return value if len(value) <= 80 else value[:77] + "..."


class HeaderLeakAnalysis:
    def __init__(self):
        self.findings: List[Tuple[str, str, str]] = []
        self.matched: List[Dict[str, str]] = []
        self._seen = set()

    def add(self, severity: str, header: str, detail: str) -> None:
        key = (severity, header, detail)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(key)

    def to_dict(self) -> Dict[str, Any]:
        return {"matched": self.matched, "findings": self.findings}


class HeaderLeaksModule(BaseHeaderModule):
    name = "Header Leak Analyzer"
    description = "Detects headers and header values that leak debug data, internal topology, environment details, identities, secrets and exposed services."

    def run(self, response: HTTPResponse) -> ModuleResult:
        result = ModuleResult(self.name)
        analysis = self.analyze(response)
        self._emit(analysis, result)
        result.metadata["header_leaks"] = analysis.to_dict()
        return result

    def analyze(self, response: HTTPResponse) -> HeaderLeakAnalysis:
        analysis = HeaderLeakAnalysis()
        cacheable = self._is_cacheable(response.headers)

        for name, value in response.headers.items():
            rule = self._match_rule(name)
            if rule is not None:
                self._apply_rule(name, value, rule, analysis)
            if name not in SKIP_VALUE_SCAN:
                self._scan_value(name, value, rule, cacheable, analysis)

        self._check_reflection(response, analysis)
        analysis.findings.sort(key=lambda item: (SEVERITY_ORDER.get(item[0], 99), item[1]))
        return analysis

    @staticmethod
    def _match_rule(name: str) -> Optional[HeaderRule]:
        rule = NAME_INDEX.get(name)
        if rule is not None:
            return rule
        for prefix, candidate in PREFIX_RULES:
            if name.startswith(prefix):
                return candidate
        return None

    @staticmethod
    def _is_cacheable(headers: Dict[str, str]) -> bool:
        directives = (headers.get("cache-control") or "").lower()
        return "no-store" not in directives and "private" not in directives

    def _apply_rule(self, name: str, value: str, rule: HeaderRule, analysis: HeaderLeakAnalysis) -> None:
        text = value.strip()
        if text.lower() in rule.ignore_values:
            return

        severity = rule.severity
        detail = rule.detail

        if rule.environment:
            flag_header = name in FLAG_ENVIRONMENT_HEADERS
            if flag_header and text.lower() not in TRUTHY_VALUES and not NON_PRODUCTION.search(text):
                return
            if NON_PRODUCTION.search(text) or (flag_header and text.lower() in TRUTHY_VALUES):
                severity = HIGH
                detail = detail + "; the value indicates a non-production environment reachable from outside"

        analysis.matched.append({"header": name, "category": rule.category, "severity": severity})

        if rule.mask and text:
            detail = f"{detail} (value: {_evidence(text, True)})"
        elif rule.show_value and text:
            detail = f"{detail} (value: {_preview(text)})"
        analysis.add(severity, _display(name), detail)

    def _scan_value(self, name: str, value: str, rule: Optional[HeaderRule], cacheable: bool, analysis: HeaderLeakAnalysis) -> None:
        category = rule.category if rule is not None else None
        matched_keys = set()

        for scanner in VALUE_SCANNERS:
            if scanner.skip_url_headers and name in URL_HEADERS:
                continue
            if category is not None and category in scanner.skip_categories:
                continue
            if any(key in matched_keys for key in scanner.suppressed_by):
                continue
            match = scanner.pattern.search(value)
            if not match:
                continue
            matched_keys.add(scanner.key)

            severity = scanner.severity
            detail = f"{scanner.detail} ({_evidence(match.group(0), scanner.mask)})"
            if scanner.token and cacheable:
                severity = HIGH
                detail += "; the response is cacheable"
            analysis.add(severity, _display(name), detail)

        self._scan_addresses(name, value, category, analysis)

    def _scan_addresses(self, name: str, value: str, category: Optional[str], analysis: HeaderLeakAnalysis) -> None:
        internal: List[str] = []
        public: List[str] = []
        for token in IPV4_TOKEN.findall(value):
            try:
                address = ipaddress.IPv4Address(token)
            except ValueError:
                continue
            if address.is_private or address.is_loopback or address.is_link_local:
                if token not in internal:
                    internal.append(token)
            elif address.is_global and token not in public:
                public.append(token)

        if internal:
            analysis.add(MEDIUM, _display(name), f"Internal IPv4 address in header value ({', '.join(internal[:3])})")

        if public and category != "forwarding" and self._public_ip_is_relevant(name):
            analysis.add(LOW, _display(name), f"Public IPv4 address in header value; it may be an origin or backend address that bypasses the CDN or WAF ({', '.join(public[:3])})")

    @staticmethod
    def _public_ip_is_relevant(name: str) -> bool:
        if name in ("via", "forwarded"):
            return True
        return name.startswith("x-") and any(hint in name for hint in PUBLIC_IP_NAME_HINTS)

    def _check_reflection(self, response: HTTPResponse, analysis: HeaderLeakAnalysis) -> None:
        request_headers = response.request_headers
        request_host = (request_headers.get("host") or urlparse(response.url).netloc or "").lower()

        for header in REFLECTION_REQUEST_HEADERS:
            raw = request_headers.get(header)
            if not raw:
                continue
            for candidate in self._host_candidates(header, raw):
                if len(candidate) < MIN_REFLECTED_LENGTH or candidate in request_host:
                    continue
                for response_name, response_value in response.headers.items():
                    if response_name in REFLECTION_SKIP_RESPONSE:
                        continue
                    if candidate in response_value.lower():
                        analysis.add(
                            HIGH,
                            _display(response_name),
                            f"Request header {_display(header)} is reflected in this response header; host header injection can lead to cache poisoning and poisoned redirects or reset links",
                        )

    @staticmethod
    def _host_candidates(header: str, raw: str) -> List[str]:
        if header == "forwarded":
            return [item.strip('"').lower() for item in re.findall(r"host=([^;,\s]+)", raw, re.IGNORECASE)]
        return [item.strip().lower() for item in raw.split(",") if item.strip()]

    def _emit(self, analysis: HeaderLeakAnalysis, result: ModuleResult) -> None:
        if not analysis.findings:
            result.add_finding("OK", "Header Leaks", "No leaking headers or sensitive header values detected")
            return
        for severity, header, detail in analysis.findings:
            result.add_finding(severity, header, detail)