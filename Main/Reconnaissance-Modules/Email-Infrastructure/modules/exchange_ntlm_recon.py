import re
import json
import asyncio
import base64
import struct
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp

from .base import BaseEmailModule


_CVE_DB_PATH = Path(__file__).parent / "exchange_cve_db.json"


def _load_cve_db() -> dict:
    try:
        with open(_CVE_DB_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {"builds": [], "cve_details": {}, "meta": {}}


_CVE_DB: dict = _load_cve_db()


def _parse_build_tuple(build_str: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in build_str.strip().split("."))
    except Exception:
        return ()


def _days_old(release_date_str: str) -> int | None:
    try:
        rd = date.fromisoformat(release_date_str)
        return (date.today() - rd).days
    except Exception:
        return None


def lookup_exchange_version(build_str: str) -> dict[str, Any]:
    builds: list[dict] = _CVE_DB.get("builds", [])
    cve_details: dict = _CVE_DB.get("cve_details", {})
    meta: dict = _CVE_DB.get("meta", {})

    detected = _parse_build_tuple(build_str)
    if not detected:
        return {}

    matched_build: dict | None = None
    for entry in builds:
        if _parse_build_tuple(entry.get("build", "")) == detected:
            matched_build = entry
            break

    if matched_build is None:
        return {}

    latest_build_str = meta.get("latest_se_build") or (builds[0]["build"] if builds else "")
    latest = _parse_build_tuple(latest_build_str)
    current = detected
    is_latest = current == latest

    days = _days_old(matched_build.get("release_date", ""))

    cves_on_build: list[str] = matched_build.get("cves", [])
    enriched_cves: list[dict] = []
    for cve_id in cves_on_build:
        detail = cve_details.get(cve_id, {})
        enriched_cves.append({
            "id": cve_id,
            "title": detail.get("title", ""),
            "cvss": detail.get("cvss"),
            "severity": detail.get("severity", ""),
            "type": detail.get("type", ""),
            "auth_required": detail.get("auth_required"),
            "exploited_in_wild": detail.get("exploited_in_wild", False),
            "description": detail.get("description", ""),
            "references": detail.get("references", []),
        })

    enriched_cves.sort(key=lambda c: c.get("cvss") or 0.0, reverse=True)

    versions_behind = 0
    found_self = False
    for entry in builds:
        if not found_self:
            if _parse_build_tuple(entry.get("build", "")) == detected:
                found_self = True
            else:
                versions_behind += 1
        else:
            break

    return {
        "label":           matched_build.get("label", ""),
        "build":           matched_build.get("build", ""),
        "release_date":    matched_build.get("release_date", ""),
        "kb":              matched_build.get("kb", ""),
        "is_latest":       is_latest,
        "versions_behind": versions_behind,
        "days_old":        days,
        "cve_count":       len(cves_on_build),
        "cves":            enriched_cves,
    }


_NTLM_TYPE1 = (
    b"NTLMSSP\x00"
    b"\x01\x00\x00\x00"
    b"\x07\x82\x08\xa2"
    b"\x00" * 24
)

_NTLM_AVID = {
    0x0001: "ntlm:nb_computer_name",
    0x0002: "ntlm:nb_domain_name",
    0x0003: "ntlm:dns_computer_name",
    0x0004: "ntlm:dns_domain_name",
    0x0005: "ntlm:dns_tree_name",
}


def _parse_ntlm_type2(token_b64: str) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        data = base64.b64decode(token_b64)
    except Exception:
        return result

    if len(data) < 56 or data[:8] != b"NTLMSSP\x00":
        return result
    if struct.unpack_from("<I", data, 8)[0] != 2:
        return result

    target_len    = struct.unpack_from("<H", data, 12)[0]
    target_offset = struct.unpack_from("<I", data, 16)[0]
    if target_offset == 0:
        target_offset = 48
    if target_offset + target_len <= len(data) and target_len:
        try:
            result["ntlm:target_name"] = data[target_offset:target_offset + target_len].decode("utf-16-le", errors="replace").strip("\x00")
        except Exception:
            pass

    if len(data) < 48:
        return result

    info_len    = struct.unpack_from("<H", data, 40)[0]
    info_offset = struct.unpack_from("<I", data, 44)[0]

    if info_offset + info_len > len(data) or not info_len:
        return result

    pos = info_offset
    end = info_offset + info_len
    while pos + 4 <= end:
        av_id  = struct.unpack_from("<H", data, pos)[0]
        av_len = struct.unpack_from("<H", data, pos + 2)[0]
        pos += 4
        if pos + av_len > end:
            break
        if av_id == 0x0000:
            break
        label = _NTLM_AVID.get(av_id)
        if label and av_len:
            try:
                value = data[pos:pos + av_len].decode("utf-16-le", errors="replace").strip("\x00")
                if value:
                    result[label] = value
            except Exception:
                pass
        pos += av_len

    return result


_OWA_PATTERNS = re.compile(
    r"(/owa/|/ecp/|/autodiscover/|/mapi/|/ews/|/rpc/|/oab/|/activesync)",
    re.IGNORECASE,
)

_FINGERPRINT_PATHS = [
    "/owa/auth/logon.aspx",
    "/owa/auth/expiredpassword.aspx",
    "/owa/auth/errorFE.aspx",
    "/owa/",
    "/ecp/",
    "/aspnet_client/",
    "/cscp/",
    "/_vti_bin/authentication.asmx",
    "/_vti_bin/lists.asmx",
    "/_api/web",
    "/sites/",
]

_AUTH_PROBE_PATHS = [
    "/EWS/Exchange.asmx",
    "/EWS/Services.wsdl",
    "/PowerShell/",
    "/Autodiscover/Autodiscover.xml",
    "/Rpc/",
    "/mapi/",
    "/OAB/",
    "/autodiscover/autodiscover.xml",
    "/Microsoft-Server-ActiveSync",
    "/rpc/rpcproxy.dll",
    "/mapi/nspi/",
    "/mapi/emsmdb/",
    "/adfs/services/trust/mex",
    "/adfs/ls/",
    "/adfs/oauth2/authorize",
    "/autodiscover/autodiscover.svc",
    "/autodiscover/autodiscover.svc/mex",
    "/webticket/webticketservice.svc",
    "/owa/auth/owaauth.dll",
    "/exchange/",
    "/exchweb/",
]

_MAPI_PROBE_PATHS = [
    "/mapi/",
    "/mapi/nspi/",
    "/mapi/emsmdb/",
]

_EWS_SOAP_BODY = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
    "<soap:Body>"
    '<GetServerTimeZones xmlns="http://schemas.microsoft.com/exchange/services/2006/messages">'
    "<ReturnFullTimeZoneData>false</ReturnFullTimeZoneData>"
    "</GetServerTimeZones>"
    "</soap:Body>"
    "</soap:Envelope>"
)

_AUTODISCOVER_XML_BODY = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">'
    "<Request>"
    "<EMailAddress>autodiscover@autodiscover.invalid</EMailAddress>"
    "<AcceptableResponseSchema>"
    "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a"
    "</AcceptableResponseSchema>"
    "</Request>"
    "</Autodiscover>"
)

_AUTODISCOVER_V2_PATH = "/autodiscover/autodiscover.json"
_AUTODISCOVER_WELLKNOWN_PATH = "/.well-known/autodiscover.json"

_EDISCOVERY_PATH = "/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application"

_EDISCOVERY_VERSION_RE = re.compile(
    r'assemblyIdentity[^>]*?version="([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"',
    re.IGNORECASE | re.DOTALL,
)
_EDISCOVERY_NAME_RE = re.compile(
    r'assemblyIdentity[^>]*?name="([^"]+)"',
    re.IGNORECASE | re.DOTALL,
)

_HEADER_PATTERNS: dict[str, re.Pattern] = {
    "X-OWA-Version":                    re.compile(r"[\d.]+"),
    "X-AspNet-Version":                 re.compile(r"[\d.]+"),
    "X-AspNetMvc-Version":              re.compile(r"[\d.]+"),
    "Server":                           re.compile(r".+"),
    "X-FEServer":                       re.compile(r".+"),
    "X-BEServer":                       re.compile(r".+"),
    "X-DiagInfo":                       re.compile(r".+"),
    "X-Powered-By":                     re.compile(r".+"),
    "X-MS-Diagnostics":                 re.compile(r".+"),
    "X-CalculatedBETarget":             re.compile(r".+"),
    "X-MS-BackOffice":                  re.compile(r".+"),
    "X-BackEndCookie":                  re.compile(r".+"),
    "X-RequestId":                      re.compile(r".+"),
    "X-ClientRequestId":                re.compile(r".+"),
    "X-ServerApplication":              re.compile(r"Exchange/[\d.]+"),
    "X-WSSecurity-For":                 re.compile(r".+"),
    "Persistent-Auth":                  re.compile(r".+"),
    "WWW-Authenticate":                 re.compile(r".+"),
    "Set-Cookie":                       re.compile(r".+"),
    "X-MS-Exchange-Organization-SCL":   re.compile(r".+"),
    "X-MS-Exchange-Organization-AVStamp-Mailbox": re.compile(r".+"),
}

_BODY_PATTERNS: dict[str, re.Pattern] = {
    "X-FEServer":        re.compile(r"X-FEServer\s+([A-Za-z0-9\-_.]+)"),
    "X-BEServer":        re.compile(r"X-BEServer\s+([A-Za-z0-9\-_.]+)"),
    "X-OWA-Version":     re.compile(r"X-OWA-Version[\":\s]+([0-9.]+)"),
    "X-AspNet-Version":  re.compile(r"X-AspNet-Version[\":\s]+([0-9.]+)"),
    "Server":            re.compile(r"(?:Server|server)[\":\s]+(Microsoft[^\s<\"]+|IIS[^\s<\"]+)"),
    "build_version":     re.compile(r"(?:build|version)[\":\s]+([0-9]{1,2}\.[0-9.]{3,})"),
    "error_server":      re.compile(r"(?:MBX|CAS|FE|BE)[0-9]{1,3}-[A-Z]{1,4}[0-9]{1,3}"),
    "internal_hostname": re.compile(r"\b([A-Z]{2,12}[0-9]{2,3}-[A-Z]{1,5}[0-9]{1,3})\b"),
    "owa_build_label":   re.compile(r"owa/auth/([0-9.]+)/"),
    "product_version":   re.compile(r"(?:Microsoft Exchange Server\s+)([0-9A-Za-z\s]+?)(?:<|\"|\n)"),
    "ServerVersionInfo": re.compile(r'MajorVersion="(\d+)".*?MinorVersion="(\d+)".*?MajorBuildNumber="(\d+)"', re.DOTALL),
    "dc_fqdn":           re.compile(r"<AD>([a-zA-Z0-9.\-]+)</AD>"),
    "oab_url":           re.compile(r"<OABUrl>(https?://[^<]+)</OABUrl>"),
    "exchange_guid":     re.compile(r"<Server>([0-9a-fA-F\-]{36})</Server>"),
    "internal_ip":       re.compile(r'realm="(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"'),
    "x_server_app":      re.compile(r"Exchange/(\d+\.\d+\.\d+\.\d+)"),
    "sid_cookie":        re.compile(r"(S-1-5-21-\d+-\d+-\d+)"),
}

_AUTH_METHODS = ["Basic", "NTLM", "Negotiate", "Kerberos", "Digest"]


def _extract_owa_urls(exchange_findings: list[dict]) -> list[str]:
    urls: list[str] = []
    for f in exchange_findings:
        for u in f.get("exposed_urls", []):
            if _OWA_PATTERNS.search(u):
                urls.append(u)
    return list(dict.fromkeys(urls))


def _base_hosts(base_urls: list[str], domain: str) -> list[str]:
    hosts: list[str] = [f"https://{domain}"]
    for u in base_urls:
        p = urlparse(u)
        base = f"{p.scheme}://{p.netloc}"
        if base not in hosts:
            hosts.append(base)
    return hosts


def _detect_auth(status: int, www_auth: str) -> tuple[bool, str]:
    if status == 401:
        wa = www_auth.lower()
        for method in _AUTH_METHODS:
            if method.lower() in wa:
                return True, method
        return True, "Unknown"
    return False, ""


class ExchangeNtlmReconModule(BaseEmailModule):

    NAME        = "exchange_ntlm_recon"
    DESCRIPTION = "Exchange OWA/ECP fingerprinting + auth-required endpoint detection"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._findings: list[dict[str, Any]] = []

    def _add_finding(self, **finding: Any) -> None:
        self._findings.append(finding)

    async def run(self, domain: str, exchange_findings: list[dict] | None = None) -> dict:
        self._findings = []
        self._domain   = domain
        self._logger.section(f"[{self.NAME.upper()}] {self.DESCRIPTION}")

        owa_urls = _extract_owa_urls(exchange_findings or [])
        hosts    = _base_hosts(owa_urls, domain)

        fingerprint_urls = [h + p for h in hosts for p in _FINGERPRINT_PATHS]
        auth_probe_urls  = [h + p for h in hosts for p in _AUTH_PROBE_PATHS]

        fingerprint_urls = list(dict.fromkeys(fingerprint_urls))
        auth_probe_urls  = list(dict.fromkeys(auth_probe_urls))

        ediscovery_urls      = list(dict.fromkeys([h + _EDISCOVERY_PATH for h in hosts]))
        autodiscover_xml_urls = list(dict.fromkeys([h + "/autodiscover/autodiscover.xml" for h in hosts]))
        ews_soap_urls         = list(dict.fromkeys([h + "/EWS/Exchange.asmx" for h in hosts]))
        mapi_urls             = list(dict.fromkeys([h + p for h in hosts for p in _MAPI_PROBE_PATHS]))
        autodiscover_v2_urls  = list(dict.fromkeys(
            [h + _AUTODISCOVER_V2_PATH for h in hosts]
            + [h + _AUTODISCOVER_WELLKNOWN_PATH for h in hosts]
        ))

        self._logger.info(
            f"[NTLM-Recon] {len(fingerprint_urls)} fingerprint probe(s) + "
            f"{len(auth_probe_urls)} auth probe(s) + "
            f"{len(ediscovery_urls)} eDiscovery probe(s) + "
            f"{len(autodiscover_xml_urls)} autodiscover XML probe(s) + "
            f"{len(ews_soap_urls)} EWS SOAP probe(s) + "
            f"{len(mapi_urls)} MAPI probe(s) + "
            f"{len(autodiscover_v2_urls)} autodiscover v2 probe(s) "
            f"across {len(hosts)} host(s)"
        )

        await asyncio.gather(
            *[self._probe_fingerprint(url) for url in fingerprint_urls],
            *[self._probe_auth(url) for url in auth_probe_urls],
            *[self._probe_ediscovery(url) for url in ediscovery_urls],
            *[self._probe_autodiscover_xml(url) for url in autodiscover_xml_urls],
            *[self._probe_ews_soap(url) for url in ews_soap_urls],
            *[self._probe_mapi_connect(url) for url in mapi_urls],
            *[self._probe_autodiscover_v2(url, domain) for url in autodiscover_v2_urls],
        )

        self._findings = self._dedup(self._findings)
        self._print_summary()
        summary = self._build_consolidated_summary()
        return {
            "findings": self._findings,
            "summary": {
                "builds": {
                    build: {
                        "label":           vi.get("label"),
                        "build":           vi.get("build"),
                        "release_date":    vi.get("release_date"),
                        "kb":              vi.get("kb"),
                        "days_old":        vi.get("days_old"),
                        "versions_behind": vi.get("versions_behind"),
                        "is_latest":       vi.get("is_latest"),
                        "cves": [
                            {
                                "id":               c["id"],
                                "title":            c.get("title"),
                                "cvss":             c.get("cvss"),
                                "severity":         c.get("severity"),
                                "type":             c.get("type"),
                                "auth_required":    c.get("auth_required"),
                                "exploited_in_wild": c.get("exploited_in_wild"),
                            }
                            for c in vi.get("cves", [])
                        ],
                    }
                    for build, vi in summary["builds"].items()
                },
                "ntlm_disclosures": summary["ntlm"],
                "endpoints": [
                    {
                        "source":      ep["source"],
                        "path":        ep["path"],
                        "http_status": ep["status"],
                        "auth":        ep["auth"],
                        "severity":    ep["severity"],
                        "unique_disclosures": {
                            k: v for k, v in ep["disclosures"].items()
                            if not k.startswith("ntlm:")
                        },
                    }
                    for ep in summary["endpoints"]
                ],
            },
        }

    async def _probe_fingerprint(self, url: str) -> None:
        session = await self._get_raw_session()
        try:
            async with session.get(url, allow_redirects=True, ssl=False) as resp:
                headers = dict(resp.headers)
                try:
                    body = await resp.text(errors="replace")
                except Exception:
                    body = ""

                extracted = self._extract_all(headers, body)
                if extracted:
                    self._logger.info(
                        f"[NTLM-Recon] {url} → HTTP {resp.status} | "
                        f"{len(extracted)} disclosure(s)"
                    )
                    for key, value in extracted.items():
                        self._logger.info(f"[NTLM-Recon]   {key}: {value}")
                    version_info = self._check_build_in_disclosures(url, extracted)
                    self._add_finding(
                        source="owa_fingerprint",
                        url=url,
                        path=urlparse(url).path,
                        http_status=resp.status,
                        disclosures=extracted,
                        severity=self._fp_severity(extracted),
                        version_info=version_info,
                    )
                else:
                    self._logger.info(f"[NTLM-Recon] {url} → HTTP {resp.status} | no disclosures")
        except Exception as exc:
            self._logger.warning(f"[NTLM-Recon] {url} → {exc}")

    async def _probe_auth(self, url: str) -> None:
        session = await self._get_raw_session()
        try:
            async with session.get(url, allow_redirects=False, ssl=False) as resp:
                www_auth  = resp.headers.get("WWW-Authenticate", "")
                auth_req, auth_type = _detect_auth(resp.status, www_auth)

                headers = dict(resp.headers)
                try:
                    body = await resp.text(errors="replace")
                except Exception:
                    body = ""
                disclosures = self._extract_all(headers, body)

                if auth_req:
                    ntlm_info: dict[str, str] = {}
                    if auth_type in ("NTLM", "Negotiate"):
                        ntlm_info = await self._ntlm_challenge(url, session)
                        disclosures.update(ntlm_info)

                    self._logger.info(
                        f"[NTLM-Recon] {url} → HTTP {resp.status} | "
                        f"Auth Required ({auth_type})"
                        + (f" | {len(disclosures)} disclosure(s)" if disclosures else "")
                    )
                    if ntlm_info:
                        for key, value in ntlm_info.items():
                            self._logger.info(f"[NTLM-Recon]   {key}: {value}")

                    version_info = self._check_build_in_disclosures(url, disclosures)
                    self._add_finding(
                        source="auth_endpoint",
                        url=url,
                        path=urlparse(url).path,
                        http_status=resp.status,
                        auth_required=True,
                        auth_type=auth_type,
                        www_authenticate=www_auth,
                        disclosures=disclosures,
                        severity="high" if disclosures else "medium",
                        version_info=version_info,
                    )
                elif resp.status == 200:
                    self._logger.info(
                        f"[NTLM-Recon] {url} → HTTP {resp.status} | Open (no auth)"
                        + (f" | {len(disclosures)} disclosure(s)" if disclosures else "")
                    )
                    if disclosures:
                        version_info = self._check_build_in_disclosures(url, disclosures)
                        self._add_finding(
                            source="auth_endpoint",
                            url=url,
                            path=urlparse(url).path,
                            http_status=resp.status,
                            auth_required=False,
                            auth_type=None,
                            www_authenticate="",
                            disclosures=disclosures,
                            severity=self._fp_severity(disclosures),
                            version_info=version_info,
                        )
                else:
                    self._logger.info(f"[NTLM-Recon] {url} → HTTP {resp.status}")
        except Exception as exc:
            self._logger.warning(f"[NTLM-Recon] {url} → {exc}")

    async def _ntlm_challenge(self, url: str, session: aiohttp.ClientSession) -> dict[str, str]:
        type1_b64 = base64.b64encode(_NTLM_TYPE1).decode()
        try:
            async with session.get(
                url,
                headers={"Authorization": f"NTLM {type1_b64}", "Connection": "keep-alive"},
                allow_redirects=False,
                ssl=False,
            ) as resp:
                www_auth = resp.headers.get("WWW-Authenticate", "")
                token = ""
                for part in www_auth.split(","):
                    part = part.strip()
                    if part.startswith("NTLM "):
                        token = part[5:].strip()
                        break
                    if part.startswith("Negotiate "):
                        token = part[10:].strip()
                        break
                if not token:
                    return {}
                parsed = _parse_ntlm_type2(token)
                if parsed:
                    self._logger.info(f"[NTLM-Recon]   NTLM Type 2 challenge parsed from {url}")
                return parsed
        except Exception:
            return {}

    async def _probe_autodiscover_xml(self, url: str) -> None:
        session = await self._get_raw_session()
        try:
            async with session.post(
                url,
                data=_AUTODISCOVER_XML_BODY,
                headers={"Content-Type": "text/xml; charset=utf-8"},
                allow_redirects=False,
                ssl=False,
            ) as resp:
                headers = dict(resp.headers)
                try:
                    body = await resp.text(errors="replace")
                except Exception:
                    body = ""
                disclosures = self._extract_all(headers, body)
                if resp.status in (200, 401) or disclosures:
                    self._logger.info(
                        f"[NTLM-Recon] {url} → HTTP {resp.status} | autodiscover XML"
                        + (f" | {len(disclosures)} disclosure(s)" if disclosures else "")
                    )
                    for key, value in disclosures.items():
                        self._logger.info(f"[NTLM-Recon]   {key}: {value}")
                    self._add_finding(
                        source="autodiscover_xml",
                        url=url,
                        path=urlparse(url).path,
                        http_status=resp.status,
                        disclosures=disclosures,
                        severity=self._fp_severity(disclosures) if disclosures else "low",
                    )
        except Exception as exc:
            self._logger.warning(f"[NTLM-Recon] {url} → {exc}")

    async def _probe_ews_soap(self, url: str) -> None:
        session = await self._get_raw_session()
        try:
            async with session.post(
                url,
                data=_EWS_SOAP_BODY,
                headers={
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": '"http://schemas.microsoft.com/exchange/services/2006/messages/GetServerTimeZones"',
                },
                allow_redirects=False,
                ssl=False,
            ) as resp:
                headers = dict(resp.headers)
                try:
                    body = await resp.text(errors="replace")
                except Exception:
                    body = ""
                disclosures = self._extract_all(headers, body)
                if resp.status in (200, 401, 500) or disclosures:
                    self._logger.info(
                        f"[NTLM-Recon] {url} → HTTP {resp.status} | EWS SOAP"
                        + (f" | {len(disclosures)} disclosure(s)" if disclosures else "")
                    )
                    for key, value in disclosures.items():
                        self._logger.info(f"[NTLM-Recon]   {key}: {value}")
                    self._add_finding(
                        source="ews_soap",
                        url=url,
                        path=urlparse(url).path,
                        http_status=resp.status,
                        disclosures=disclosures,
                        severity=self._fp_severity(disclosures) if disclosures else "low",
                    )
        except Exception as exc:
            self._logger.warning(f"[NTLM-Recon] {url} → {exc}")

    async def _probe_mapi_connect(self, url: str) -> None:
        session = await self._get_raw_session()
        try:
            async with session.post(
                url,
                headers={"X-RequestType": "Connect", "X-ClientInfo": "{ExchangeNtlmRecon}"},
                allow_redirects=False,
                ssl=False,
            ) as resp:
                headers = dict(resp.headers)
                try:
                    body = await resp.text(errors="replace")
                except Exception:
                    body = ""
                disclosures = self._extract_all(headers, body)
                x_response_code = headers.get("X-ResponseCode", "")
                x_server_app    = headers.get("X-ServerApplication", "")
                if x_response_code:
                    disclosures["X-ResponseCode"] = x_response_code
                if x_server_app:
                    disclosures["X-ServerApplication"] = x_server_app
                if resp.status in (200, 401) or disclosures:
                    self._logger.info(
                        f"[NTLM-Recon] {url} → HTTP {resp.status} | MAPI Connect"
                        + (f" | {len(disclosures)} disclosure(s)" if disclosures else "")
                    )
                    for key, value in disclosures.items():
                        self._logger.info(f"[NTLM-Recon]   {key}: {value}")
                    self._add_finding(
                        source="mapi_connect",
                        url=url,
                        path=urlparse(url).path,
                        http_status=resp.status,
                        disclosures=disclosures,
                        severity=self._fp_severity(disclosures) if disclosures else "low",
                    )
        except Exception as exc:
            self._logger.warning(f"[NTLM-Recon] {url} → {exc}")

    async def _probe_autodiscover_v2(self, url: str, domain: str) -> None:
        await self._autodiscover_v2_check(url, f"autodiscover@{domain}", tag="[NTLM-Recon]")

    async def _autodiscover_v2_check(
        self,
        base_url: str,
        email: str,
        tag: str = "[Email-Validation]",
    ) -> dict[str, object]:
        session  = await self._get_raw_session()
        protocol = "Ews"
        probe_url = f"{base_url}?Email={email}&Protocol={protocol}"
        result: dict[str, object] = {
            "email":        email,
            "url":          probe_url,
            "email_exists": False,
            "http_status":  None,
            "disclosures":  {},
        }
        try:
            async with session.get(
                probe_url,
                allow_redirects=False,
                ssl=False,
            ) as resp:
                headers = dict(resp.headers)
                try:
                    body = await resp.text(errors="replace")
                except Exception:
                    body = ""
                disclosures  = self._extract_all(headers, body)
                email_exists = resp.status == 200
                result["http_status"]  = resp.status
                result["email_exists"] = email_exists
                result["disclosures"]  = disclosures

                status_label = "EXISTS ✓" if email_exists else "not found"
                self._logger.info(
                    f"{tag} {email} → HTTP {resp.status} | {status_label}"
                    + (f" | {len(disclosures)} disclosure(s)" if disclosures else "")
                )
                for key, value in disclosures.items():
                    self._logger.info(f"{tag}   {key}: {value}")

                self._add_finding(
                    source="autodiscover_v2",
                    url=probe_url,
                    path=urlparse(probe_url).path,
                    http_status=resp.status,
                    email=email,
                    email_exists=email_exists,
                    protocol=protocol,
                    disclosures=disclosures,
                    severity="info",
                )
        except Exception as exc:
            self._logger.warning(f"{tag} {probe_url} → {exc}")
        return result

    async def run_email_validation(self, domain: str, emails: list[str]) -> dict:
        self._findings = []
        self._domain   = domain
        self._logger.section(f"[EMAIL-VALIDATION] Autodiscover v2 — {len(emails)} email(s) — no credentials, no lockout")

        owa_urls  = _extract_owa_urls([])
        hosts     = _base_hosts([], domain)
        base_urls = list(dict.fromkeys(
            [h + _AUTODISCOVER_V2_PATH for h in hosts]
            + [h + _AUTODISCOVER_WELLKNOWN_PATH for h in hosts]
        ))

        valid: list[str]   = []
        invalid: list[str] = []
        rows: list[list[str]] = []

        for email in emails:
            found = False
            for base_url in base_urls:
                result = await self._autodiscover_v2_check(base_url, email)
                if result.get("email_exists"):
                    found = True
                    break
            if found:
                valid.append(email)
            else:
                invalid.append(email)
            rows.append([email, "✓ EXISTS" if found else "✗ NOT FOUND"])

        self._logger.table(
            ["Email", "Status"],
            rows,
        )
        self._logger.info(
            f"[Email-Validation] {len(valid)} valid / {len(invalid)} not found "
            f"out of {len(emails)} tested"
        )

        return {
            "tested":    emails,
            "valid":     valid,
            "not_found": invalid,
            "findings":  self._findings,
        }

    async def _probe_ediscovery(self, url: str) -> None:
        session = await self._get_raw_session()
        try:
            async with session.get(url, allow_redirects=True, ssl=False) as resp:
                if resp.status != 200:
                    self._logger.info(f"[NTLM-Recon] {url} → HTTP {resp.status} | eDiscovery not exposed")
                    return

                try:
                    body = await resp.text(errors="replace")
                except Exception:
                    body = ""

                version_match = _EDISCOVERY_VERSION_RE.search(body)
                name_match    = _EDISCOVERY_NAME_RE.search(body)

                version = version_match.group(1) if version_match else None
                name    = name_match.group(1)    if name_match    else None

                disclosures: dict[str, str] = {}
                if version:
                    disclosures["ediscovery:exchange_build"] = version
                if name:
                    disclosures["ediscovery:assembly_name"] = name

                header_disclosures = self._extract_all(dict(resp.headers), body)
                disclosures.update(header_disclosures)

                self._logger.info(
                    f"[NTLM-Recon] {url} → HTTP {resp.status} | "
                    f"eDiscovery manifest exposed"
                    + (f" | build: {version}" if version else "")
                )
                for key, value in disclosures.items():
                    self._logger.info(f"[NTLM-Recon]   {key}: {value}")

                version_info: dict[str, Any] = {}
                if version:
                    version_info = lookup_exchange_version(version)
                    if version_info:
                        self._log_version_info(url, version_info)

                self._add_finding(
                    source="ediscovery_manifest",
                    url=url,
                    path=urlparse(url).path,
                    http_status=resp.status,
                    auth_required=False,
                    exchange_build=version,
                    assembly_name=name,
                    disclosures=disclosures,
                    severity="high",
                    version_info=version_info,
                )
        except Exception as exc:
            self._logger.warning(f"[NTLM-Recon] {url} → {exc}")

    def _log_version_info(self, url: str, vi: dict[str, Any]) -> None:
        label   = vi.get("label", "unknown")
        build   = vi.get("build", "")
        days    = vi.get("days_old")
        behind  = vi.get("versions_behind", 0)
        is_latest = vi.get("is_latest", False)

        age_str = f"{days} days old" if days is not None else "unknown age"
        latest_str = "LATEST" if is_latest else f"{behind} version(s) behind latest"

        self._logger.info(
            f"[NTLM-Recon]   Version: {label} ({build}) — {age_str} — {latest_str}"
        )

        cves = vi.get("cves", [])
        if cves:
            self._logger.warning(
                f"[NTLM-Recon]   {len(cves)} unpatched CVE(s) on this build:"
            )
            for cve in cves:
                wild = " [EXPLOITED IN WILD]" if cve.get("exploited_in_wild") else ""
                self._logger.warning(
                    f"[NTLM-Recon]     {cve['id']} CVSS:{cve.get('cvss', '?'):>4} "
                    f"[{cve.get('severity','?').upper():<8}] {cve.get('title','')}{wild}"
                )
        else:
            self._logger.info("[NTLM-Recon]   No known unpatched CVEs for this build.")

    def _check_build_in_disclosures(self, url: str, disclosures: dict[str, str]) -> dict[str, Any]:
        build_keys = (
            "X-OWA-Version",
            "body:X-OWA-Version",
            "body:build_version",
            "body:ServerVersionInfo",
            "body:x_server_app",
            "ediscovery:exchange_build",
        )
        for key in build_keys:
            build_str = disclosures.get(key, "")
            if build_str and re.match(r"^\d+\.\d+\.\d+", build_str):
                vi = lookup_exchange_version(build_str)
                if vi:
                    self._log_version_info(url, vi)
                    return vi
        return {}

    def _extract_all(self, headers: dict[str, str], body: str) -> dict[str, str]:
        found: dict[str, str] = {}

        for header_name, pattern in _HEADER_PATTERNS.items():
            raw = headers.get(header_name) or headers.get(header_name.lower())
            if raw:
                m = pattern.search(raw)
                if m:
                    found[header_name] = raw.strip()

        for label, pattern in _BODY_PATTERNS.items():
            if label in found:
                continue
            m = pattern.search(body)
            if m:
                if label == "ServerVersionInfo" and m.lastindex and m.lastindex >= 3:
                    value = f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
                elif m.lastindex and m.lastindex >= 1:
                    value = m.group(1)
                else:
                    value = m.group(0)
                found[f"body:{label}"] = value.strip()

        return found

    def _fp_severity(self, disclosures: dict[str, str]) -> str:
        keys = set(disclosures.keys())
        if any(k in keys for k in ("X-FEServer", "X-BEServer", "body:error_server", "body:internal_hostname")):
            return "high"
        if any(k in keys for k in ("X-OWA-Version", "X-AspNet-Version", "Server", "body:X-OWA-Version")):
            return "medium"
        return "low"

    def _dedup(self, findings: list[dict]) -> list[dict]:
        seen: set[str] = set()
        out:  list[dict] = []
        for f in findings:
            key = f.get("url", "") + str(sorted(f.get("disclosures", {}).items()))
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out

    def _build_consolidated_summary(self) -> dict[str, Any]:
        seen_builds: dict[str, dict] = {}
        for f in self._findings:
            vi = f.get("version_info") or {}
            build = vi.get("build", "")
            if build and build not in seen_builds:
                seen_builds[build] = vi

        all_ntlm: dict[str, set[str]] = {}
        for f in self._findings:
            for k, v in f.get("disclosures", {}).items():
                if k.startswith("ntlm:"):
                    field = k.replace("ntlm:", "")
                    all_ntlm.setdefault(field, set()).add(v)

        endpoint_rows: list[dict] = []
        for f in self._findings:
            disc = f.get("disclosures", {})
            unique_disc: dict[str, str] = {}
            for k, v in disc.items():
                if k.startswith("ntlm:"):
                    field = k.replace("ntlm:", "")
                    global_vals = all_ntlm.get(field, set())
                    if len(global_vals) > 1 or v not in global_vals:
                        unique_disc[k] = v
                else:
                    unique_disc[k] = v

            auth_type = f.get("auth_type") or ""
            auth_str  = auth_type if f.get("auth_required") else ("open" if f.get("http_status") == 200 else "")
            endpoint_rows.append({
                "source":    f.get("source", ""),
                "path":      f.get("path", ""),
                "status":    str(f.get("http_status", "")),
                "auth":      auth_str,
                "severity":  f.get("severity", ""),
                "disclosures": unique_disc,
            })

        return {
            "builds":    seen_builds,
            "ntlm":      {k: sorted(v) for k, v in all_ntlm.items()},
            "endpoints": endpoint_rows,
        }

    def _print_summary(self) -> None:
        if not self._findings:
            self._logger.warning("[NTLM-Recon] No findings.")
            return

        summary = self._build_consolidated_summary()
        builds    = summary["builds"]
        ntlm      = summary["ntlm"]
        endpoints = summary["endpoints"]

        self._logger.info("")
        self._logger.info("=" * 72)
        self._logger.info("  EXCHANGE RECON — CONSOLIDATED SUMMARY")
        self._logger.info("=" * 72)

        if builds:
            self._logger.info("")
            self._logger.info("── VERSION & CVE REPORT ─────────────────────────────────────────────")
            for build_str, vi in builds.items():
                label      = vi.get("label", build_str)
                days       = vi.get("days_old")
                behind     = vi.get("versions_behind", 0)
                is_latest  = vi.get("is_latest", False)
                kb         = vi.get("kb", "")
                age_str    = f"{days} days old" if days is not None else "unknown age"
                status_str = "LATEST" if is_latest else f"{behind} version(s) behind latest"
                self._logger.info(f"  Build : {label}  ({build_str})")
                self._logger.info(f"  KB    : {kb}   Released: {vi.get('release_date', '?')}   {age_str}   {status_str}")
                cves = vi.get("cves", [])
                if cves:
                    self._logger.warning(f"  {len(cves)} unpatched CVE(s):")
                    cve_rows = []
                    for cve in cves:
                        wild = " ⚠ EXPLOITED" if cve.get("exploited_in_wild") else ""
                        cve_rows.append([
                            cve["id"] + wild,
                            str(cve.get("cvss", "?")),
                            cve.get("severity", "?").upper(),
                            cve.get("type", ""),
                            cve.get("title", ""),
                        ])
                    self._logger.table(["CVE", "CVSS", "Severity", "Type", "Title"], cve_rows)
                else:
                    self._logger.info("  No known unpatched CVEs — build is current.")

        if ntlm:
            self._logger.info("")
            self._logger.info("── NTLM DISCLOSURES (all endpoints combined) ────────────────────────")
            ntlm_rows = []
            for field, values in sorted(ntlm.items()):
                ntlm_rows.append([field, ", ".join(values)])
            self._logger.table(["Field", "Values observed"], ntlm_rows)

        common_disc: dict[str, set[str]] = {}
        for ep in endpoints:
            for k, v in ep["disclosures"].items():
                if not k.startswith("ntlm:"):
                    common_disc.setdefault(k, set()).add(v)

        shared_keys = {k for k, vs in common_disc.items() if len(vs) == 1 and
                       sum(1 for ep in endpoints if k in ep["disclosures"]) > 1}

        if shared_keys:
            self._logger.info("")
            self._logger.info("── COMMON DISCLOSURES (same value across multiple endpoints) ────────")
            shared_rows = []
            for k in sorted(shared_keys):
                val = next(iter(common_disc[k]))
                count = sum(1 for ep in endpoints if k in ep["disclosures"])
                shared_rows.append([k, val, str(count)])
            self._logger.table(["Field", "Value", "Endpoints"], shared_rows)

        self._logger.info("")
        self._logger.info("── ENDPOINT TABLE ───────────────────────────────────────────────────")
        ep_rows = []
        for ep in endpoints:
            unique_parts = []
            for k, v in ep["disclosures"].items():
                if k.startswith("ntlm:"):
                    continue
                if k in shared_keys:
                    continue
                unique_parts.append(f"{k}={v}")
            ep_rows.append([
                ep["source"],
                ep["path"],
                ep["status"],
                ep["auth"] or "-",
                ep["severity"].upper(),
                "; ".join(unique_parts) or "-",
            ])
        self._logger.table(
            ["Source", "Path", "HTTP", "Auth", "Severity", "Unique Disclosures"],
            ep_rows,
        )

        sev: dict[str, int] = {}
        for f in self._findings:
            s = f.get("severity", "low")
            sev[s] = sev.get(s, 0) + 1
        self._logger.info("")
        self._logger.info("── SEVERITY SUMMARY ─────────────────────────────────────────────────")
        self._logger.table(
            ["Severity", "Count"],
            [[k.upper(), str(v)] for k, v in sorted(sev.items(), key=lambda x: ["critical","high","medium","low","info"].index(x[0]) if x[0] in ["critical","high","medium","low","info"] else 99)],
        )

    async def _get_raw_session(self) -> aiohttp.ClientSession:
        if not hasattr(self, "_raw_session") or self._raw_session.closed:
            self._raw_session = aiohttp.ClientSession(
                headers={"User-Agent": "Mozilla/5.0 (compatible; EmailInfraEnum/1.0)"},
                timeout=aiohttp.ClientTimeout(total=10),
                connector=aiohttp.TCPConnector(ssl=False),
            )
        return self._raw_session