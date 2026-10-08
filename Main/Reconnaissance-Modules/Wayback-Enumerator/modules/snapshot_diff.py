from __future__ import annotations

import difflib
import re
from typing import Any
from urllib.parse import urljoin

from modules.base import BaseArchiveModule

WAYBACK_CDX_URL      = "http://web.archive.org/cdx/search/cdx"
WAYBACK_SNAPSHOT_URL = "https://web.archive.org/web/{timestamp}if_/{url}"

ENDPOINT_PATTERN = re.compile(
    r"""(?:["'`]|href=|src=|action=|url\s*[:=])\s*["'`]?(/[^\s"'`>),;]{2,})""",
    re.IGNORECASE,
)

SECRET_PATTERN = re.compile(
    r"""(?:api[_\-]?key|token|secret|password|auth|bearer)\s*[:=]\s*["'`]?([A-Za-z0-9+/\-_]{8,})""",
    re.IGNORECASE,
)

class SnapshotDiffModule(BaseArchiveModule):

    async def run(
        self,
        url: str | None = None,
        timestamp_a: str | None = None,
        timestamp_b: str | None = None,
    ) -> dict[str, Any]:
        if url is None:
            url = getattr(self, "domain", None)
            if url:
                url = f"https://{url}"
        if not url:
            raise ValueError("No target URL provided and self.domain is not set.")
        self.logger.info(f"Snapshot diff started → {url}")

        timestamps = await self.get_snapshot_timestamps(url)

        if not timestamps:
            self.logger.warning("No snapshots found for the given URL.")
            return {"url": url, "timestamps": [], "diff": None, "stats": {}}

        ts_a = timestamp_a or timestamps[0]
        ts_b = timestamp_b or timestamps[-1]

        self.log_debug(f"Comparing {ts_a} ↔ {ts_b}")

        snap_a = await self.fetch_raw_snapshot(url, ts_a)
        snap_b = await self.fetch_raw_snapshot(url, ts_b)

        diff_result = self.compare_snapshots(snap_a, snap_b)

        self.logger.success(
            f"Diff complete – "
            f"Endpoints +{len(diff_result['endpoints_added'])}/-{len(diff_result['endpoints_removed'])} | "
            f"Secrets:{len(diff_result['secrets_found'])}"
        )

        return {
            "url":               url,
            "compared_a":        ts_a,
            "compared_b":        ts_b,
            "total_snapshots":   len(timestamps),
            "endpoints_added":   diff_result["endpoints_added"],
            "endpoints_removed": diff_result["endpoints_removed"],
            "secrets_found":     diff_result["secrets_found"],
        }

    async def get_snapshot_timestamps(self, url: str) -> list[str]:
        params = {
            "url":      url,
            "output":   "json",
            "fl":       "timestamp",
            "collapse": "digest",
        }
        data = await self.requester.get(WAYBACK_CDX_URL, params=params, response_type="json")

        if not data or not isinstance(data, list) or len(data) < 2:
            return []

        return [row[0] for row in data[1:] if row and isinstance(row, list) and row[0]]

    async def fetch_raw_snapshot(self, url: str, timestamp: str) -> str:
        snapshot_url = WAYBACK_SNAPSHOT_URL.format(timestamp=timestamp, url=url)
        data = await self.requester.get(snapshot_url, response_type="text")
        return data or ""

    def compare_snapshots(self, snap_a: str, snap_b: str) -> dict[str, Any]:
        added_lines: list[str] = []
        for line in difflib.unified_diff(snap_a.splitlines(keepends=True), snap_b.splitlines(keepends=True), lineterm=""):
            if line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:])

        endpoints_a = self._extract_endpoints(snap_a)
        endpoints_b = self._extract_endpoints(snap_b)

        endpoints_added   = sorted(endpoints_b - endpoints_a)
        endpoints_removed = sorted(endpoints_a - endpoints_b)

        secrets_found = self._extract_secrets("".join(added_lines))

        return {
            "endpoints_added":   endpoints_added,
            "endpoints_removed": endpoints_removed,
            "secrets_found":     secrets_found,
        }

    def _extract_endpoints(self, content: str) -> set[str]:
        matches = ENDPOINT_PATTERN.findall(content)
        cleaned: set[str] = set()
        for m in matches:
            path = m.strip().strip("\"'`")
            if path.startswith("/") and len(path) > 1:
                cleaned.add(path.split("?")[0].split("#")[0])
        return cleaned

    def _extract_secrets(self, content: str) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []
        seen: set[str] = set()

        for match in SECRET_PATTERN.finditer(content):
            full  = match.group(0)
            value = match.group(1)
            key   = f"{full[:20]}:{value[:16]}"
            if key not in seen and len(value) >= 8:
                seen.add(key)
                findings.append({
                    "match": full[:256],
                    "value": value[:128],
                })

        return findings