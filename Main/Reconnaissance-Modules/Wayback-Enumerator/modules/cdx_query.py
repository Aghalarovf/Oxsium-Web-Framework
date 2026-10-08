from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from modules.base import BaseArchiveModule


WAYBACK_CDX_URL = "http://web.archive.org/cdx/search/cdx"

STATUS_GROUPS: dict[str, set[str]] = {
    "ok":       {"200"},
    "redirect": {"301", "302", "303", "307", "308"},
    "client_error": {"400", "401", "403", "404", "405", "410", "429"},
    "server_error": {"500", "502", "503", "504"},
}

MIMETYPE_ALIASES: dict[str, str] = {
    "json":       "application/json",
    "html":       "text/html",
    "plain":      "text/plain",
    "xml":        "application/xml",
    "javascript": "application/javascript",
    "pdf":        "application/pdf",
    "form":       "application/x-www-form-urlencoded",
    "binary":     "application/octet-stream",
}

CDX_FIELDS = ["original", "statuscode", "mimetype", "timestamp", "digest"]


class CDXQueryModule(BaseArchiveModule):

    async def run(
        self,
        pattern: str | None = None,
        status_filter: str | list[str] | None = None,
        mime_filter: str | None = None,
    ) -> dict[str, Any]:
        if pattern is None:
            pattern = f"*.{self.domain}/*"

        self.logger.info(f"CDX query started → {pattern}")

        raw_records = await self._fetch_cdx_records(pattern)
        self.logger.info(f"CDX raw records: {len(raw_records)}")

        by_status   = self.filter_by_status_code(raw_records, status_filter)
        by_mime     = self.filter_by_mimetype(raw_records, mime_filter)

        stats = {
            "total_records": len(raw_records),
            "by_status":     {k: len(v) for k, v in by_status.items()},
            "by_mime":       {k: len(v) for k, v in by_mime.items()},
        }

        self.logger.success(
            f"CDX complete – "
            f"Records:{stats['total_records']} | "
            f"Status groups:{len(by_status)} | "
            f"MIME groups:{len(by_mime)}"
        )

        return {
            "raw_records": raw_records,
            "by_status":   by_status,
            "by_mime":     by_mime,
            "stats":       stats,
        }

    def build_wildcard_query(self, pattern: str) -> dict[str, str]:
        if not any(c in pattern for c in ("*", "?")):
            parsed = urlparse(pattern)
            if parsed.scheme:
                host = parsed.netloc or parsed.path
                pattern = f"*.{host}/*"
            else:
                pattern = f"*.{pattern}/*"

        return {
            "url":      pattern,
            "output":   "json",
            "fl":       ",".join(CDX_FIELDS),
            "collapse": "urlkey",
        }

    def filter_by_status_code(
        self,
        records: list[dict[str, str]],
        status: str | list[str] | None = None,
    ) -> dict[str, list[dict[str, str]]]:
        if status is not None:
            target_codes: set[str] = set()
            codes = [status] if isinstance(status, str) else status
            for code in codes:
                normalized = code.strip().lower()
                if normalized in STATUS_GROUPS:
                    target_codes |= STATUS_GROUPS[normalized]
                else:
                    target_codes.add(normalized)

            matched = [r for r in records if r.get("statuscode") in target_codes]
            return {"filtered": matched}

        buckets: dict[str, list[dict[str, str]]] = {k: [] for k in STATUS_GROUPS}
        buckets["other"] = []

        for record in records:
            code = record.get("statuscode", "")
            placed = False
            for group, codes in STATUS_GROUPS.items():
                if code in codes:
                    buckets[group].append(record)
                    placed = True
                    break
            if not placed:
                buckets["other"].append(record)

        return buckets

    def filter_by_mimetype(
        self,
        records: list[dict[str, str]],
        mime_type: str | None = None,
    ) -> dict[str, list[dict[str, str]]]:
        if mime_type is not None:
            normalized = MIMETYPE_ALIASES.get(mime_type.lower(), mime_type.lower())
            matched = [
                r for r in records
                if normalized in r.get("mimetype", "").lower()
            ]
            return {"filtered": matched}

        buckets: dict[str, list[dict[str, str]]] = {}

        for record in records:
            mime = record.get("mimetype", "unknown").split(";")[0].strip().lower()
            if not mime:
                mime = "unknown"
            buckets.setdefault(mime, []).append(record)

        return buckets

    async def _fetch_cdx_records(self, pattern: str) -> list[dict[str, str]]:
        params = self.build_wildcard_query(pattern)
        records: list[dict[str, str]] = []

        num_pages = await self._page_count(params)
        self.log_debug(f"CDX pages: {num_pages}")

        tasks = [self._fetch_page(params, page) for page in range(num_pages)]
        pages = await asyncio.gather(*tasks, return_exceptions=True)

        for page_records in pages:
            if isinstance(page_records, list):
                records.extend(page_records)

        return records

    async def _page_count(self, base_params: dict[str, str]) -> int:
        params = {**base_params, "showNumPages": "true"}
        data = await self.requester.get(WAYBACK_CDX_URL, params=params, response_type="text")
        try:
            count = int(data.strip()) if data else 1
            return max(1, min(count, 50))
        except (ValueError, AttributeError):
            return 1

    async def _fetch_page(self, base_params: dict[str, str], page: int) -> list[dict[str, str]]:
        params = {**base_params, "page": page}
        data = await self.requester.get(WAYBACK_CDX_URL, params=params, response_type="json")

        if not data or not isinstance(data, list) or len(data) < 2:
            return []

        headers = [h.lower() for h in data[0]]
        records = []
        for row in data[1:]:
            if isinstance(row, list) and len(row) == len(headers):
                records.append(dict(zip(headers, row)))

        return records