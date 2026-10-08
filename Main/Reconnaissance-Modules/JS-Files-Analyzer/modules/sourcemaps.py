from __future__ import annotations

import base64
import json
import posixpath
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from modules.base import BaseJSModule, Finding


SOURCEMAPPING_COMMENT_RE = re.compile(
    r"""(?://|/\*)\s*#\s*sourceMappingURL\s*=\s*([^\s*]+)""",
    re.IGNORECASE,
)

SOURCEMAP_HEADER_RE = re.compile(
    r"""^(?:X-Source-?Map|SourceMap)\s*:\s*(.+)$""",
    re.IGNORECASE | re.MULTILINE,
)

INLINE_SOURCEMAP_RE = re.compile(
    r"""sourceMappingURL=data:application/json;(?:charset=[^;,]+;)?base64,([A-Za-z0-9+/=]+)""",
    re.IGNORECASE,
)

CANDIDATE_MAP_URL_RE = re.compile(
    r"""["'`]([^"'`\s]+\.js\.map)["'`]""",
    re.IGNORECASE,
)

INTERESTING_PATH_RE = re.compile(
    r"""(?:src/|lib/|components?/|pages?/|store/|hooks?/|utils?/|
         services?/|controllers?/|models?/|api/|config/|server/|
         internal/|private/|admin/)""",
    re.IGNORECASE | re.VERBOSE,
)

SENSITIVE_COMMENT_RE = re.compile(
    r"""//.*?(?:TODO|FIXME|HACK|XXX|password|secret|token|key|credential|bug|vuln).*""",
    re.IGNORECASE,
)


@dataclass
class SourceMapRef:
    url: str
    origin: str
    is_inline: bool = False
    inline_data: bytes | None = None


@dataclass
class RecoveredSource:
    path: str
    content: str
    has_sensitive_comments: bool = False
    comment_snippets: list[str] = field(default_factory=list)


@dataclass
class SourceMapAnalysis:
    ref: SourceMapRef
    sources: list[RecoveredSource] = field(default_factory=list)
    directory_tree: list[str] = field(default_factory=list)
    raw_map: dict[str, Any] | None = None
    error: str | None = None


class SourceMapsModule(BaseJSModule):

    def analyze(self, content: str, filename: str = "") -> list[Finding]:
        self.findings = []
        refs = self.detect_map_headers(content)
        for ref in refs:
            self.findings.append(self._ref_to_finding(ref, content))
        return self.findings

    def detect_map_headers(self, content: str) -> list[SourceMapRef]:
        refs: list[SourceMapRef] = []
        seen: set[str] = set()

        for m in INLINE_SOURCEMAP_RE.finditer(content):
            b64 = m.group(1)
            key = f"inline:{b64[:32]}"
            if key in seen:
                continue
            seen.add(key)
            try:
                raw = base64.b64decode(b64 + "==")
            except Exception:
                raw = None
            refs.append(SourceMapRef(url="<inline>", origin="inline", is_inline=True, inline_data=raw))

        for m in SOURCEMAPPING_COMMENT_RE.finditer(content):
            url = m.group(1).strip()
            if url.startswith("data:"):
                continue
            key = f"comment:{url}"
            if key in seen:
                continue
            seen.add(key)
            refs.append(SourceMapRef(url=url, origin="comment"))

        for m in SOURCEMAP_HEADER_RE.finditer(content):
            url = m.group(1).strip()
            key = f"header:{url}"
            if key in seen:
                continue
            seen.add(key)
            refs.append(SourceMapRef(url=url, origin="header"))

        for m in CANDIDATE_MAP_URL_RE.finditer(content):
            url = m.group(1)
            key = f"candidate:{url}"
            if key in seen:
                continue
            seen.add(key)
            refs.append(SourceMapRef(url=url, origin="candidate"))

        return refs

    def download_maps(
        self,
        refs: list[SourceMapRef],
        base_url: str = "",
        fetcher: Any = None,
    ) -> list[SourceMapAnalysis]:
        results: list[SourceMapAnalysis] = []

        for ref in refs:
            analysis = SourceMapAnalysis(ref=ref)
            try:
                raw_json: str | None = None
                if ref.is_inline and ref.inline_data:
                    raw_json = ref.inline_data.decode("utf-8", errors="replace")
                elif fetcher:
                    resolved = self._resolve_url(ref.url, base_url)
                    raw_json = fetcher(resolved)
                if raw_json:
                    analysis.raw_map = json.loads(raw_json)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                analysis.error = f"Parse error: {exc}"
            except Exception as exc:
                analysis.error = f"Download error: {exc}"
            results.append(analysis)

        return results

    def recover_source(self, analysis: SourceMapAnalysis) -> SourceMapAnalysis:
        if not analysis.raw_map:
            analysis.error = analysis.error or "No map payload to recover"
            return analysis

        sm               = analysis.raw_map
        sources          = sm.get("sources", [])
        sources_content  = sm.get("sourcesContent", [])
        recovered: list[RecoveredSource] = []
        tree_paths: set[str] = set()

        for idx, src_path in enumerate(sources):
            clean_path = self._normalize_source_path(src_path)
            tree_paths.add(str(PurePosixPath(clean_path).parent))

            raw_content: str = ""
            if idx < len(sources_content) and sources_content[idx]:
                raw_content = sources_content[idx]

            snippets: list[str] = []
            if raw_content:
                for m in SENSITIVE_COMMENT_RE.finditer(raw_content):
                    snippets.append(m.group(0).strip()[:256])

            recovered.append(RecoveredSource(
                path                  = clean_path,
                content               = raw_content,
                has_sensitive_comments= bool(snippets),
                comment_snippets      = snippets,
            ))

        analysis.sources        = recovered
        analysis.directory_tree = sorted(tree_paths)
        return analysis

    def _ref_to_finding(self, ref: SourceMapRef, content: str) -> Finding:
        if ref.origin == "inline":
            line, ctx = 1, "<inline data-URI>"
        else:
            pattern = re.compile(re.escape(ref.url[:64]))
            m = pattern.search(content)
            if m:
                line = self._get_line_number(content, m.start())
                ctx  = self._get_context(content, m.start())
            else:
                line, ctx = 0, ""

        severity = (
            self.SEVERITY_HIGH
            if ref.origin in ("comment", "header", "inline")
            else self.SEVERITY_MEDIUM
        )

        return self._finding(
            type       = f"source_map_{ref.origin}",
            value      = ref.url[:512],
            severity   = severity,
            context    = ctx,
            line       = line,
            confidence = self.CONFIDENCE_HIGH,
            meta       = {"origin": ref.origin, "is_inline": ref.is_inline},
        )

    @staticmethod
    def _resolve_url(url: str, base_url: str) -> str:
        if url.startswith(("http://", "https://")):
            return url
        if base_url:
            return urllib.parse.urljoin(base_url, url)
        return url

    @staticmethod
    def _normalize_source_path(path: str) -> str:
        path = re.sub(r"^(?:webpack|vite|rollup):///(?:\.\/)?", "", path)
        path = re.sub(r"^(?:\.\/)+", "", path)
        return posixpath.normpath(path)