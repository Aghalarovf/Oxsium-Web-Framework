import json
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

DEFAULT_PORTS = {"http": "80", "https": "443"}

TEXT_TYPE_HINTS = (
    "text/", "json", "javascript", "ecmascript", "xml", "svg", "html",
    "x-www-form-urlencoded", "yaml", "csv", "x-sh", "x-httpd",
)
BINARY_TYPE_PREFIXES = ("image/", "audio/", "video/", "font/")


def clean_host(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def host_matches(url: str, target: str) -> bool:
    host, wanted = clean_host(url), clean_host(target)
    return bool(host and wanted) and (host == wanted or host.endswith("." + wanted))


def display_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.port and DEFAULT_PORTS.get(parsed.scheme) == str(parsed.port):
        return parsed._replace(netloc=parsed.netloc.rsplit(":", 1)[0]).geturl()
    return url


def url_key(url: str) -> tuple[str, str, str]:
    parsed = urlparse(url)
    return (clean_host(url), parsed.path.rstrip("/") or "/", parsed.query)


@dataclass
class Entry:
    url: str
    method: str
    status: int
    headers: dict
    body: str
    content_type: str = ""
    source_file: str = ""
    raw_head: str = ""

    @property
    def host(self) -> str:
        return clean_host(self.url)

    @property
    def size(self) -> int:
        return len(self.body)

    @property
    def success(self) -> bool:
        return 200 <= self.status < 300

    def head_bytes(self, count: int = 16) -> bytes:
        head = (self.raw_head or self.body)[:count]
        try:
            return head.encode("latin-1")
        except UnicodeEncodeError:
            return head.encode("utf-8", errors="replace")

    @property
    def is_binary(self) -> bool:
        ctype = self.content_type.lower()
        if ctype.startswith(BINARY_TYPE_PREFIXES):
            return True
        sample = self.body[:512]
        if not sample:
            return False
        if "\x00" in sample:
            return True
        controls = sum(1 for ch in sample if ord(ch) < 32 and ch not in "\r\n\t\f")
        return controls > 4

    @property
    def is_html(self) -> bool:
        if not self.body.strip() or self.is_binary:
            return False
        head = self.body[:300].lstrip().lower()
        return "html" in self.content_type.lower() or head.startswith(("<!doctype html", "<html"))

    @property
    def is_text(self) -> bool:
        if not self.body.strip() or self.is_binary:
            return False
        ctype = self.content_type.lower()
        if any(hint in ctype for hint in TEXT_TYPE_HINTS):
            return True
        return not ctype

    def score(self) -> tuple:
        return (self.method == "GET", self.success, self.size)


def parse_records(data: bytes, filename: str) -> list[dict]:
    text = data.decode("utf-8", errors="replace").lstrip("\ufeff")
    if not filename.lower().endswith(".jsonl"):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, list):
            return [item for item in obj if isinstance(item, dict)]
        if isinstance(obj, dict):
            return [obj]
    records: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def load_records(path: str) -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = []
    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path, "r") as archive:
            for name in archive.namelist():
                if name.lower().endswith((".json", ".jsonl")):
                    for record in parse_records(archive.read(name), name):
                        out.append((f"{path}:{name}", record))
    else:
        with open(path, "rb") as handle:
            for record in parse_records(handle.read(), path):
                out.append((path, record))
    return out


def repair_encoding(body: str) -> str:
    if not body or body.isascii():
        return body
    try:
        raw = body.encode("latin-1")
    except UnicodeEncodeError:
        return body
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.start >= len(raw) - 3:
            return raw[:exc.start].decode("utf-8", errors="replace")
    return body


def to_entry(record: dict, source_file: str) -> Optional[Entry]:
    request = record.get("request") or {}
    response = record.get("response") or {}
    url = request.get("url") or ""
    if not url:
        return None
    body = response.get("body_preview")
    if body is None:
        body = response.get("body")
    if body is None:
        body = ""
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode("latin-1")
    elif not isinstance(body, str):
        body = json.dumps(body, ensure_ascii=False)
    headers = {str(k): str(v) for k, v in (response.get("headers") or {}).items()}
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    try:
        status = int(response.get("status_code") or 0)
    except (TypeError, ValueError):
        status = 0
    entry = Entry(
        url=display_url(url),
        method=str(request.get("method") or "GET").upper(),
        status=status,
        headers=headers,
        body=body,
        content_type=content_type,
        source_file=source_file,
    )
    entry.raw_head = body[:64]
    if not entry.is_binary:
        entry.body = repair_encoding(body)
    return entry


@dataclass
class TrafficStore:
    paths: list[str]
    target: Optional[str]
    logger: Any
    entries: list[Entry] = field(default_factory=list)
    total: int = 0
    skipped: int = 0

    def load(self) -> bool:
        for path in self.paths:
            self.logger.info(f"Loading traffic file: {path}")
            try:
                records = load_records(path)
            except Exception as exc:
                self.logger.error(f"Failed to load {path}: {exc}")
                continue
            for source_file, record in records:
                self.total += 1
                entry = to_entry(record, source_file)
                if entry is None:
                    self.skipped += 1
                    continue
                if self.target and not host_matches(entry.url, self.target):
                    self.skipped += 1
                    continue
                self.entries.append(entry)
        if not self.target and self.entries:
            top = Counter(e.host for e in self.entries).most_common(1)[0][0]
            scheme = urlparse(self.entries[0].url).scheme or "https"
            self.target = f"{scheme}://{top}"
        self.logger.info(
            f"{self.total} record(s) read, {len(self.entries)} usable, {self.skipped} skipped"
        )
        return bool(self.entries)

    def unique(self) -> list[Entry]:
        best: dict[tuple, Entry] = {}
        for entry in self.entries:
            key = url_key(entry.url)
            if key not in best or entry.score() > best[key].score():
                best[key] = entry
        return list(best.values())

    def pages(self) -> list[Entry]:
        return [e for e in self.unique() if e.success and e.is_html]

    def texts(self) -> list[Entry]:
        return [e for e in self.unique() if e.success and e.is_text]
