import json
import os
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlparse

SUPPORTED_EXTENSIONS = (".json", ".jsonl")
CONTAINER_KEYS = ("entries", "items", "traffic", "messages", "history", "requests", "data")


class InterceptError(Exception):
    pass


class HTTPResponse:
    def __init__(
        self,
        entry_id: str,
        method: str,
        url: str,
        status_code: int,
        headers: Dict[str, str],
        request_headers: Dict[str, str],
        http_version: str = "",
        timestamp: str = "",
        source: str = "",
    ):
        self.entry_id = entry_id
        self.method = method
        self.url = url
        self.final_url = url
        self.status_code = status_code
        self.headers = headers
        self.request_headers = request_headers
        self.http_version = http_version
        self.timestamp = timestamp
        self.source = source

    def get_header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.entry_id,
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "http_version": self.http_version,
            "timestamp": self.timestamp,
            "source": self.source,
            "headers": self.headers,
        }


def normalize_headers(raw: Any) -> Dict[str, str]:
    pairs: List[Tuple[Any, Any]] = []

    if isinstance(raw, dict):
        pairs = list(raw.items())
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and "name" in item:
                pairs.append((item["name"], item.get("value", "")))
            elif isinstance(item, str) and ":" in item:
                name, _, value = item.partition(":")
                pairs.append((name, value))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                pairs.append((item[0], item[1]))

    normalized: Dict[str, str] = {}
    for name, value in pairs:
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(v) for v in value)
        key = str(name).strip().lower()
        text = str(value).strip()
        if not key:
            continue
        if key in normalized:
            normalized[key] = f"{normalized[key]}, {text}"
        else:
            normalized[key] = text
    return normalized


def normalize_host(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if "://" not in text:
        text = "//" + text
    try:
        host = urlparse(text).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".")


def host_matches_domain(host: str, domain: str) -> bool:
    if not host or not domain:
        return False
    return host == domain or host.endswith("." + domain)


def extract_hosts(record: Dict[str, Any]) -> Set[str]:
    request = record.get("request")
    request = request if isinstance(request, dict) else {}
    request_headers = normalize_headers(request.get("headers"))

    candidates = [
        request_headers.get("host"),
        request.get("host"),
        record.get("host"),
        request.get("url"),
        record.get("url"),
    ]
    hosts = {normalize_host(candidate) for candidate in candidates}
    hosts.discard("")
    return hosts


def _to_status_code(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


class InterceptReader:
    def __init__(self, paths: List[str], domain: Optional[str] = None):
        self.paths = paths
        self.domain = normalize_host(domain) if domain else ""
        self.warnings: List[str] = []
        self.files_read: List[str] = []
        self.total_records = 0
        self.host_matches: Dict[str, int] = {}

    def discover_files(self) -> List[str]:
        files: List[str] = []
        for path in self.paths:
            if os.path.isdir(path):
                found = sorted(
                    os.path.join(path, name)
                    for name in os.listdir(path)
                    if name.lower().endswith(SUPPORTED_EXTENSIONS)
                )
                if not found:
                    self.warnings.append(f"No .json or .jsonl files found in directory: {path}")
                files.extend(found)
            elif os.path.isfile(path):
                if not path.lower().endswith(SUPPORTED_EXTENSIONS):
                    raise InterceptError(f"Unsupported file type (expected .json or .jsonl): {path}")
                files.append(path)
            else:
                raise InterceptError(f"Path does not exist: {path}")
        if not files:
            raise InterceptError("No intercept files to read")
        return files

    def read(self) -> List[HTTPResponse]:
        responses: List[HTTPResponse] = []
        for file_path in self.discover_files():
            self.files_read.append(file_path)
            records = list(self._read_records(file_path))
            if self.domain:
                self._verify_domain(records, file_path)
            for index, record in enumerate(records, start=1):
                self.total_records += 1
                response = self._build_response(record, index, file_path)
                if response is not None:
                    responses.append(response)
        return responses

    def _verify_domain(self, records: List[Dict[str, Any]], file_path: str) -> None:
        seen: Set[str] = set()
        matched = 0
        for record in records:
            hosts = extract_hosts(record)
            seen.update(hosts)
            if any(host_matches_domain(host, self.domain) for host in hosts):
                matched += 1

        if matched == 0:
            listed = ", ".join(sorted(seen)[:10]) or "none"
            if len(seen) > 10:
                listed += f" (+{len(seen) - 10} more)"
            raise InterceptError(
                f"Domain mismatch: '{self.domain}' not found in {file_path}. Hosts in file: {listed}"
            )

        self.host_matches[file_path] = matched

    def _read_records(self, file_path: str) -> Iterator[Dict[str, Any]]:
        try:
            with open(file_path, "r", encoding="utf-8-sig") as handle:
                content = handle.read()
        except OSError as exc:
            raise InterceptError(f"Cannot read {file_path}: {exc}")

        if file_path.lower().endswith(".jsonl"):
            yield from self._parse_jsonl(content, file_path)
            return

        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            lines = [line for line in content.splitlines() if line.strip()]
            if len(lines) > 1:
                self.warnings.append(f"{file_path}: not a single JSON document ({exc.msg}); reading as JSON Lines")
                yield from self._parse_jsonl(content, file_path)
                return
            raise InterceptError(f"Invalid JSON in {file_path}: {exc}")

        yield from self._extract_records(data, file_path)

    def _parse_jsonl(self, content: str, file_path: str) -> Iterator[Dict[str, Any]]:
        for line_number, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                self.warnings.append(f"{file_path}:{line_number}: invalid JSON line skipped ({exc.msg})")
                continue
            yield from self._extract_records(data, file_path)

    def _extract_records(self, data: Any, file_path: str) -> Iterator[Dict[str, Any]]:
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    yield item
                else:
                    self.warnings.append(f"{file_path}: non-object record skipped")
            return

        if isinstance(data, dict):
            if "request" in data or "response" in data:
                yield data
                return
            for key in CONTAINER_KEYS:
                value = data.get(key)
                if isinstance(value, list):
                    yield from self._extract_records(value, file_path)
                    return
            raise InterceptError(f"Unrecognized traffic structure in {file_path}")

        raise InterceptError(f"Unrecognized traffic structure in {file_path}")

    def _build_response(self, record: Dict[str, Any], index: int, file_path: str) -> Optional[HTTPResponse]:
        request = record.get("request")
        response = record.get("response")
        request = request if isinstance(request, dict) else {}
        entry_id = str(record.get("id", index))

        if not isinstance(response, dict):
            self.warnings.append(f"{os.path.basename(file_path)} entry {entry_id}: no response recorded, skipped")
            return None

        headers = normalize_headers(response.get("headers"))
        if not headers:
            self.warnings.append(f"{os.path.basename(file_path)} entry {entry_id}: response has no headers, skipped")
            return None

        status = response.get("status_code", response.get("status"))

        return HTTPResponse(
            entry_id=entry_id,
            method=str(request.get("method") or record.get("method") or "GET").upper(),
            url=str(request.get("url") or record.get("url") or ""),
            status_code=_to_status_code(status),
            headers=headers,
            request_headers=normalize_headers(request.get("headers")),
            http_version=str(record.get("http_version") or ""),
            timestamp=str(record.get("timestamp") or ""),
            source=os.path.basename(file_path),
        )
