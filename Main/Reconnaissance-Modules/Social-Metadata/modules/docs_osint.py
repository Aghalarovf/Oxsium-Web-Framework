import html as html_lib
import mimetypes
import re
from typing import Any
from urllib.parse import unquote, urljoin, urlparse

from core.traffic import Entry, display_url
from .base import BaseModule


STATIC_EXTENSIONS = {"html", "htm", "xhtml", "css", "js", "mjs"}

FILE_TYPES: dict[str, dict[str, str]] = {
    "Document": {
        "pdf": "PDF document", "doc": "Word document (legacy)", "docx": "Word document",
        "dot": "Word template (legacy)", "dotx": "Word template", "docm": "Word macro document",
        "odt": "OpenDocument text", "rtf": "Rich Text document", "txt": "Plain text",
        "md": "Markdown", "epub": "EPUB e-book", "mobi": "Mobi e-book", "pages": "Apple Pages document",
        "xls": "Excel spreadsheet (legacy)", "xlsx": "Excel spreadsheet", "xlsm": "Excel macro spreadsheet",
        "xlsb": "Excel binary spreadsheet", "ods": "OpenDocument spreadsheet", "csv": "CSV data",
        "tsv": "TSV data", "numbers": "Apple Numbers spreadsheet",
        "ppt": "PowerPoint presentation (legacy)", "pptx": "PowerPoint presentation",
        "pptm": "PowerPoint macro presentation", "pps": "PowerPoint slideshow (legacy)",
        "ppsx": "PowerPoint slideshow", "odp": "OpenDocument presentation",
    },
    "Data": {
        "json": "JSON data", "jsonl": "JSON Lines data", "ndjson": "NDJSON data", "xml": "XML data",
        "yaml": "YAML data", "yml": "YAML data", "sql": "SQL dump", "db": "Database file",
        "sqlite": "SQLite database", "sqlite3": "SQLite database", "mdb": "Access database",
        "accdb": "Access database", "rss": "RSS feed", "atom": "Atom feed", "kml": "KML geodata",
        "kmz": "KMZ geodata", "geojson": "GeoJSON data", "har": "HTTP archive", "ldif": "LDAP export",
    },
    "Archive": {
        "zip": "ZIP archive", "rar": "RAR archive", "7z": "7-Zip archive", "tar": "TAR archive",
        "gz": "Gzip archive", "tgz": "Gzip TAR archive", "bz2": "Bzip2 archive", "xz": "XZ archive",
        "zst": "Zstandard archive", "iso": "Disk image", "cab": "Cabinet archive",
    },
    "Image": {
        "png": "PNG image", "jpg": "JPEG image", "jpeg": "JPEG image", "gif": "GIF image",
        "webp": "WebP image", "svg": "SVG image", "ico": "Icon", "bmp": "Bitmap image",
        "tif": "TIFF image", "tiff": "TIFF image", "avif": "AVIF image", "heic": "HEIC image",
        "psd": "Photoshop document", "ai": "Illustrator document", "eps": "EPS graphic",
    },
    "Font": {
        "woff": "WOFF font", "woff2": "WOFF2 font", "ttf": "TrueType font", "otf": "OpenType font",
        "eot": "Embedded OpenType font",
    },
    "Audio/Video": {
        "mp3": "MP3 audio", "wav": "WAV audio", "ogg": "Ogg media", "flac": "FLAC audio",
        "aac": "AAC audio", "m4a": "M4A audio", "mp4": "MP4 video", "m4v": "M4V video",
        "mov": "QuickTime video", "avi": "AVI video", "mkv": "Matroska video", "webm": "WebM video",
        "wmv": "WMV video", "flv": "Flash video", "mpg": "MPEG video", "mpeg": "MPEG video",
        "3gp": "3GP video", "srt": "SubRip subtitles", "vtt": "WebVTT subtitles",
    },
    "Executable/Package": {
        "exe": "Windows executable", "msi": "Windows installer", "dll": "Windows library",
        "apk": "Android package", "xapk": "Android package bundle", "aab": "Android app bundle",
        "ipa": "iOS application", "dmg": "macOS disk image", "pkg": "Installer package",
        "deb": "Debian package", "rpm": "RPM package", "jar": "Java archive", "war": "Java web archive",
        "ear": "Java enterprise archive", "bin": "Binary file", "appx": "Windows app package",
        "msix": "Windows MSIX package", "wasm": "WebAssembly module",
    },
    "Server-side script": {
        "php": "PHP script", "phtml": "PHP script", "asp": "ASP script", "aspx": "ASP.NET page",
        "asmx": "ASP.NET web service", "ashx": "ASP.NET handler", "jsp": "JSP page",
        "jspx": "JSP page", "do": "Java action endpoint", "action": "Java action endpoint",
        "cgi": "CGI script", "pl": "Perl script", "cfm": "ColdFusion page",
    },
    "Source/Script": {
        "py": "Python source", "rb": "Ruby source", "sh": "Shell script", "bash": "Shell script",
        "bat": "Batch script", "cmd": "Batch script", "ps1": "PowerShell script",
        "ts": "TypeScript source", "tsx": "TypeScript React source", "jsx": "JSX source",
        "vue": "Vue component", "scss": "SCSS source", "sass": "Sass source", "less": "Less source",
        "java": "Java source",
    },
    "Config": {
        "ini": "INI config", "conf": "Config file", "config": "Config file", "cfg": "Config file",
        "properties": "Properties file", "toml": "TOML config", "htaccess": "Apache config",
        "htpasswd": "Apache password file", "webmanifest": "Web app manifest", "plist": "Property list",
        "env": "Environment file",
    },
    "Secret/Certificate": {
        "pem": "PEM certificate/key", "key": "Key file", "crt": "Certificate", "cer": "Certificate",
        "p12": "PKCS#12 keystore", "pfx": "PKCS#12 keystore", "ppk": "PuTTY private key",
        "pub": "Public key", "jks": "Java keystore", "keystore": "Java keystore",
        "asc": "PGP armored file", "gpg": "GPG file",
    },
    "Backup/Temp": {
        "bak": "Backup file", "backup": "Backup file", "old": "Old file copy", "orig": "Original file copy",
        "tmp": "Temporary file", "swp": "Vim swap file", "save": "Saved copy", "dist": "Distribution copy",
    },
    "Log": {"log": "Log file"},
    "Source map": {"map": "Source map"},
}

EXT_INFO: dict[str, tuple[str, str]] = {
    ext: (label, category)
    for category, items in FILE_TYPES.items()
    for ext, label in items.items()
}

BARE_UNSAFE_CATEGORIES = {"Config", "Secret/Certificate", "Backup/Temp", "Server-side script", "Source/Script", "Log", "Source map"}
BARE_UNSAFE_EXTENSIONS = {"md", "ai", "bin", "db", "wasm", "ear", "war", "cab", "pkg", "dist"}

_ALL_EXTENSIONS = sorted(set(EXT_INFO) | STATIC_EXTENSIONS, key=len, reverse=True)
_EXT_ALT = "|".join(re.escape(e) for e in _ALL_EXTENSIONS)

_PATH_CHARS = r"(?:[\w\-./%~@+!$&*:]|\([\dA-Za-z]{1,3}\))"
_END = r"(?=[?#\"'\s,)<>;\\|]|$)"

_ABSOLUTE_RE = re.compile(
    r"(?<![\w.-])((?:https?:)?//[^\s\"'<>\\`(),;|]*?" + r"\.(?:" + _EXT_ALT + r")(?:[?#][^\s\"'<>\\`|]*)?)" + r"(?=[\s\"'<>\\`),;|]|$)",
    re.IGNORECASE,
)
_RELATIVE_RE = re.compile(
    r"(?<=[\"'(=\s,>])(" + _PATH_CHARS + r"+\.(?:" + _EXT_ALT + r"))(?:[?#][^\"'\s<>)]*)?" + _END,
    re.IGNORECASE,
)
_BASE_RE = re.compile(r"<base\s[^>]*?href=[\"']([^\"']+)[\"']", re.IGNORECASE)
_DISPOSITION_RE = re.compile(r"filename\*?=(?:UTF-8'')?[\"']?([^\"';]+)", re.IGNORECASE)

MAGIC_SIGNATURES: list[tuple[bytes, str, int]] = [
    (b"%PDF-", "pdf", 0),
    (b"\x89PNG\r\n\x1a\n", "png", 0),
    (b"\xff\xd8\xff", "jpg", 0),
    (b"GIF87a", "gif", 0),
    (b"GIF89a", "gif", 0),
    (b"BM", "bmp", 0),
    (b"\x00\x00\x01\x00", "ico", 0),
    (b"II*\x00", "tif", 0),
    (b"MM\x00*", "tif", 0),
    (b"8BPS", "psd", 0),
    (b"PK\x03\x04", "zip", 0),
    (b"PK\x05\x06", "zip", 0),
    (b"Rar!\x1a\x07", "rar", 0),
    (b"7z\xbc\xaf\x27\x1c", "7z", 0),
    (b"\x1f\x8b", "gz", 0),
    (b"BZh", "bz2", 0),
    (b"\xfd7zXZ\x00", "xz", 0),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "doc", 0),
    (b"{\\rtf", "rtf", 0),
    (b"SQLite format 3\x00", "sqlite", 0),
    (b"MZ", "exe", 0),
    (b"\x7fELF", "bin", 0),
    (b"\xca\xfe\xba\xbe", "jar", 0),
    (b"\x00asm", "wasm", 0),
    (b"OggS", "ogg", 0),
    (b"ID3", "mp3", 0),
    (b"fLaC", "flac", 0),
    (b"wOFF", "woff", 0),
    (b"wOF2", "woff2", 0),
    (b"\x00\x01\x00\x00\x00", "ttf", 0),
    (b"OTTO", "otf", 0),
    (b"ftyp", "mp4", 4),
    (b"\x1aE\xdf\xa3", "webm", 0),
    (b"-----BEGIN ", "pem", 0),
    (b"%!PS", "eps", 0),
]

CONTENT_TYPE_EXTENSIONS: dict[str, str] = {
    "application/pdf": "pdf",
    "application/msword": "doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.ms-excel": "xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.ms-powerpoint": "ppt",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
    "application/vnd.oasis.opendocument.text": "odt",
    "application/vnd.oasis.opendocument.spreadsheet": "ods",
    "application/vnd.oasis.opendocument.presentation": "odp",
    "application/rtf": "rtf",
    "application/epub+zip": "epub",
    "application/zip": "zip",
    "application/x-zip-compressed": "zip",
    "application/x-rar-compressed": "rar",
    "application/vnd.rar": "rar",
    "application/x-7z-compressed": "7z",
    "application/gzip": "gz",
    "application/x-gzip": "gz",
    "application/x-tar": "tar",
    "application/x-bzip2": "bz2",
    "application/x-msdownload": "exe",
    "application/x-msdos-program": "exe",
    "application/vnd.android.package-archive": "apk",
    "application/java-archive": "jar",
    "application/x-sqlite3": "sqlite",
    "application/vnd.sqlite3": "sqlite",
    "application/x-x509-ca-cert": "crt",
    "application/x-pem-file": "pem",
    "application/x-pkcs12": "p12",
    "application/wasm": "wasm",
    "application/x-apple-diskimage": "dmg",
    "text/csv": "csv",
    "font/woff": "woff",
    "font/woff2": "woff2",
    "font/ttf": "ttf",
    "font/otf": "otf",
}

SOURCE_PRIORITY = ["request_url", "content_disposition", "content_type", "body_magic", "body_reference"]

MAX_FOUND_ON = 10


def _extension_of(path: str) -> str:
    name = unquote(path).rstrip("/").rsplit("/", 1)[-1]
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].lower()


def _file_name_of(path: str) -> str:
    return unquote(path).rstrip("/").rsplit("/", 1)[-1]


def _strip_fragment(url: str) -> str:
    return url.split("#", 1)[0]


def _detect_magic(entry: Entry) -> str:
    head = entry.head_bytes(32)
    for signature, ext, offset in MAGIC_SIGNATURES:
        if head[offset:offset + len(signature)] == signature:
            if ext == "gz" and entry.body[:2] != "\x1f\x8b":
                continue
            if ext == "webm" and head[:4] != b"\x1aE\xdf\xa3":
                continue
            return ext
    if head[:4] == b"RIFF":
        tail = head[8:12]
        if tail == b"WEBP":
            return "webp"
        if tail == b"WAVE":
            return "wav"
        if tail == b"AVI ":
            return "avi"
    return ""


def _content_type_extension(content_type: str) -> str:
    ctype = content_type.split(";", 1)[0].strip().lower()
    if not ctype:
        return ""
    if ctype in CONTENT_TYPE_EXTENSIONS:
        return CONTENT_TYPE_EXTENSIONS[ctype]
    if ctype.startswith(("image/", "audio/", "video/", "font/")):
        guessed = mimetypes.guess_extension(ctype) or ""
        guessed = guessed.lstrip(".").lower()
        if guessed == "jpe":
            guessed = "jpg"
        return guessed if guessed in EXT_INFO else ""
    return ""


class DocsOsintModule(BaseModule):
    NAME = "docs_osint"
    DESCRIPTION = "File and file-type discovery from captured request URLs and response bodies (offline)"

    async def run(self) -> list[dict[str, Any]]:
        self.logger.section(f"[{self.NAME.upper()}] {self.DESCRIPTION}")

        self._files: dict[str, dict[str, Any]] = {}

        for entry in self.traffic.entries:
            self._scan_request(entry)

        texts = self.traffic.texts()
        self.logger.info(
            f"Scanning {len(self.traffic.entries)} captured request URL(s) and {len(texts)} text response body(ies)"
        )
        for entry in texts:
            self._scan_body(entry)

        self._findings = self._build_findings()
        for finding in self._findings:
            self._log_finding(
                f"{finding['category']} / {finding['extension']}",
                finding["url"],
            )

        self._print_summary()
        return self._findings

    def _scan_request(self, entry: Entry) -> None:
        parsed = urlparse(entry.url)
        ext = _extension_of(parsed.path)
        detected = _detect_magic(entry) if entry.body else ""
        headers = {k.lower(): v for k, v in entry.headers.items()}

        source = ""
        file_ext = ""
        file_name = _file_name_of(parsed.path)

        if ext and ext not in STATIC_EXTENSIONS and ext in EXT_INFO:
            source, file_ext = "request_url", ext
        elif not ext or ext in STATIC_EXTENSIONS or ext not in EXT_INFO:
            disposition = _DISPOSITION_RE.search(headers.get("content-disposition", ""))
            if disposition:
                name = unquote(disposition.group(1).strip())
                disp_ext = _extension_of(name)
                if disp_ext in EXT_INFO and disp_ext not in STATIC_EXTENSIONS:
                    source, file_ext, file_name = "content_disposition", disp_ext, name
            if not source and not ext:
                ct_ext = _content_type_extension(entry.content_type)
                if ct_ext and ct_ext not in STATIC_EXTENSIONS:
                    source, file_ext = "content_type", ct_ext
            if not source and not ext and detected and detected not in STATIC_EXTENSIONS:
                source, file_ext = "body_magic", detected

        if not source:
            return

        extra = {"captured": True}
        if detected and detected != file_ext and not (file_ext in ("jpeg", "jpg") and detected == "jpg"):
            extra["detected_type"] = detected
        length = headers.get("content-length", "")
        extra["size_bytes"] = int(length) if length.isdigit() else entry.size
        extra["status"] = entry.status
        extra["content_type"] = entry.content_type or None
        self._register(entry.url, file_ext, file_name, source, extra=extra)

    def _scan_body(self, entry: Entry) -> None:
        text = entry.body
        clean = html_lib.unescape(
            text.replace("\\/", "/").replace("\\u002F", "/").replace("\\u002f", "/").replace("\\u0026", "&")
        )
        found: set[str] = set()
        base = entry.url
        if entry.is_html:
            base_tag = _BASE_RE.search(text)
            if base_tag:
                base = urljoin(entry.url, base_tag.group(1))

        for match in _ABSOLUTE_RE.finditer(clean):
            url = match.group(1)
            if url.startswith("//"):
                url = f"{urlparse(entry.url).scheme or 'https'}:{url}"
            found.add(url)

        for match in _RELATIVE_RE.finditer(clean):
            ref = match.group(1)
            if ref.startswith(("data:", "javascript:", "mailto:", "tel:")):
                continue
            if "/" not in ref:
                ext = _extension_of(ref)
                info = EXT_INFO.get(ext)
                if ext in BARE_UNSAFE_EXTENSIONS or (info and info[1] in BARE_UNSAFE_CATEGORIES):
                    continue
            full_match = match.group(0)
            query = re.search(r"[?#][^\"'\s<>)]*$", full_match)
            found.add(urljoin(base, ref + (query.group(0) if query else "")))

        for url in found:
            path = urlparse(url).path
            ext = _extension_of(path)
            if ext in STATIC_EXTENSIONS or ext not in EXT_INFO:
                continue
            self._register(url, ext, _file_name_of(path), "body_reference", page=entry.url)

    def _register(
        self,
        url: str,
        ext: str,
        file_name: str,
        source: str,
        page: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        url = display_url(_strip_fragment(url))
        if not url.startswith(("http://", "https://")):
            return
        key = re.sub(r"^https?://(?:www\.)?", "", url, flags=re.I).rstrip("/").lower()
        slot = self._files.get(key)
        if slot is None:
            slot = {"url": url, "extension": ext, "file_name": file_name, "sources": [], "found_on": []}
            self._files[key] = slot
        if source not in slot["sources"]:
            slot["sources"].append(source)
        if page and page not in slot["found_on"]:
            slot["found_on"].append(page)
        if extra:
            for k, v in extra.items():
                slot.setdefault(k, v)

    def _build_findings(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for slot in self._files.values():
            ext = slot["extension"]
            label, category = EXT_INFO.get(ext, (ext.upper() + " file", "Other"))
            sources = sorted(slot["sources"], key=lambda s: SOURCE_PRIORITY.index(s))
            found_on = slot["found_on"]
            detected = slot.get("detected_type")
            finding = {
                "source": sources[0],
                "sources": sources,
                "category": category,
                "file_type": label,
                "extension": ext,
                "file_name": slot["file_name"],
                "url": slot["url"],
                "host": urlparse(slot["url"]).hostname,
                "captured": bool(slot.get("captured")),
                "status": slot.get("status"),
                "content_type": slot.get("content_type"),
                "size_bytes": slot.get("size_bytes"),
                "detected_type": EXT_INFO[detected][0] if detected in EXT_INFO else None,
                "found_on": found_on[:MAX_FOUND_ON],
                "found_on_count": len(found_on) if len(found_on) > MAX_FOUND_ON else None,
            }
            entry = {k: v for k, v in finding.items() if v not in (None, "", [], {})}
            entry.setdefault("captured", False)
            out.append(entry)
        out.sort(key=lambda f: (f["category"], f["extension"], f["url"]))
        return out

    def _print_summary(self):
        if not self._findings:
            self.logger.warning("No non-static files discovered.")
            return

        by_type: dict[tuple[str, str], int] = {}
        by_category: dict[str, int] = {}
        by_source: dict[str, int] = {}
        captured = 0
        for f in self._findings:
            by_type[(f["category"], f["extension"])] = by_type.get((f["category"], f["extension"]), 0) + 1
            by_category[f["category"]] = by_category.get(f["category"], 0) + 1
            by_source[f["source"]] = by_source.get(f["source"], 0) + 1
            if f.get("captured"):
                captured += 1

        self.logger.table(
            ["Category", "Extension", "File Type", "Count"],
            [
                [cat, ext, EXT_INFO.get(ext, (ext.upper(), cat))[0], str(n)]
                for (cat, ext), n in sorted(by_type.items())
            ],
        )
        self.logger.table(
            ["Category", "Count"],
            [[c, str(n)] for c, n in sorted(by_category.items())],
        )
        self.logger.table(
            ["Source", "Count"],
            [[s, str(n)] for s, n in sorted(by_source.items())],
        )
        self.logger.info(
            f"Total unique files: {len(self._findings)}  |  Captured in traffic: {captured}  |  "
            f"Referenced only: {len(self._findings) - captured}"
        )
