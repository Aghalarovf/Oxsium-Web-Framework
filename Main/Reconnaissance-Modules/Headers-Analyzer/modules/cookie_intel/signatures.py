import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

SIGNATURE_ENV_VAR = "HEADERS_ANALYZER_COOKIE_SIGNATURES"
DEFAULT_SIGNATURE_FILE = Path(__file__).resolve().parent / "cookies_signatures.json"

CLIENT_READABLE_CATEGORIES = frozenset({"tracking", "consent", "csrf", "preference"})
SENSITIVE_CATEGORIES = frozenset({"session", "auth"})

_SENSITIVE_NAME_HINTS = (
    "sess", "token", "auth", "sid", "jwt", "login", "secret", "credential",
    "remember", "role", "apikey", "api_key", "passport", "identity", "access",
)


class SignatureDatabase:
    def __init__(self) -> None:
        self.exact: Dict[str, Tuple[str, str]] = {}
        self.prefix: List[Tuple[str, str, str]] = []
        self.suffix: List[Tuple[str, str, str]] = []
        self.regex: List[Tuple[Pattern[str], str, str]] = []
        self.categories: frozenset = frozenset()
        self.errors: List[str] = []
        self.source: Optional[Path] = None

    def lookup(self, lower: str) -> Optional[Dict[str, str]]:
        hit = self.exact.get(lower)
        if hit:
            return {"label": hit[0], "category": hit[1]}
        for match, label, category in self.prefix:
            if lower.startswith(match):
                return {"label": label, "category": category}
        for pattern, label, category in self.regex:
            if pattern.match(lower):
                return {"label": label, "category": category}
        for match, label, category in self.suffix:
            if lower.endswith(match):
                return {"label": label, "category": category}
        return None


def _resolve_path() -> Path:
    override = os.environ.get(SIGNATURE_ENV_VAR)
    return Path(override).expanduser() if override else DEFAULT_SIGNATURE_FILE


def _valid_entry(entry: Any, categories: frozenset, required: str) -> bool:
    if not isinstance(entry, dict):
        return False
    value = entry.get(required)
    label = entry.get("label")
    category = entry.get("category")
    if not isinstance(value, str) or not value:
        return False
    if not isinstance(label, str) or not label:
        return False
    return isinstance(category, str) and category in categories


def _build(raw: Any, db: SignatureDatabase) -> None:
    if not isinstance(raw, dict):
        db.errors.append("root element must be an object")
        return

    categories = raw.get("categories")
    if not isinstance(categories, list) or not all(isinstance(item, str) for item in categories):
        db.errors.append("'categories' must be a list of strings")
        return
    db.categories = frozenset(categories)

    exact = raw.get("exact", {})
    if isinstance(exact, dict):
        for name, entry in exact.items():
            if not isinstance(name, str) or not isinstance(entry, dict):
                db.errors.append(f"exact entry {name!r} is malformed")
                continue
            label = entry.get("label")
            category = entry.get("category")
            if not isinstance(label, str) or category not in db.categories:
                db.errors.append(f"exact entry {name!r} has an invalid label or category")
                continue
            db.exact[name.lower()] = (label, category)
    else:
        db.errors.append("'exact' must be an object")

    for section, target in (("prefix", db.prefix), ("suffix", db.suffix)):
        items = raw.get(section, [])
        if not isinstance(items, list):
            db.errors.append(f"'{section}' must be a list")
            continue
        for index, entry in enumerate(items):
            if not _valid_entry(entry, db.categories, "match"):
                db.errors.append(f"{section}[{index}] is malformed")
                continue
            target.append((entry["match"].lower(), entry["label"], entry["category"]))
        target.sort(key=lambda row: len(row[0]), reverse=True)

    items = raw.get("regex", [])
    if isinstance(items, list):
        for index, entry in enumerate(items):
            if not _valid_entry(entry, db.categories, "pattern"):
                db.errors.append(f"regex[{index}] is malformed")
                continue
            try:
                compiled = re.compile(entry["pattern"])
            except re.error as exc:
                db.errors.append(f"regex[{index}] does not compile: {exc}")
                continue
            db.regex.append((compiled, entry["label"], entry["category"]))
    else:
        db.errors.append("'regex' must be a list")


@lru_cache(maxsize=1)
def load_signatures() -> SignatureDatabase:
    db = SignatureDatabase()
    path = _resolve_path()
    db.source = path
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        db.errors.append(f"signature file not found: {path}")
        return db
    except (OSError, ValueError) as exc:
        db.errors.append(f"signature file could not be read: {exc}")
        return db
    _build(raw, db)
    return db


def reload_signatures() -> SignatureDatabase:
    load_signatures.cache_clear()
    return load_signatures()


def signature_load_errors() -> List[str]:
    return list(load_signatures().errors)


def identify_cookie(name: str) -> Optional[Dict[str, str]]:
    return load_signatures().lookup(name.lower())


def is_sensitive_name(name: str) -> bool:
    lower = name.lower()
    return any(hint in lower for hint in _SENSITIVE_NAME_HINTS)