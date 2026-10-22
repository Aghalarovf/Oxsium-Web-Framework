import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


TESTED_JAVA_MAJOR = 21

WINDOWS_JAVA_DIRS = [
    Path("C:/Program Files/BurpSuiteCommunity"),
    Path("C:/Program Files/BurpSuitePro"),
    Path("C:/Program Files/Java"),
    Path("C:/Program Files (x86)/Java"),
    Path("C:/Program Files/Eclipse Adoptium"),
    Path("C:/Program Files/Eclipse Foundation"),
    Path("C:/Program Files/Microsoft"),
    Path("C:/Program Files/Amazon Corretto"),
    Path("C:/Program Files/Zulu"),
    Path("C:/Program Files/BellSoft"),
    Path("C:/Program Files/Semeru"),
    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "BurpSuiteCommunity",
    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "BurpSuitePro",
    Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Java",
    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Java",
]

UNIX_JAVA_DIRS = [
    Path.home() / "BurpSuiteCommunity",
    Path.home() / "BurpSuitePro",
    Path("/opt/BurpSuiteCommunity"),
    Path("/opt/BurpSuitePro"),
    Path("/usr/bin"),
    Path("/usr/local/bin"),
    Path("/usr/lib/jvm"),
    Path("/usr/java"),
    Path("/opt/java"),
    Path("/opt/jdk"),
    Path("/opt/jre"),
    Path("/Library/Java/JavaVirtualMachines"),
    Path.home() / ".jenv" / "shims",
    Path.home() / ".sdkman" / "candidates" / "java" / "current" / "bin",
]


def java_binary_name() -> str:
    return "java.exe" if sys.platform == "win32" else "java"


def probe_java(path: Path) -> Path | None:
    try:
        result = subprocess.run(
            [str(path), "-version"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0 or result.stderr:
            return path
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


_VERSION_RE = re.compile(r'version "(\d+)(?:\.(\d+))?')


def get_java_major_version(path: Path) -> int | None:
    try:
        result = subprocess.run(
            [str(path), "-version"],
            capture_output=True,
            timeout=5,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    output = (result.stdout or "") + (result.stderr or "")
    match = _VERSION_RE.search(output)
    if not match:
        return None

    major = int(match.group(1))
    if major == 1 and match.group(2):
        return int(match.group(2))
    return major


def find_in_path() -> Path | None:
    found = shutil.which("java")
    if found:
        return Path(found).resolve()
    return None


def find_in_java_home() -> Path | None:
    java_home = os.environ.get("JAVA_HOME", "")
    if not java_home:
        return None
    candidate = Path(java_home) / "bin" / java_binary_name()
    if candidate.is_file():
        return candidate.resolve()
    return None


def _candidate_binaries(base: Path, binary: str) -> list[Path]:
    paths = [base / binary]
    try:
        children = sorted(base.iterdir(), reverse=True)
    except OSError:
        return paths
    for child in children:
        paths.append(child / "bin" / binary)
        paths.append(child / "Contents" / "Home" / "bin" / binary)
    return paths


def find_in_common_dirs() -> Path | None:
    dirs = WINDOWS_JAVA_DIRS if sys.platform == "win32" else UNIX_JAVA_DIRS
    binary = java_binary_name()

    for base in dirs:
        if not base.is_dir():
            continue
        for candidate in _candidate_binaries(base, binary):
            if candidate.is_file() and probe_java(candidate):
                return candidate.resolve()

    return None


def auto_find() -> Path | None:
    result = find_in_path()
    if result:
        return result

    result = find_in_java_home()
    if result:
        return result

    result = find_in_common_dirs()
    if result:
        return result

    return None


def find_all_in_common_dirs(probe: bool = True) -> list[Path]:
    dirs = WINDOWS_JAVA_DIRS if sys.platform == "win32" else UNIX_JAVA_DIRS
    binary = java_binary_name()
    found: list[Path] = []
    seen: set[Path] = set()

    for base in dirs:
        if not base.is_dir():
            continue
        for candidate in _candidate_binaries(base, binary):
            if not candidate.is_file():
                continue
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            if probe and not probe_java(candidate):
                continue
            seen.add(resolved)
            found.append(resolved)

    return found


def burp_bundled_java(burp_jar: Path | None) -> Path | None:
    if not burp_jar:
        return None
    root = Path(burp_jar).parent
    binary = java_binary_name()
    layouts = (
        ("jre", "bin"),
        ("jre.bundle", "Contents", "Home", "bin"),
        ("jre", "Contents", "Home", "bin"),
    )
    for layout in layouts:
        candidate = root.joinpath(*layout, binary)
        if candidate.is_file():
            return candidate.resolve()
    return None


def find_all_java_paths(burp_jar: Path | None = None, probe: bool = True) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()

    def _add(path: Path | None) -> None:
        if path and path not in seen:
            seen.add(path)
            paths.append(path)

    _add(burp_bundled_java(burp_jar))
    _add(find_in_path())
    _add(find_in_java_home())
    for path in find_all_in_common_dirs(probe=probe):
        _add(path)
    return paths


def list_installed_javas() -> list[tuple[Path, int | None]]:
    return [(path, get_java_major_version(path)) for path in find_all_java_paths()]


_PROPERTY_RE = re.compile(
    r"^\s*(java\.version|java\.vendor|java\.specification\.version)\s*=\s*(.+?)\s*$",
    re.MULTILINE,
)

_describe_cache: dict[tuple[str, int], dict] = {}


def _spec_major(text: str | None) -> int | None:
    if not text:
        return None
    parts = text.strip().split(".")
    try:
        if parts[0] == "1" and len(parts) > 1:
            return int(parts[1])
        return int(parts[0])
    except ValueError:
        return None


def describe_java(path: Path) -> dict | None:
    try:
        stamp = path.stat().st_mtime_ns
    except OSError:
        return None

    key = (str(path), stamp)
    if key in _describe_cache:
        return _describe_cache[key]

    try:
        result = subprocess.run(
            [str(path), "-XshowSettings:properties", "-version"],
            capture_output=True,
            timeout=15,
            text=True,
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    output = (result.stdout or "") + "\n" + (result.stderr or "")
    props = dict(_PROPERTY_RE.findall(output))

    major = _spec_major(props.get("java.specification.version"))
    if major is None:
        match = _VERSION_RE.search(output)
        if match:
            major = int(match.group(1))
            if major == 1 and match.group(2):
                major = int(match.group(2))
    if major is None:
        return None

    info = {
        "major": major,
        "version": props.get("java.version") or str(major),
        "vendor": props.get("java.vendor") or "Unknown vendor",
    }
    _describe_cache[key] = info
    return info


def tested_java_major(required: int | None = None) -> int:
    return required if required else TESTED_JAVA_MAJOR


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(-int(part) for part in re.findall(r"\d+", version))


def _rank_key(candidate: dict, target: int) -> tuple:
    return (
        0 if candidate["compatible"] else 1,
        0 if candidate["bundled"] else 1,
        0 if candidate["major"] == target else 1,
        abs(candidate["major"] - target),
        1 if candidate["major"] < target else 0,
        _version_key(candidate["version"]),
        candidate["path"].lower(),
    )


def _dedupe_candidates(candidates: list[dict]) -> list[dict]:
    chosen: dict[tuple, dict] = {}
    order: list[tuple] = []
    for item in candidates:
        key = (item["vendor"], item["version"], item["bundled"])
        current = chosen.get(key)
        if current is None:
            chosen[key] = item
            order.append(key)
        elif "javapath" in current["path"].lower() and "javapath" not in item["path"].lower():
            chosen[key] = item
    return [chosen[key] for key in order]


def list_java_candidates(required: int | None = None, burp_jar: Path | None = None) -> list[dict]:
    target = tested_java_major(required)
    adjacent = burp_bundled_java(burp_jar)
    candidates: list[dict] = []

    for path in find_all_java_paths(burp_jar, probe=False):
        info = describe_java(path)
        if info is None:
            continue
        candidates.append({
            "path": str(path),
            "major": info["major"],
            "version": info["version"],
            "vendor": info["vendor"],
            "bundled": adjacent is not None and path == adjacent,
            "compatible": required is None or info["major"] >= required,
        })

    candidates = _dedupe_candidates(candidates)
    candidates.sort(key=lambda item: _rank_key(item, target))

    for index, item in enumerate(candidates):
        item["recommended"] = item["compatible"] and (item["bundled"] or item["major"] == target)
        item["default"] = index == 0
        item["label"] = f"Java {item['major']} ({item['vendor']} {item['version']})"

    return candidates


def find_best_java(min_version: int | None = None, burp_jar: Path | None = None) -> Path | None:
    candidates = list_java_candidates(min_version, burp_jar)
    if candidates:
        return Path(candidates[0]["path"])
    return auto_find()


def validate_java(path: Path) -> Path:
    path = path.expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Java binary not found: {path}")
    if not path.is_file():
        raise ValueError(f"Expected a file, got: {path}")
    result = probe_java(path)
    if result is None:
        raise ValueError(f"Path does not appear to be a valid Java binary: {path}")
    return path


def resolve_java_path(
    args: argparse.Namespace,
    required: int | None = None,
    burp_jar: Path | None = None,
) -> Path:
    if hasattr(args, "java_browse") and args.java_browse:
        return validate_java(Path(args.java_browse))

    if hasattr(args, "java_auto") and args.java_auto:
        found = find_best_java(required, burp_jar)
        if found:
            return found
        raise FileNotFoundError(
            "Java binary not found automatically. "
            "Use --java-browse <path> to specify it manually."
        )

    raise ValueError(
        "No Java source specified. "
        "Use --java-auto or --java-browse <path>."
    )


def add_java_path_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--java-auto",
        action="store_true",
        help="Automatically locate Java binary on the system.",
    )
    parser.add_argument(
        "--java-browse",
        metavar="PATH",
        help="Path to the Java binary (java or java.exe).",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Locate Java binary for BurpSuite.")
    add_java_path_args(parser)
    args = parser.parse_args()

    try:
        java = resolve_java_path(args)
        print(java)
        sys.exit(0)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()