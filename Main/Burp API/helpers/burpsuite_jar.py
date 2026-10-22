import argparse
import os
import string
import struct
import sys
import zipfile
from pathlib import Path


SEARCH_PATTERNS = [
    "burpsuite*.jar",
    "burp-suite*.jar",
    "burp_suite*.jar",
    "burp*.jar",
]

PRIORITY_DIRS_WINDOWS = [
    Path(os.environ.get("ProgramFiles", "C:/Program Files")),
    Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")),
    Path(os.environ.get("LOCALAPPDATA", "")),
    Path(os.environ.get("APPDATA", "")),
    Path(os.environ.get("USERPROFILE", "")),
]

PRIORITY_DIRS_UNIX = [
    Path.home(),
    Path("/opt"),
    Path("/usr/local"),
    Path("/usr/share"),
    Path("/Applications"),
]

SKIP_DIRS_WINDOWS = {
    "windows", "system32", "syswow64", "winsxs",
    "$recycle.bin", "system volume information",
}


def system_roots() -> list[Path]:
    if sys.platform == "win32":
        return [
            Path(f"{d}:/")
            for d in string.ascii_uppercase
            if Path(f"{d}:/").exists()
        ]
    return [Path("/")]


def priority_dirs() -> list[Path]:
    if sys.platform == "win32":
        return [p for p in PRIORITY_DIRS_WINDOWS if p != Path("")]
    return PRIORITY_DIRS_UNIX


def find_jar_in(directory: Path) -> Path | None:
    if not directory.is_dir():
        return None
    for pattern in SEARCH_PATTERNS:
        matches = sorted(directory.glob(pattern))
        if matches:
            return matches[-1]
    return None


def _walk_for_jar(root: Path) -> Path | None:
    try:
        for entry in root.iterdir():
            if not entry.is_dir():
                continue
            if sys.platform == "win32" and entry.name.lower() in SKIP_DIRS_WINDOWS:
                continue
            result = find_jar_in(entry)
            if result:
                return result
            nested = _walk_for_jar(entry)
            if nested:
                return nested
    except PermissionError:
        pass
    return None


def auto_find() -> Path | None:
    for d in priority_dirs():
        for pattern in SEARCH_PATTERNS:
            try:
                matches = sorted(d.rglob(pattern))
            except PermissionError:
                continue
            if matches:
                return matches[-1]

    for root in system_roots():
        result = _walk_for_jar(root)
        if result:
            return result

    return None


_CLASS_MAGIC = b"\xca\xfe\xba\xbe"

_CLASS_MAJOR_TO_JAVA = {44 + n: n for n in range(8, 30)}

_SCAN_SAMPLE_LIMIT = 500


def class_major_to_java_version(major: int | None) -> int | None:
    if major is None:
        return None
    return _CLASS_MAJOR_TO_JAVA.get(major)


def _read_class_major(data: bytes) -> int | None:
    if len(data) < 8 or data[:4] != _CLASS_MAGIC:
        return None
    return struct.unpack(">H", data[6:8])[0]


def get_jar_required_major_version(jar_path: Path) -> int | None:
    try:
        with zipfile.ZipFile(jar_path) as zf:
            main_class = None
            try:
                manifest = zf.read("META-INF/MANIFEST.MF").decode("utf-8", "ignore")
                for line in manifest.splitlines():
                    if line.strip().startswith("Main-Class:"):
                        main_class = line.split(":", 1)[1].strip()
                        break
            except KeyError:
                pass

            if main_class:
                entry = main_class.replace(".", "/") + ".class"
                try:
                    major = _read_class_major(zf.read(entry))
                    if major:
                        return major
                except KeyError:
                    pass

            highest = None
            scanned = 0
            for name in zf.namelist():
                if not name.endswith(".class") or "META-INF/versions/" in name:
                    continue
                scanned += 1
                if scanned > _SCAN_SAMPLE_LIMIT:
                    break
                try:
                    major = _read_class_major(zf.read(name))
                except (KeyError, zipfile.BadZipFile):
                    continue
                if major and (highest is None or major > highest):
                    highest = major
            return highest
    except (OSError, zipfile.BadZipFile):
        return None


def get_jar_required_java_version(jar_path: Path) -> int | None:
    return class_major_to_java_version(get_jar_required_major_version(jar_path))


def validate_jar(path: Path) -> Path:
    path = path.expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"JAR not found: {path}")
    if path.suffix.lower() != ".jar":
        raise ValueError(f"Expected a .jar file, got: {path}")
    return path


def resolve_burp_jar(args: argparse.Namespace) -> Path:
    if hasattr(args, "burp_browse") and args.burp_browse:
        return validate_jar(Path(args.burp_browse))

    if hasattr(args, "burp_auto") and args.burp_auto:
        found = auto_find()
        if found:
            return found
        raise FileNotFoundError(
            "BurpSuite JAR not found automatically. "
            "Use --burp-browse <path> to specify it manually."
        )

    raise ValueError(
        "No BurpSuite JAR source specified. "
        "Use --burp-auto or --burp-browse <path>."
    )


def add_burp_jar_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--burp-auto",
        action="store_true",
        help="Automatically locate BurpSuite JAR on the system.",
    )
    parser.add_argument(
        "--burp-browse",
        metavar="PATH",
        help="Path to the BurpSuite JAR file.",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Locate BurpSuite JAR file.")
    add_burp_jar_args(parser)
    args = parser.parse_args()

    if getattr(args, "burp_auto", False):
        print("Searching entire system for BurpSuite JAR...", file=sys.stderr)

    try:
        jar = resolve_burp_jar(args)
        print(jar)
        sys.exit(0)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()