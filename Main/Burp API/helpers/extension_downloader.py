import argparse
import json
import os
import shutil
import sys
import urllib.request
from pathlib import Path

try:
    from helpers.burpsuite_jar import detect_edition
except ImportError:
    from burpsuite_jar import detect_edition

JYTHON_URL = "https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.4/jython-standalone-2.7.4.jar"
EXTENSION_NAME = "Oxsium Burp Exporter"

CONFIG_NAMES = {
    "Professional": "UserConfigPro.json",
    "Community": "UserConfigCommunity.json",
}


def burp_home() -> Path:
    return Path.home() / ".BurpSuite"


def config_files_for(jar: Path) -> list[Path]:
    edition = detect_edition(jar)
    base = burp_home()
    if edition in CONFIG_NAMES:
        return [base / CONFIG_NAMES[edition]]
    existing = [base / name for name in CONFIG_NAMES.values() if (base / name).is_file()]
    if existing:
        return existing
    raise FileNotFoundError(
        f"Cannot determine the Burp Suite edition of {jar}. "
        "Rename the JAR to include 'pro' or 'community', or start Burp once to create its config."
    )


def ensure_jython(jython_jar: Path) -> Path:
    if jython_jar.is_file():
        return jython_jar
    jython_jar.parent.mkdir(parents=True, exist_ok=True)
    tmp = jython_jar.with_suffix(".part")
    with urllib.request.urlopen(JYTHON_URL, timeout=60) as response, open(tmp, "wb") as out:
        shutil.copyfileobj(response, out)
    os.replace(tmp, jython_jar)
    return jython_jar


def load_config(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size == 0:
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_config(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        backup = path.with_name(path.name + ".oxsium.bak")
        if not backup.exists():
            shutil.copy2(path, backup)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    os.replace(tmp, path)


def apply_to_config(data: dict, jython_jar: Path, extension_file: Path) -> dict:
    extender = data.setdefault("user_options", {}).setdefault("extender", {})
    extender.setdefault("python", {})["location_of_jython_standalone_jar"] = str(jython_jar)

    extensions = extender.setdefault("extensions", [])
    target = str(extension_file)
    entry = {
        "errors": "ui",
        "extension_file": target,
        "extension_type": "python",
        "loaded": True,
        "name": EXTENSION_NAME,
        "output": "ui",
    }
    for index, current in enumerate(extensions):
        if os.path.normcase(str(current.get("extension_file", ""))) == os.path.normcase(target):
            extensions[index] = {**current, **entry}
            break
    else:
        extensions.append(entry)
    return data


def configure(burp_jar: Path, jython_jar: Path, extension_file: Path) -> dict:
    burp_jar = Path(burp_jar).expanduser().resolve()
    extension_file = Path(extension_file).expanduser().resolve()
    jython_jar = Path(jython_jar).expanduser().resolve()

    if not burp_jar.is_file():
        raise FileNotFoundError(f"Burp Suite JAR not found: {burp_jar}")
    if detect_edition(burp_jar) == "Enterprise":
        raise ValueError("Burp Suite Enterprise does not support BApp extensions.")
    if not extension_file.is_file():
        raise FileNotFoundError(f"Extension file not found: {extension_file}")

    ensure_jython(jython_jar)
    configs = config_files_for(burp_jar)
    for path in configs:
        write_config(path, apply_to_config(load_config(path), jython_jar, extension_file))

    return {
        "burp_jar": str(burp_jar),
        "edition": detect_edition(burp_jar),
        "jython_jar": str(jython_jar),
        "extension_file": str(extension_file),
        "config_files": [str(p) for p in configs],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Integrate Jython and the Oxsium extension into Burp Suite.")
    parser.add_argument("--burp-jar", required=True)
    parser.add_argument("--jython-jar", required=True)
    parser.add_argument("--extension", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(configure(Path(args.burp_jar), Path(args.jython_jar), Path(args.extension)), indent=2))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()