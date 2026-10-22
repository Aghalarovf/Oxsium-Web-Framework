import json
import os
import sys
from pathlib import Path


def default_user_config_path(edition: str = "community") -> Path:
    name = "UserConfigPro.json" if edition.lower().startswith("pro") else "UserConfigCommunity.json"

    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return base / "BurpSuite" / name
    return Path.home() / ".BurpSuite" / name


def detect_edition(burp_jar: Path) -> str:
    name = Path(burp_jar).name.lower()
    return "professional" if "pro" in name else "community"


def _load_existing(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _ensure_path(data: dict, *keys: str) -> dict:
    node = data
    for key in keys:
        node = node.setdefault(key, {})
    return node


def merge_jython_and_extension(
    existing: dict,
    jython_jar: Path,
    extension_file: Path,
    extension_name: str = "Burp Exporter",
    overwrite: bool = True,
) -> "tuple[dict, dict]":
    data = json.loads(json.dumps(existing)) if existing else {}

    extender = _ensure_path(data, "user_options", "extender")

    python_settings = _ensure_path(data, "user_options", "extender", "python")
    jython_already_configured = bool(python_settings.get("location_of_jython_standalone_jar_file"))
    if overwrite or not jython_already_configured:
        python_settings["location_of_jython_standalone_jar_file"] = str(jython_jar)

    extensions = extender.setdefault("extensions", [])

    extension_file_str = str(extension_file)
    entry = next((e for e in extensions if e.get("extension_file") == extension_file_str), None)
    extension_already_configured = entry is not None

    if entry is None:
        extensions.append({
            "extension_file": extension_file_str,
            "extension_type": "python",
            "name": extension_name,
            "loaded": True,
            "errors": "ui",
            "output": "ui",
        })
    elif overwrite:
        entry.update({
            "extension_file": extension_file_str,
            "extension_type": "python",
            "name": extension_name,
            "loaded": True,
            "errors": "ui",
            "output": "ui",
        })

    extender_settings = _ensure_path(data, "user_options", "extender", "settings")
    if overwrite or "automatically_reload_extensions_on_startup" not in extender_settings:
        extender_settings["automatically_reload_extensions_on_startup"] = True

    status = {
        "jython_already_configured": jython_already_configured,
        "extension_already_configured": extension_already_configured,
    }
    return data, status


def apply_jython_and_extension(
    jython_jar: Path,
    extension_file: Path,
    burp_jar: "Path | None" = None,
    config_path: "Path | None" = None,
    overwrite: bool = True,
) -> dict:
    jython_jar = Path(jython_jar)
    extension_file = Path(extension_file)

    if not jython_jar.is_file():
        raise FileNotFoundError(f"Jython JAR not found: {jython_jar}")
    if not extension_file.is_file():
        raise FileNotFoundError(f"Extension file not found: {extension_file}")

    if config_path is None:
        edition = detect_edition(burp_jar) if burp_jar else "community"
        config_path = default_user_config_path(edition)

    config_path = Path(config_path)
    existing = _load_existing(config_path)
    merged, status = merge_jython_and_extension(
        existing, jython_jar, extension_file, overwrite=overwrite
    )

    config_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = config_path.with_suffix(config_path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    tmp_path.replace(config_path)

    return {
        "user_config_file": str(config_path),
        "jython_jar": str(jython_jar),
        "extension_file": str(extension_file),
        "created_new_file": not existing,
        "jython_already_configured": status["jython_already_configured"],
        "extension_already_configured": status["extension_already_configured"],
        "launch_flag": f'--user-config-file="{config_path}"',
    }