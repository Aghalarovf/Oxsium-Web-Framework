import json
import os
import sys
from typing import Optional

ENV_FALLBACKS: dict[str, str] = {
    "virustotal": "VIRUSTOTAL_API_KEY",
    "intelx":     "INTELX_API_KEY",
    "intelx_host": "INTELX_HOST",
    "urlscan":    "URLSCAN_API_KEY",
    "otx":        "OTX_API_KEY",
}


def load_keys(api_keys_path: Optional[str] = None) -> dict[str, str]:
    keys: dict[str, str] = {}
    for name, env in ENV_FALLBACKS.items():
        if os.environ.get(env):
            keys[name] = os.environ[env].strip()

    candidates: list[str] = []
    if api_keys_path:
        candidates.append(api_keys_path)
    candidates.append(os.path.join(os.getcwd(), "api_keys.json"))
    candidates.append(
        os.path.join(os.path.expanduser("~"), ".config", "subdomain-hunter", "api_keys.json")
    )

    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            print(f"[!] could not read key file {path}: {exc}", file=sys.stderr)
            continue
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, str) and v.strip():
                    keys[k] = v.strip()
        break
    return keys
