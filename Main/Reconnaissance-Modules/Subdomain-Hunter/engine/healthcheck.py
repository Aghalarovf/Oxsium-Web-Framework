from __future__ import annotations

import requests

from core.config import USER_AGENT
from sources import ALL_SOURCES


def run_health_check(keys: dict) -> None:
    missing: list[tuple[str, list[str]]] = []

    for cls in ALL_SOURCES:
        if not cls.enabled:
            continue

        # Collect what keys this source needs and which are absent
        needs: list[str] = []

        if cls.required_keys:
            needs = [k for k in cls.required_keys if not keys.get(k)]
        elif cls.requires_api_key:
            # requires_api_key=True but no required_keys tuple declared (e.g. Censys).
            # Fall back to matching known ENV_FALLBACKS keys by source name prefix.
            from core.config import ENV_FALLBACKS
            guessed = [k for k in ENV_FALLBACKS if k == cls.name or k.startswith(cls.name + "_")]
            needs = [k for k in guessed if not keys.get(k)]

        if needs:
            missing.append((cls.name, needs))

    if not missing:
        print("All sources are ready.")
        return

    col_w = max(len(name) for name, _ in missing)
    for name, need in missing:
        print(f"  {name:<{col_w}}  missing: {', '.join(need)}")