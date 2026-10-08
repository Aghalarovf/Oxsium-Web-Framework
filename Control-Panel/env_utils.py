"""
core/env_utils.py
─────────────────
Sets up virtual environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path

from config import ROOT


def build_env(extra: dict | None = None) -> dict:
    """
    Prepares environment variables for the process.
    `extra` — additional variables to pass to subprocess (e.g. PORT, HOST).
    """
    env = os.environ.copy()
    venv_bin = ROOT / "oxsium" / ("Scripts" if os.name == "nt" else "bin")

    env["PATH"]                    = str(venv_bin) + os.pathsep + env.get("PATH", "")
    env["VIRTUAL_ENV"]             = str(ROOT / "oxsium")
    env["PYTHONUNBUFFERED"]        = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    if extra:
        env.update(extra)
    return env