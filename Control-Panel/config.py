"""
Control-Panel/config.py
"""
from __future__ import annotations
import os, sys
from pathlib import Path

ROOT        = Path(__file__).resolve().parent.parent
VENV_PYTHON = (ROOT / "oxsium"
               / ("Scripts" if os.name == "nt" else "bin")
               / ("python.exe" if os.name == "nt" else "python"))
PYTHON      = VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable)

FILES: dict[str, Path] = {
    "connection":   ROOT / "Main" / "Backend" / "connection.py",
    "database_api": ROOT / "Main" / "SQLite-Engine" / "database-api.py",
    "html":         ROOT / "Main" / "Oxsium-Web-Framework.html",
}

DEFAULT_PORTS: dict[str, int] = {
    "connection":   30300,
    "database_api": 30301,
    "http":         30305,
}

class C:
    # === BACKGROUNDS ===
    BASE    = "#12110F"      # main background — slightly lighter dark
    SURF0   = "#1A1814"      # panel background
    SURF1   = "#201E18"      # header/bar background
    SURF2   = "#272420"      # hover background
    SURF3   = "#2E2A22"      # selected element

    # === BORDERS ===
    BDR0    = "#2E2A22"
    BDR1    = "#3D3828"
    BDR2    = "#524C35"

    # === GOLD PALETTE ===
    G0      = "#9A7A2A"      # deep gold
    G1      = "#C8962E"      # dark gold
    G2      = "#E4B038"      # main gold
    G3      = "#F5C842"      # bright gold
    G4      = "#FFD966"      # brightest gold (accent)
    G_DIM   = "#221A00"      # gold background (dark)
    G_MID   = "#2E2200"      # gold background (mid)
    G_GLOW  = "#4A3800"      # gold glow background

    # === STATUS COLORS ===
    GREEN   = "#5DD97A"
    GREEN_B = "#0A2010"
    RED     = "#E05555"
    RED_B   = "#220A0A"
    AMBER   = "#E09A3A"
    AMBER_B = "#221200"

    # === TEXT — significantly lighter ===
    T0      = "#F8EDD0"      # primary text — bright cream
    T1      = "#E0C07A"      # secondary text — warm yellow
    T2      = "#B08840"      # muted text
    T3      = "#7A6030"      # very muted
    TCO     = "#DDB850"      # console output — bright amber
    TPATH   = "#8A7040"      # file path

    # === SIDEBAR ===
    SB_BG   = "#0D0C0A"
    SB_SEL  = "#1A1600"
    SB_W    = 56

    # === ALIASES ===
    BLUE    = G2
    BLUE_B  = G_DIM
    GOLD    = G3
    GOLD2   = G4
    TEAL    = G1


TERMINAL_FONT = "'Cascadia Code', 'JetBrains Mono', 'Fira Code', 'Consolas', 'Courier New', monospace"

QSS = f"""
* {{
    font-family: {TERMINAL_FONT};
    font-size: 12px;
    outline: none;
}}
QWidget     {{ background: transparent; color: {C.T0}; }}
QMainWindow {{ background: {C.BASE}; }}

QScrollBar:vertical {{
    background: {C.BASE}; width: 3px; border: none; margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {C.BDR2}; border-radius: 2px; min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{ background: {C.G2}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ height: 0; }}

QToolTip {{
    background: {C.SURF3};
    color: {C.T0};
    border: 1px solid {C.G0};
    padding: 5px 10px;
    border-radius: 6px;
    font-size: 11px;
    font-family: {TERMINAL_FONT};
}}

QSplitter::handle {{
    background: {C.BDR0};
}}
QSplitter::handle:hover {{
    background: {C.G0};
}}
"""

SERVICE_DEFS: list[tuple] = [
    ("connection",   "Connection",   "API Backend · Flask · DNS Engine",
     "connection",   "connection",   "API",  C.G3),
    ("database_api", "Database API", "Database API · Flask · Data Layer",
     "database_api", "database_api", "DB",   C.G1),
]

SIDEBAR_ENTRIES: list[tuple[str, str, str]] = [
    ("⇌", "Connection  ·  API / DNS Engine", C.G3),
    ("⊞", "Database API  ·  Data Layer",      C.G1),
    ("◉", "Web Viewer  ·  HTTP Server",       C.G4),
]