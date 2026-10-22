import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.pycache_prefix = str(PROJECT_ROOT / "pycache")

from core.cli import main

if __name__ == "__main__":
    sys.exit(main())
