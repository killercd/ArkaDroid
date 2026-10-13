"""Source and PyInstaller entry point for the Windows desktop application."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from droidboard.desktop import main

if __name__ == "__main__":
    raise SystemExit(main())
