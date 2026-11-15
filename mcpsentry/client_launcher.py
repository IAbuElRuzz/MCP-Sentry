"""Absolute launcher for desktop MCP hosts with an unrelated working directory."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcpsentry.cli import main

if __name__ == "__main__":
    main()
