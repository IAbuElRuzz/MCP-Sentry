"""Source-tree launcher for clients that do not support an MCP cwd setting."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mcpsentry.cli import main

main()
