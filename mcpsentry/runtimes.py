"""Find installed client launchers without opening a GUI or modifying PATH."""

import os
from pathlib import Path
import shutil


def client_executable(name):
    path = shutil.which(name)
    if path:
        return path
    if name == "cursor":
        candidate = Path("/Applications/Cursor.app/Contents/Resources/app/bin/cursor")
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None
