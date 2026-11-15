"""Context cues plus an opt-in local classifier. Never overrides deterministic DLP."""

import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import signal
import os

CATEGORIES = {"confidential_text", "health_information", "personal_information"}
RULES = {
    "confidential_text": [r"\bconfidential\s*[:\-]", r"\b(?:internal use only|do not distribute|not for public release|under nda)\b", r"\b(?:unreleased|nonpublic|non-public)\b.{0,100}\b(?:results|roadmap|acquisition|financial|strategy)\b"],
    "health_information": [r"\b(?:patient|he|she|they|[A-Z][a-z]+)\b.{0,100}\b(?:diagnosed with|undergoing (?:chemotherapy|treatment)|prescribed|medical history)\b", r"\b(?:patient|medical|health)\s+(?:record|history|diagnosis)\s*[:\-]"],
    "personal_information": [r"\b(?:date of birth|passport number|social security number|home address|employee salary)\s*[:\-]", r"\b(?:he|she|they) lives? at\b"],
}


def validate(config):
    if not isinstance(config, dict) or set(config) - {"mode", "command", "timeout_seconds"}:
        raise ValueError("Invalid semantic configuration")
    mode = config.get("mode", "context")
    if mode not in ("off", "context", "command"):
        raise ValueError("semantic.mode must be off, context, or command")
    timeout = config.get("timeout_seconds", 5)
    if type(timeout) not in (int, float) or not 0.1 <= timeout <= 30:
        raise ValueError("Invalid semantic timeout")
    command = config.get("command")
    if mode == "command":
        if not isinstance(command, list) or not command or any(not isinstance(x, str) or not x or "\x00" in x for x in command) or not Path(command[0]).is_absolute():
            raise ValueError("Semantic command requires an explicit absolute executable and argument list")
    elif command is not None:
        raise ValueError("Semantic command requires command mode")


def context_categories(text):
    return {category for category, rules in RULES.items() if any(re.search(rule, text, re.I | re.S) for rule in rules)}


def classify(texts, config):
    """Return categories, complete. Values never appear in errors or logs."""
    if config.get("mode", "context") == "off":
        return set(), True
    found = set().union(*(context_categories(t) for t in texts)) if texts else set()
    if config.get("mode", "context") != "command":
        return found, True
    if sum(map(len, texts)) > 65536:
        return found, False
    try:
        timeout = config.get("timeout_seconds", 5)
        launcher = [sys.executable, "-I", str(Path(__file__).with_name("limit_exec.py")), "8192", str(timeout), *config["command"]]
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(launcher, stdin=subprocess.PIPE, stdout=output, stderr=subprocess.DEVNULL, start_new_session=True)
            try:
                process.communicate(input=json.dumps({"texts": texts, "allowed_categories": sorted(CATEGORIES)}).encode(), timeout=timeout)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                if process.stdin:
                    process.stdin.close()
            output.seek(0)
            raw = output.read(8193)
        if process.returncode or len(raw) > 8192:
            return found, False
        result = json.loads(raw)
        if not isinstance(result, dict) or set(result) != {"categories"} or not isinstance(result["categories"], list) or any(not isinstance(x, str) or x not in CATEGORIES for x in result["categories"]):
            return found, False
        return found | set(result["categories"]), True
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return found, False
