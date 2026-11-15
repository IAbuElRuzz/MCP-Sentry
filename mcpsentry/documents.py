"""Inspect inline PDF/OOXML documents in a resource-limited worker process."""

import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile
import time

LIMIT = 1_048_576


class WatchdogUnavailable(Exception):
    pass


def kind(raw):
    if b"%PDF-" in raw[:1024]:
        return "pdf"
    if raw.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                names = set(archive.namelist())
                if {name.lower() for name in names}.intersection({"word/document.xml", "xl/workbook.xml", "ppt/presentation.xml"}):
                    return "office"
        except (ValueError, zipfile.BadZipFile):
            pass
    return None


def extract(raw, document_kind):
    if len(raw) > LIMIT:
        return {"texts": [], "complete": False, "issue": "document_too_large"}
    try:
        process = subprocess.Popen([sys.executable, "-I", str(Path(__file__).with_name("document_worker.py")), document_kind], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        deadline, first = time.monotonic() + 5, True
        try:
            while True:
                try:
                    output, _ = process.communicate(input=raw if first else None, timeout=0.2)
                    break
                except subprocess.TimeoutExpired:
                    first = False
                    if time.monotonic() >= deadline:
                        raise ValueError("document_timeout")
                    if sys.platform == "darwin":
                        try:
                            usage = subprocess.run(["ps", "-o", "rss=", "-p", str(process.pid)], capture_output=True, timeout=0.5)
                        except (OSError, subprocess.TimeoutExpired) as exc:
                            raise WatchdogUnavailable from exc
                        if usage.returncode != 0 and process.poll() is None:
                            raise WatchdogUnavailable
                        if usage.returncode == 0 and int(usage.stdout.strip() or b"0") > 384 * 1024:
                            raise ValueError("document_memory_limit")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
            for pipe in (process.stdin, process.stdout):
                if pipe is not None:
                    pipe.close()
        if process.returncode or len(output) > LIMIT:
            raise ValueError("document_worker_failed")
        result = json.loads(output)
        if set(result) != {"texts", "complete", "issue"} or type(result["complete"]) is not bool or not isinstance(result["texts"], list) or any(not isinstance(t, str) for t in result["texts"]):
            raise ValueError("invalid_document_result")
        return result
    except WatchdogUnavailable:
        return {"texts": [], "complete": False, "issue": "document_memory_watchdog_unavailable"}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {"texts": [], "complete": False, "issue": "document_extraction_failed"}
