"""
Shared helpers used by every attack-stage script:

  * DvwaSession   - logged-in requests.Session against the target DVWA,
                    with the CSRF (`user_token`) scraping DVWA requires.
  * GroundTruth   - append-only JSONL logger the attacker side uses to
                    record what it *actually did and when*. This is the
                    label file that collector/correlation_export.py joins
                    against the defender-side alerts (Suricata/Apache) to
                    build the supervised/RL training dataset.

Keeping ground truth on the attacker side (rather than trying to infer it
after the fact from logs) is what makes this a useful correlation dataset:
you get a trustworthy timestamped label for "attack stage X started/ended
at time T", independent of whatever the detectors did or didn't catch.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

import config

TOKEN_RE = re.compile(r"user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", re.IGNORECASE)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DvwaSession:
    """A logged-in DVWA session with CSRF-token-aware GET/POST helpers."""

    def __init__(self, base_url: str = config.DVWA_BASE_URL):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def login(self, username: str = config.DVWA_ADMIN_USER, password: str = config.DVWA_ADMIN_PASS) -> None:
        r = self.session.get(f"{self.base_url}/login.php", timeout=10)
        r.raise_for_status()
        token = self._token(r.text)
        r = self.session.post(
            f"{self.base_url}/login.php",
            data={"username": username, "password": password, "Login": "Login", "user_token": token},
            timeout=10,
        )
        r.raise_for_status()

    def _token(self, html: str) -> str:
        m = TOKEN_RE.search(html)
        if not m:
            raise RuntimeError("Could not find DVWA CSRF user_token in response.")
        return m.group(1)

    def fresh_token(self, path: str) -> str:
        r = self.session.get(f"{self.base_url}/{path.lstrip('/')}", timeout=10)
        r.raise_for_status()
        return self._token(r.text)

    def get(self, path: str, **kwargs) -> requests.Response:
        return self.session.get(f"{self.base_url}/{path.lstrip('/')}", timeout=10, **kwargs)

    def post(self, path: str, **kwargs) -> requests.Response:
        return self.session.post(f"{self.base_url}/{path.lstrip('/')}", timeout=10, **kwargs)


@dataclass
class GroundTruth:
    """Append-only JSONL ground-truth logger for one attack-chain run."""

    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    path: Path = config.GROUND_TRUTH_FILE

    def _write(self, record: dict) -> None:
        record.setdefault("run_id", self.run_id)
        with open(self.path, "a") as f:
            f.write(json.dumps(record) + "\n")

    @contextmanager
    def stage(self, name: str, details: Optional[dict] = None):
        """Context manager: logs stage_start / stage_end with MITRE mapping.

        Usage:
            with gt.stage("sqli", {"payload": "..."}):
                ... do the exploit ...
        """
        mitre = config.STAGE_MITRE_MAP.get(name, {})
        start = now_iso()
        self._write({
            "event": "stage_start", "stage": name, "timestamp": start,
            "mitre_tactic": mitre.get("tactic"), "mitre_technique": mitre.get("technique"),
            "details": details or {},
        })
        t0 = time.time()
        try:
            yield
            status = "success"
        except Exception as e:
            status = f"error: {e}"
            raise
        finally:
            end = now_iso()
            self._write({
                "event": "stage_end", "stage": name, "timestamp": end,
                "mitre_tactic": mitre.get("tactic"), "mitre_technique": mitre.get("technique"),
                "status": status, "duration_seconds": round(time.time() - t0, 3),
            })

    def note(self, stage: str, message: str, **extra) -> None:
        """Log a fine-grained event inside a stage (e.g. each brute-force attempt)."""
        self._write({"event": "note", "stage": stage, "timestamp": now_iso(), "message": message, **extra})
