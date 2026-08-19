"""
Common normalized alert/event schema used across all defender-side sources
(Suricata, Apache access/error logs, the behavioral brute-force detector,
optionally MySQL). Everything gets flattened into this shape before it hits
SQLite, so the dashboard and correlation export don't need to know which
source an alert came from.
"""
from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class Alert:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: str = ""          # ISO8601 UTC
    source: str = ""             # suricata | apache_access | apache_error | apache_behavioral | mysql
    category: str = ""           # recon | bruteforce | sqli | upload_rce | c2_discovery | exfiltration | other
    signature: str = ""          # human-readable alert message
    severity: Optional[int] = None
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    proto: Optional[str] = None
    raw: str = ""


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT,
    category TEXT,
    signature TEXT,
    severity INTEGER,
    src_ip TEXT,
    dest_ip TEXT,
    dest_port INTEGER,
    proto TEXT,
    raw TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);

CREATE TABLE IF NOT EXISTS ground_truth (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    event TEXT NOT NULL,      -- stage_start | stage_end | note
    stage TEXT,
    mitre_tactic TEXT,
    mitre_technique TEXT,
    timestamp TEXT NOT NULL,
    status TEXT,
    duration_seconds REAL,
    message TEXT,
    details TEXT
);
CREATE INDEX IF NOT EXISTS idx_gt_timestamp ON ground_truth(timestamp);
CREATE INDEX IF NOT EXISTS idx_gt_run_id ON ground_truth(run_id);
"""


def get_connection(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA_SQL)
    return conn


def insert_alert(conn: sqlite3.Connection, alert: Alert) -> None:
    d = asdict(alert)
    conn.execute(
        """INSERT OR IGNORE INTO alerts
           (id, timestamp, source, category, signature, severity, src_ip, dest_ip, dest_port, proto, raw)
           VALUES (:id, :timestamp, :source, :category, :signature, :severity, :src_ip, :dest_ip, :dest_port, :proto, :raw)""",
        d,
    )
