#!/usr/bin/env python3
"""
Builds the labeled correlation dataset the dashboard (and, later, the RL
correlator) consumes:

  1. Loads ground_truth.jsonl (attacker-side stage start/end events) and
     upserts them into the `ground_truth` table in alerts.db, so the
     dashboard can query everything from one place.
  2. For each stage_start/stage_end pair, finds every alert in alerts.db
     whose timestamp falls in [stage_start - PAD, stage_end + PAD] and
     labels it with that stage/run_id -- this is the "which alerts
     correspond to which true attack stage" ground truth an RL reward
     function would need.
  3. Writes data/exports/correlated_dataset_<run_id or 'all'>.csv and logs
     a per-stage summary (alert counts, sources, categories) -- directly
     usable as a results table in the thesis.

Operational logging (this script's own progress/errors, not the alert
data) is structured, Log4j-style, via logging_setup.py: each summary row
is emitted as a structured log record (e.g. stage_alert_count) as well as
printed as a human-readable table, and everything also lands as JSON in
data/logs/correlation_export.log.

Run this AFTER a log_collector.py + run_attack_chain.py session (collector
can be stopped once the attack chain finishes).

Usage:
    python3 collector/correlation_export.py
    python3 collector/correlation_export.py --run-id <run_id> --pad 5
    python3 collector/correlation_export.py --log-level DEBUG
"""
import argparse
import json
import logging
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
from collector.schema import get_connection  # noqa: E402
from logging_setup import configure_logging  # noqa: E402

log = logging.getLogger("collector.correlation_export")


def parse_ts(ts: str) -> datetime:
    ts = ts.replace("Z", "+00:00")
    return datetime.fromisoformat(ts)


def load_ground_truth_into_db(conn: sqlite3.Connection, gt_path: Path) -> list[dict]:
    records = []
    if not gt_path.exists():
        log.warning("no ground truth file found", extra={"path": str(gt_path)})
        return records
    with open(gt_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            records.append(rec)
            conn.execute(
                """INSERT OR IGNORE INTO ground_truth
                   (id, run_id, event, stage, mitre_tactic, mitre_technique, timestamp, status, duration_seconds, message, details)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    f"{rec['run_id']}:{rec['event']}:{rec.get('stage')}:{rec['timestamp']}",
                    rec["run_id"], rec["event"], rec.get("stage"),
                    rec.get("mitre_tactic"), rec.get("mitre_technique"), rec["timestamp"],
                    rec.get("status"), rec.get("duration_seconds"), rec.get("message"),
                    json.dumps(rec.get("details")) if rec.get("details") else None,
                ),
            )
    conn.commit()
    log.info("ground truth loaded", extra={"path": str(gt_path), "record_count": len(records)})
    return records


def build_stage_windows(records: list[dict], pad_seconds: float) -> list[dict]:
    """Pair stage_start/stage_end records into time windows per (run_id, stage)."""
    starts = {}
    windows = []
    for rec in records:
        key = (rec["run_id"], rec["stage"])
        if rec["event"] == "stage_start":
            starts[key] = rec["timestamp"]
        elif rec["event"] == "stage_end" and key in starts:
            start = parse_ts(starts.pop(key)) - timedelta(seconds=pad_seconds)
            end = parse_ts(rec["timestamp"]) + timedelta(seconds=pad_seconds)
            windows.append({
                "run_id": rec["run_id"], "stage": rec["stage"],
                "mitre_tactic": rec.get("mitre_tactic"), "mitre_technique": rec.get("mitre_technique"),
                "start": start, "end": end,
            })
    log.info("stage windows built", extra={"window_count": len(windows), "pad_seconds": pad_seconds})
    return windows


def correlate(conn: sqlite3.Connection, windows: list[dict], run_id: str | None) -> list[dict]:
    cur = conn.execute("SELECT * FROM alerts ORDER BY timestamp")
    cols = [d[0] for d in cur.description]
    alerts = [dict(zip(cols, row)) for row in cur.fetchall()]
    log.info("alerts loaded for correlation", extra={"alert_count": len(alerts), "run_id": run_id or "all"})

    rows = []
    for alert in alerts:
        try:
            ts = parse_ts(alert["timestamp"])
        except (ValueError, KeyError) as e:
            log.debug("skipping alert with unparseable timestamp",
                      extra={"alert_id": alert.get("id"), "error": str(e)})
            continue
        matched = None
        for w in windows:
            if run_id and w["run_id"] != run_id:
                continue
            if w["start"] <= ts <= w["end"]:
                matched = w
                break
        rows.append({
            "alert_id": alert["id"], "alert_timestamp": alert["timestamp"],
            "alert_source": alert["source"], "alert_category": alert["category"],
            "alert_signature": alert["signature"], "severity": alert["severity"],
            "src_ip": alert["src_ip"], "dest_port": alert["dest_port"],
            "matched_run_id": matched["run_id"] if matched else None,
            "matched_stage": matched["stage"] if matched else "unlabeled",
            "mitre_tactic": matched["mitre_tactic"] if matched else None,
            "mitre_technique": matched["mitre_technique"] if matched else None,
        })
    return rows


def write_csv(rows: list[dict], out_path: Path) -> None:
    import csv
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        log.warning("no alert rows to export", extra={"out_path": str(out_path)})
        return
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    log.info("correlated dataset exported", extra={"row_count": len(rows), "out_path": str(out_path)})


def log_summary(rows: list[dict]) -> None:
    """Emits the per-stage / per-(source,category) breakdown as structured
    log records (grep/parse-able from data/logs/correlation_export.log)
    and prints the same numbers as a human-readable table."""
    from collections import Counter

    by_stage = Counter(r["matched_stage"] for r in rows)
    print("\n--- Alerts per attack stage (incl. 'unlabeled' = no ground-truth match) ---")
    for stage, count in sorted(by_stage.items(), key=lambda kv: -kv[1]):
        log.info("stage_alert_count", extra={"stage": stage, "count": count})
        print(f"  {stage:15s} {count}")

    by_source_cat = Counter((r["alert_source"], r["alert_category"]) for r in rows)
    print("\n--- Alerts per (source, category) ---")
    for (source, category), count in sorted(by_source_cat.items(), key=lambda kv: -kv[1]):
        log.info("source_category_alert_count", extra={"source": source, "category": category, "count": count})
        print(f"  {source:20s} {category:15s} {count}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", default=None, help="Only correlate/export this run_id (default: all runs).")
    ap.add_argument("--pad", type=float, default=3.0, help="Seconds of padding around each stage window.")
    ap.add_argument("--db", default=str(config.ALERTS_DB))
    ap.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ap.add_argument("--log-file", default=str(config.CORRELATION_EXPORT_LOG_FILE))
    ap.add_argument("--console-json", action="store_true")
    args = ap.parse_args()

    configure_logging(
        "collector.correlation_export", Path(args.log_file),
        level=getattr(logging, args.log_level), console_json=args.console_json,
    )

    conn = get_connection(Path(args.db))
    records = load_ground_truth_into_db(conn, config.GROUND_TRUTH_FILE)
    if not records:
        return 1

    windows = build_stage_windows(records, args.pad)
    rows = correlate(conn, windows, args.run_id)

    suffix = args.run_id or "all"
    out_path = config.EXPORT_DIR / f"correlated_dataset_{suffix}.csv"
    write_csv(rows, out_path)
    log_summary(rows)
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
