#!/usr/bin/env python3
"""
Tails the defender-side log sources (Suricata eve.json, Apache access/error
logs, and a lightweight in-process behavioral brute-force detector), parses
each into the common Alert schema (schema.py), and writes them to SQLite
(data/alerts.db) as they arrive.

Run this BEFORE (or at the same time as) attacks/run_attack_chain.py so the
alert stream covers the whole attack window, and leave it running until the
attack chain finishes. Stop with Ctrl+C.

The pipeline's own operational logging (startup, parse errors, throughput,
exceptions -- NOT the alert data itself) is structured, Log4j-style, via
logging_setup.py: a human-readable console layout plus a rotating JSON
file appender at data/logs/collector.log.

Usage:
    python3 collector/log_collector.py
    python3 collector/log_collector.py --from-start        # replay existing log content too
    python3 collector/log_collector.py --log-level DEBUG   # verbose console + file logging
    python3 collector/log_collector.py --console-json       # JSON on console too (not just the file)
"""
import argparse
import json
import logging
import queue
import re
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
from collector.schema import Alert, get_connection, insert_alert  # noqa: E402
from logging_setup import configure_logging, log_context  # noqa: E402

STOP = threading.Event()
ALERT_QUEUE: "queue.Queue[Alert]" = queue.Queue()

log_main = None          # bound in main() after configure_logging()
log_suricata = None
log_apache_access = None
log_apache_error = None
log_writer = None

APACHE_COMBINED_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3}) (?P<size>\S+)'
)
APACHE_ERROR_TIME_RE = re.compile(
    r'^\[(?P<time>[A-Za-z]{3} [A-Za-z]{3} \d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\]'
)


def parse_apache_access_time(raw: str) -> str:
    """Parses combined-log-format time (e.g. '18/Aug/2026:10:00:01 +0000')
    into UTC ISO8601. Falls back to current time if unparseable -- this
    matters for --from-start replay of historical logs, where using "now"
    instead of the log's own timestamp would silently break the
    ground-truth time-window correlation."""
    try:
        dt = datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def parse_apache_error_time(line: str) -> str:
    """Parses the leading '[Day Mon DD HH:MM:SS[.ffffff] YYYY]' timestamp
    Apache's error log uses. Assumes the container clock is UTC (true for
    the default vulnerables/web-dvwa image); falls back to current time."""
    m = APACHE_ERROR_TIME_RE.match(line)
    if not m:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    raw = m.group("time")
    for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def follow(path: Path, from_start: bool, logger):
    """Yield new lines appended to `path`, tailing across rotation/truncation."""
    logger.info("waiting for log source", extra={"path": str(path)})
    while not path.exists() and not STOP.is_set():
        time.sleep(1)
    if STOP.is_set():
        return
    logger.info("log source found, tailing", extra={"path": str(path), "from_start": from_start})
    with open(path, "r", errors="ignore") as f:
        if not from_start:
            f.seek(0, 2)  # end of file
        while not STOP.is_set():
            line = f.readline()
            if not line:
                time.sleep(0.5)
                try:
                    if f.tell() > path.stat().st_size:
                        logger.warning("log file truncated/rotated, reopening from start",
                                        extra={"path": str(path)})
                        f.seek(0)
                except FileNotFoundError:
                    time.sleep(1)
                continue
            yield line.rstrip("\n")
    logger.info("stopped tailing log source", extra={"path": str(path)})


def classify_suricata_stage(signature: str) -> str:
    sig = signature.lower()
    if "recon" in sig:
        return "recon"
    if "bruteforce" in sig:
        return "bruteforce"
    if "sqli" in sig:
        return "sqli"
    if "upload" in sig:
        return "upload_rce"
    if " c2 " in sig or "c2 -" in sig:
        return "c2_discovery"
    if "exfil" in sig:
        return "exfiltration"
    return "other"


def tail_suricata(eve_path: Path, from_start: bool):
    try:
        for line in follow(eve_path, from_start, log_suricata):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as e:
                log_suricata.warning("failed to parse eve.json line", extra={"error": str(e)})
                continue
            if event.get("event_type") != "alert":
                continue
            alert_obj = event.get("alert", {})
            signature = alert_obj.get("signature", "")
            category = classify_suricata_stage(signature)
            log_suricata.debug("suricata alert ingested", extra={
                "signature": signature, "category": category,
                "src_ip": event.get("src_ip"), "dest_ip": event.get("dest_ip"),
            })
            ALERT_QUEUE.put(Alert(
                timestamp=event.get("timestamp", ""),
                source="suricata",
                category=category,
                signature=signature,
                severity=alert_obj.get("severity"),
                src_ip=event.get("src_ip"),
                dest_ip=event.get("dest_ip"),
                dest_port=event.get("dest_port"),
                proto=event.get("proto"),
                raw=line,
            ))
    except Exception:
        log_suricata.exception("tail_suricata crashed")


def classify_apache_path(path: str, status: int) -> str:
    p = path.lower()
    if status == 404:
        return "recon"
    if "vulnerabilities/brute/" in p:
        return "bruteforce"
    if "union" in p and "select" in p:
        return "sqli"
    if "vulnerabilities/upload/" in p:
        return "upload_rce"
    if "hackable/uploads/" in p and "cmd=" in p:
        if "passwd" in p:
            return "exfiltration"
        return "c2_discovery"
    return "other"


class BruteForceDetector:
    """Simple sliding-window heuristic: N+ requests to the same path from the
    same source IP within `window` seconds emits a synthetic behavioral alert.
    A stand-in for a real WAF/UEBA component -- not a substitute for one."""

    def __init__(self, threshold: int = 5, window: float = 10.0):
        self.threshold = threshold
        self.window = window
        self._hits: dict[tuple[str, str], deque] = defaultdict(deque)
        self._fired: dict[tuple[str, str], float] = {}

    def observe(self, ip: str, path: str, ts: float) -> bool:
        key = (ip, path)
        dq = self._hits[key]
        dq.append(ts)
        while dq and ts - dq[0] > self.window:
            dq.popleft()
        if len(dq) >= self.threshold and (ts - self._fired.get(key, 0)) > self.window:
            self._fired[key] = ts
            return True
        return False


def tail_apache_access(access_path: Path, from_start: bool):
    detector = BruteForceDetector()
    unparsed = 0
    try:
        for line in follow(access_path, from_start, log_apache_access):
            m = APACHE_COMBINED_RE.search(line)
            if not m:
                unparsed += 1
                if unparsed % 50 == 1:
                    log_apache_access.warning("line did not match combined log format",
                                                extra={"unparsed_total": unparsed})
                continue
            ip = m.group("ip")
            path = m.group("path")
            status = int(m.group("status"))
            category = classify_apache_path(path, status)
            log_ts = parse_apache_access_time(m.group("time"))
            log_apache_access.debug("apache access alert ingested", extra={
                "category": category, "status": status, "src_ip": ip,
            })
            ALERT_QUEUE.put(Alert(
                timestamp=log_ts,
                source="apache_access",
                category=category,
                signature=f"{m.group('method')} {path} -> {status}",
                src_ip=ip,
                raw=line,
            ))
            if detector.observe(ip, path, time.time()):
                log_apache_access.info("behavioral brute-force threshold crossed", extra={
                    "src_ip": ip, "path": path, "threshold": detector.threshold, "window_s": detector.window,
                })
                ALERT_QUEUE.put(Alert(
                    timestamp=log_ts,
                    source="apache_behavioral",
                    category="bruteforce" if "brute" in path.lower() else "recon",
                    signature=f"Behavioral: {detector.threshold}+ requests to {path} from {ip} in {detector.window}s",
                    src_ip=ip,
                    raw=line,
                ))
    except Exception:
        log_apache_access.exception("tail_apache_access crashed")


def tail_apache_error(error_path: Path, from_start: bool):
    try:
        for line in follow(error_path, from_start, log_apache_error):
            log_apache_error.debug("apache error line ingested", extra={"preview": line[:120]})
            ALERT_QUEUE.put(Alert(
                timestamp=parse_apache_error_time(line),
                source="apache_error",
                category="other",
                signature=line[:200],
                raw=line,
            ))
    except Exception:
        log_apache_error.exception("tail_apache_error crashed")


def writer_loop(db_path: Path):
    conn = get_connection(db_path)
    count = 0
    last_commit = time.time()
    log_writer.info("writer started", extra={"db_path": str(db_path)})
    while not STOP.is_set() or not ALERT_QUEUE.empty():
        try:
            alert = ALERT_QUEUE.get(timeout=1)
        except queue.Empty:
            alert = None

        if alert is not None:
            try:
                insert_alert(conn, alert)
                count += 1
                if count % 25 == 0:
                    log_writer.info("alert batch progress", extra={
                        "total_written": count, "latest_source": alert.source, "latest_category": alert.category,
                    })
            except Exception:
                log_writer.exception("failed to insert alert", extra={"alert_source": alert.source})

        # Commit on a ~1s tick regardless of whether an alert just arrived,
        # so rows are visible to other readers (e.g. correlation_export.py)
        # even during a lull in traffic, not just right after an insert.
        if time.time() - last_commit > 1:
            conn.commit()
            last_commit = time.time()
    conn.commit()
    conn.close()
    log_writer.info("writer stopped", extra={"total_written": count, "db_path": str(db_path)})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from-start", action="store_true", help="Also parse existing log content, not just new lines.")
    ap.add_argument("--db", default=str(config.ALERTS_DB))
    ap.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ap.add_argument("--log-file", default=str(config.COLLECTOR_LOG_FILE),
                     help="Rotating JSON operational log file (not the alert data).")
    ap.add_argument("--console-json", action="store_true",
                     help="Emit structured JSON to the console too, instead of the human-readable layout.")
    args = ap.parse_args()

    global log_main, log_suricata, log_apache_access, log_apache_error, log_writer
    log_main = configure_logging(
        "collector.main", Path(args.log_file),
        level=getattr(logging, args.log_level),
        console_json=args.console_json,
    )
    log_suricata = logging.getLogger("collector.suricata")
    log_apache_access = logging.getLogger("collector.apache_access")
    log_apache_error = logging.getLogger("collector.apache_error")
    log_writer = logging.getLogger("collector.writer")

    with log_context(component="collector"):
        log_main.info("collector starting", extra={
            "db": args.db, "from_start": args.from_start,
            "suricata_eve": str(config.SURICATA_EVE_JSON),
            "apache_log_dir": str(config.APACHE_LOG_DIR),
        })

        sources = [
            threading.Thread(target=tail_suricata, args=(config.SURICATA_EVE_JSON, args.from_start),
                              daemon=True, name="tail-suricata"),
            threading.Thread(target=tail_apache_access, args=(config.APACHE_LOG_DIR / "access.log", args.from_start),
                              daemon=True, name="tail-apache-access"),
            threading.Thread(target=tail_apache_error, args=(config.APACHE_LOG_DIR / "error.log", args.from_start),
                              daemon=True, name="tail-apache-error"),
        ]
        writer = threading.Thread(target=writer_loop, args=(Path(args.db),), daemon=True, name="db-writer")

        writer.start()
        for t in sources:
            t.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log_main.info("shutdown requested (Ctrl+C)")
            STOP.set()
            writer.join(timeout=10)
        log_main.info("collector stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
