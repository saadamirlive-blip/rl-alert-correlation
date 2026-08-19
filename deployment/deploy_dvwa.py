#!/usr/bin/env python3
"""
Bring up the DVWA lab and configure it into a known, scriptable state:

  1. `docker compose up -d` the DVWA container (see ../docker-compose.yml)
  2. Wait for the web server to answer
  3. Click the "Create / Reset Database" button on setup.php
  4. Log in as the DVWA admin user
  5. Set the DVWA security level (default: low)

Run this once per lab session (or any time you want to reset DVWA back to a
clean, freshly-seeded database before a new batch of attack episodes).

Usage:
    python3 deployment/deploy_dvwa.py
    python3 deployment/deploy_dvwa.py --security-level medium
    python3 deployment/deploy_dvwa.py --no-docker   # DVWA already running
"""
import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402

TOKEN_RE = re.compile(r"user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", re.IGNORECASE)


def run_docker_compose(root_dir: Path) -> None:
    print("[*] Starting DVWA via docker compose ...")
    subprocess.run(["docker", "compose", "up", "-d"], cwd=root_dir, check=True)


def wait_for_http(url: str, timeout: int = 90) -> None:
    print(f"[*] Waiting for {url} to respond ...")
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code < 500:
                print("[+] DVWA web server is up.")
                return
        except requests.RequestException as e:
            last_err = e
        time.sleep(2)
    raise RuntimeError(f"DVWA never became reachable at {url}: {last_err}")


def extract_token(html: str) -> str:
    m = TOKEN_RE.search(html)
    if not m:
        raise RuntimeError("Could not find CSRF user_token in page (unexpected DVWA HTML).")
    return m.group(1)


def reset_database(session: requests.Session, base_url: str) -> None:
    print("[*] Resetting DVWA database (setup.php) ...")
    r = session.get(f"{base_url}/setup.php", timeout=10)
    r.raise_for_status()
    token = extract_token(r.text)
    r = session.post(
        f"{base_url}/setup.php",
        data={"create_db": "Create / Reset Database", "user_token": token},
        timeout=30,
    )
    r.raise_for_status()
    print("[+] Database created / reset.")


def login(session: requests.Session, base_url: str, username: str, password: str) -> None:
    print(f"[*] Logging in as '{username}' ...")
    r = session.get(f"{base_url}/login.php", timeout=10)
    r.raise_for_status()
    token = extract_token(r.text)
    r = session.post(
        f"{base_url}/login.php",
        data={"username": username, "password": password, "Login": "Login", "user_token": token},
        timeout=10,
        allow_redirects=True,
    )
    r.raise_for_status()
    if "login.php" in r.url and "index.php" not in r.url:
        raise RuntimeError("Login appears to have failed (still on login.php).")
    print("[+] Logged in.")


def set_security_level(session: requests.Session, base_url: str, level: str) -> None:
    print(f"[*] Setting DVWA security level to '{level}' ...")
    r = session.get(f"{base_url}/security.php", timeout=10)
    r.raise_for_status()
    token = extract_token(r.text)
    r = session.post(
        f"{base_url}/security.php",
        data={"security": level, "seclev_submit": "Submit", "user_token": token},
        timeout=10,
    )
    r.raise_for_status()
    if session.cookies.get("security") != level:
        raise RuntimeError(f"Security cookie is '{session.cookies.get('security')}', expected '{level}'.")
    print("[+] Security level set.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--security-level", default=config.DVWA_SECURITY_LEVEL,
                     choices=["low", "medium", "high", "impossible"])
    ap.add_argument("--no-docker", action="store_true",
                     help="Skip 'docker compose up' (assume DVWA is already running).")
    ap.add_argument("--timeout", type=int, default=90)
    args = ap.parse_args()

    root_dir = Path(__file__).resolve().parent.parent
    base_url = config.DVWA_BASE_URL

    if not args.no_docker:
        run_docker_compose(root_dir)

    wait_for_http(f"{base_url}/setup.php", timeout=args.timeout)

    session = requests.Session()
    reset_database(session, base_url)
    login(session, base_url, config.DVWA_ADMIN_USER, config.DVWA_ADMIN_PASS)
    set_security_level(session, base_url, args.security_level)

    print(f"\n[+] DVWA ready at {base_url}  (security level: {args.security_level})")
    print("    Next: deployment/setup_suricata.sh, then collector/log_collector.py,")
    print("    then attacks/run_attack_chain.py.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
