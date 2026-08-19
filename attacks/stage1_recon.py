"""
Stage 1 - Reconnaissance (MITRE TA0043 / T1595)

Two sub-steps against the lab target only:
  1. A tiny TCP port scan (falls back to pure-python sockets if `nmap` isn't
     installed, so this stage never hard-fails the chain).
  2. HTTP content discovery: GET a small built-in wordlist of common
     DVWA/PHP paths and record which return 200.

This is intentionally noisy (many requests in a short window) so it lights
up the "repeated 404s" Suricata rule (sid 9000002) as well as normal Apache
access-log entries -- both are useful correlation signal.
"""
import shutil
import socket
import subprocess

import requests

import config
from attacks.dvwa_session import GroundTruth, now_iso

COMMON_PORTS = [21, 22, 80, 443, 3306, 8080]


def _socket_port_scan(host: str, ports: list[int]) -> list[int]:
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                open_ports.append(port)
    return open_ports


def _nmap_scan(host: str) -> list[int]:
    out = subprocess.run(
        ["nmap", "-Pn", "-T4", "-p", ",".join(map(str, COMMON_PORTS)), host],
        capture_output=True, text=True, timeout=30,
    ).stdout
    return [p for p in COMMON_PORTS if f"{p}/tcp" in out and "open" in out.split(f"{p}/tcp", 1)[1][:20]]


def port_scan(gt: GroundTruth) -> list[int]:
    host = config.DVWA_HOST
    engine = "nmap" if shutil.which("nmap") else "socket"
    gt.note("recon", f"starting port scan via {engine}", target=host, ports=COMMON_PORTS)
    open_ports = _nmap_scan(host) if engine == "nmap" else _socket_port_scan(host, COMMON_PORTS)
    gt.note("recon", "port scan complete", open_ports=open_ports)
    return open_ports


def content_discovery(gt: GroundTruth) -> list[str]:
    base_url = config.DVWA_BASE_URL
    found = []
    for path in config.RECON_PATHS:
        url = f"{base_url}/{path}"
        try:
            r = requests.get(url, timeout=5)
            gt.note("recon", "content discovery request", path=path, status=r.status_code, timestamp=now_iso())
            if r.status_code == 200:
                found.append(path)
        except requests.RequestException as e:
            gt.note("recon", "content discovery request failed", path=path, error=str(e))
    gt.note("recon", "content discovery complete", found=found)
    return found


def run(gt: GroundTruth) -> dict:
    with gt.stage("recon", {"target": config.DVWA_HOST}):
        open_ports = port_scan(gt)
        found_paths = content_discovery(gt)
    return {"open_ports": open_ports, "found_paths": found_paths}


if __name__ == "__main__":
    run(GroundTruth())
