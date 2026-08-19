#!/usr/bin/env bash
#
# Configure and run Suricata on the HOST to watch the Docker bridge network
# that DVWA lives on (dvwa_net, 172.28.0.0/24 - see ../docker-compose.yml).
#
# Suricata watches from the host rather than from inside a container: it's
# simpler, needs no extra container capabilities, and still sees all traffic
# to/from the DVWA container because docker bridge interfaces are visible
# on the host.
#
# Requires: Ubuntu/Debian host, sudo, DVWA container already started
# (deployment/deploy_dvwa.py) so the dvwa_net bridge exists.
#
# Usage:
#   sudo ./deployment/setup_suricata.sh            # install, configure, run (foreground)
#   sudo ./deployment/setup_suricata.sh --daemon    # run in background
#
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_SRC="$PROJECT_ROOT/deployment/suricata/local.rules"
LOG_DIR="$PROJECT_ROOT/data/suricata"
NETWORK_NAME="dvwa_net"
HOME_NET="172.28.0.0/24"

mkdir -p "$LOG_DIR"

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script needs root (packet capture + reading the docker bridge). Re-run with sudo." >&2
  exit 1
fi

if ! command -v suricata >/dev/null 2>&1; then
  echo "[*] Installing suricata ..."
  apt-get update -y
  apt-get install -y suricata
fi

BRIDGE_ID="$(docker network inspect "$NETWORK_NAME" -f '{{.Id}}' 2>/dev/null || true)"
if [[ -z "$BRIDGE_ID" ]]; then
  echo "Docker network '$NETWORK_NAME' not found. Start DVWA first: python3 deployment/deploy_dvwa.py" >&2
  exit 1
fi
IFACE="br-${BRIDGE_ID:0:12}"

if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "Expected bridge interface $IFACE not found. List bridges with: ip -o link show type bridge" >&2
  exit 1
fi
echo "[+] Watching interface: $IFACE (docker network '$NETWORK_NAME')"

CONF_DIR="/etc/suricata"
LOCAL_RULES_DST="$CONF_DIR/rules/local.rules"
mkdir -p "$CONF_DIR/rules"
cp "$RULES_SRC" "$LOCAL_RULES_DST"
echo "[+] Installed rules to $LOCAL_RULES_DST"

# Make sure local.rules is loaded and HOME_NET matches the DVWA subnet.
if ! grep -q '^\s*-\s*local.rules' "$CONF_DIR/suricata.yaml" 2>/dev/null; then
  sed -i '/^rule-files:/a\  - local.rules' "$CONF_DIR/suricata.yaml"
fi
sed -i "s#^\(\s*HOME_NET:\s*\).*#\1\"[${HOME_NET}]\"#" "$CONF_DIR/suricata.yaml"

# Point eve.json into this project's data dir so log_collector.py can read it
# without needing root.
sed -i "s#^\(\s*default-log-dir:\s*\).*#\1${LOG_DIR}#" "$CONF_DIR/suricata.yaml"

suricata -T -c "$CONF_DIR/suricata.yaml" -i "$IFACE"
echo "[+] Config test passed."

if [[ "${1:-}" == "--daemon" ]]; then
  echo "[*] Starting Suricata in background, logging to $LOG_DIR/eve.json"
  suricata -D -c "$CONF_DIR/suricata.yaml" -i "$IFACE" --pidfile "$LOG_DIR/suricata.pid"
  echo "[+] Suricata started (pidfile: $LOG_DIR/suricata.pid)."
  echo "    Stop with: sudo kill \$(cat $LOG_DIR/suricata.pid)"
else
  echo "[*] Starting Suricata in foreground (Ctrl+C to stop). eve.json -> $LOG_DIR/eve.json"
  exec suricata -c "$CONF_DIR/suricata.yaml" -i "$IFACE"
fi
