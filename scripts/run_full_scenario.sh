#!/usr/bin/env bash
#
# Convenience wrapper that runs one full lab cycle end-to-end:
#   deploy/reset DVWA -> start collector in background -> run N attack
#   episodes -> stop collector -> export the correlated dataset.
#
# Suricata is NOT started by this script (it needs sudo and a foreground
# terminal of its own) -- start it separately first:
#   sudo ./deployment/setup_suricata.sh --daemon
#
# Usage:
#   ./scripts/run_full_scenario.sh [episodes] [security_level]
#   ./scripts/run_full_scenario.sh 5 low
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

EPISODES="${1:-1}"
SECURITY_LEVEL="${2:-low}"

echo "[*] Deploying / resetting DVWA (security level: $SECURITY_LEVEL) ..."
python3 deployment/deploy_dvwa.py --security-level "$SECURITY_LEVEL"

echo "[*] Starting log collector in background ..."
python3 collector/log_collector.py --from-start > data/collector.log 2>&1 &
COLLECTOR_PID=$!
trap 'echo "[*] Stopping collector (pid $COLLECTOR_PID)"; kill -INT "$COLLECTOR_PID" 2>/dev/null || true; wait "$COLLECTOR_PID" 2>/dev/null || true' EXIT

sleep 3

echo "[*] Running $EPISODES attack-chain episode(s) ..."
python3 attacks/run_attack_chain.py --episodes "$EPISODES"

sleep 3
echo "[*] Stopping log collector ..."
kill -INT "$COLLECTOR_PID"
wait "$COLLECTOR_PID" 2>/dev/null || true
trap - EXIT

echo "[*] Exporting correlated dataset ..."
python3 collector/correlation_export.py

echo "[+] Done. Launch the dashboard with: streamlit run dashboard/app.py"
