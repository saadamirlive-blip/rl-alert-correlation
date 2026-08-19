#!/usr/bin/env python3
"""
Orchestrates the full multi-stage attack chain against the DVWA lab:

  recon -> bruteforce -> sqli -> upload_rce -> c2_discovery -> exfiltration

Each run gets a unique run_id and writes ground-truth stage labels to
data/ground_truth.jsonl (see attacks/dvwa_session.py:GroundTruth). Run this
*while* collector/log_collector.py is running in another terminal so the
defender-side alerts and attacker-side ground truth cover the same window.

Usage:
    python3 attacks/run_attack_chain.py
    python3 attacks/run_attack_chain.py --episodes 10 --delay 5
"""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
from attacks import stage1_recon, stage2_bruteforce, stage3_sqli  # noqa: E402
from attacks import stage4_upload_rce, stage5_c2_discovery, stage6_exfiltration  # noqa: E402
from attacks.dvwa_session import DvwaSession, GroundTruth  # noqa: E402


def run_episode(episode_num: int) -> str:
    gt = GroundTruth()
    print(f"\n=== Episode {episode_num} | run_id={gt.run_id} ===")

    dvwa = DvwaSession()
    dvwa.login()

    stage1_recon.run(gt)
    stage2_bruteforce.run(dvwa, gt)
    stage3_sqli.run(dvwa, gt)
    upload_result = stage4_upload_rce.run(dvwa, gt)
    shell_url = upload_result.get("shell_url")
    stage5_c2_discovery.run(dvwa, shell_url, gt)
    stage6_exfiltration.run(dvwa, shell_url, gt)

    print(f"=== Episode {episode_num} complete (run_id={gt.run_id}) ===")
    return gt.run_id


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--episodes", type=int, default=1, help="Number of full attack-chain runs.")
    ap.add_argument("--delay", type=float, default=3.0, help="Seconds to wait between episodes.")
    args = ap.parse_args()

    print(f"[*] Target: {config.DVWA_BASE_URL}  |  Ground truth: {config.GROUND_TRUTH_FILE}")
    run_ids = []
    for i in range(1, args.episodes + 1):
        run_ids.append(run_episode(i))
        if i < args.episodes:
            time.sleep(args.delay)

    print(f"\n[+] {len(run_ids)} episode(s) complete: {run_ids}")
    print("    Next: stop the log collector, then run collector/correlation_export.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
