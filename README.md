# RL-Based Adaptive Alert Correlation Lab (DVWA Multi-Stage Attack Chain)

Supporting lab for a thesis on **Reinforcement-Learning-Based Adaptive Alert
Correlation for Detecting Multi-Stage Cyber Attacks**. It stands up an
isolated, intentionally vulnerable target (DVWA), runs a scripted six-stage
attack chain against it, captures the resulting IDS/application alerts, and
correlates them against ground-truth attack-stage labels — producing the
labeled dataset an alert-correlation system (rule-based baseline, or later,
an RL agent) can be trained and evaluated against.

> **Isolated lab use only.** Everything here targets a DVWA container you
> run yourself on an isolated Docker network. Do not expose the DVWA
> container to the internet, and do not point any script here at a host you
> do not own or have explicit authorization to test.

---

## 1. Why this design

Alert correlation research needs two things that real-world SOC data almost
never gives you cleanly: (a) a **known-good ground truth** of exactly which
attack stage happened when, and (b) a **repeatable, re-runnable** attack
chain so you can generate many labeled episodes for training/evaluation.
This lab gets both by keeping the attacker and the defender on separate
sides of the same event stream:

- The **attack scripts** (`attacks/`) are the attacker. Every stage writes
  its own timestamped ground truth (`data/ground_truth.jsonl`) — this is
  authoritative, independent of whatever the IDS did or didn't catch.
- The **collector** (`collector/`) is the defender. It only ever reads
  Suricata/Apache output — it has no knowledge of what the attacker did.
- **`correlation_export.py`** is the analysis step that joins the two by
  time window and produces the labeled dataset — the thing an RL
  correlator would consume as its observation stream / reward signal.

## 2. Architecture

```
                 ┌─────────────────────┐
                 │   docker-compose     │
                 │   DVWA container      │  172.28.0.10  (dvwa_net)
                 │   (Apache+MySQL+PHP)  │
                 └─────────┬────────────┘
                           │ HTTP (port 80)
        ┌──────────────────┼───────────────────────┐
        │                  │                        │
┌───────▼────────┐ ┌───────▼────────┐   ┌───────────▼──────────┐
│ attacks/        │ │ Suricata (host) │   │ Apache access/error   │
│ run_attack_chain│ │ watches dvwa_net│   │ logs (volume-mounted)  │
│  6 MITRE-mapped │ │ -> eve.json     │   │                        │
│  stages         │ └───────┬────────┘   └───────────┬────────────┘
└───────┬─────────┘         │                          │
        │ writes            │ tailed by                │ tailed by
        ▼                   ▼                          ▼
data/ground_truth.jsonl   collector/log_collector.py (normalizes to
  (attacker-side truth)      common Alert schema) -> data/alerts.db (SQLite)
        │                                                 │
        └───────────────────┬─────────────────────────────┘
                             ▼
                collector/correlation_export.py
              (time-window join: alert <-> true stage)
                             │
              ┌──────────────┴───────────────┐
              ▼                               ▼
   data/exports/correlated_dataset*.csv   dashboard/app.py (Streamlit)
   (input for RL / offline analysis)      (timeline + correlation heatmap)
```

## 3. Attack chain (MITRE ATT&CK-mapped)

| # | Stage | Script | MITRE Tactic | MITRE Technique | DVWA module used |
|---|-------|--------|---------------|------------------|-------------------|
| 1 | Recon | `attacks/stage1_recon.py` | TA0043 Reconnaissance | T1595 Active Scanning | port scan + content discovery |
| 2 | Brute force | `attacks/stage2_bruteforce.py` | TA0006 Credential Access | T1110 Brute Force | `vulnerabilities/brute/` |
| 3 | SQL injection | `attacks/stage3_sqli.py` | TA0006 / Initial Access | T1190 Exploit Public-Facing App | `vulnerabilities/sqli/` |
| 4 | Upload -> RCE | `attacks/stage4_upload_rce.py` | TA0002 Execution | T1505.003 Web Shell | `vulnerabilities/upload/` |
| 5 | C2 / discovery | `attacks/stage5_c2_discovery.py` | TA0007 Discovery | T1082 System Info Discovery | planted webshell |
| 6 | Exfiltration | `attacks/stage6_exfiltration.py` | TA0010 Exfiltration | T1041 Exfil Over C2 Channel | planted webshell |

`attacks/run_attack_chain.py` runs all six in order, once per "episode".
Run multiple episodes (`--episodes N`) to build up a larger labeled dataset
for training/evaluating the correlator.

## 4. Prerequisites

- Linux host with Docker + the `docker compose` plugin
- Python 3.10+
- `suricata` (installed automatically by `deployment/setup_suricata.sh` via apt)
- Optional: `nmap` (stage 1 falls back to a pure-Python socket scan if absent)

```bash
cd rl-alert-correlation
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## 5. Step-by-step

### 5.1 Deploy and configure DVWA

```bash
python3 deployment/deploy_dvwa.py --security-level low
```

This runs `docker compose up -d`, waits for the web server, clicks
"Create/Reset Database" on `setup.php`, logs in as `admin`/`password`, and
sets the DVWA security level. Re-run any time you want a clean database
before a new batch of episodes.

> Start with `--security-level low` — the attack scripts are written and
> verified against low. Medium/high change how each vulnerability behaves
> (e.g. SQLi becomes a dropdown of numeric IDs, uploads get extension
> checks) and are a natural extension exercise: harden the target and see
> how the attack scripts and the resulting alert signatures change.

### 5.2 Start Suricata (host-side NIDS)

```bash
sudo ./deployment/setup_suricata.sh --daemon
```

Installs Suricata if needed, loads the lab's custom rules
(`deployment/suricata/local.rules`, SIDs 9000001–9000050, one rule family
per attack stage), points `HOME_NET` at the DVWA subnet, and watches the
`dvwa_net` Docker bridge. Logs to `data/suricata/eve.json`.

### 5.3 Start the log collector

In its own terminal (leave running for the whole session):

```bash
python3 collector/log_collector.py
```

Tails Suricata `eve.json` and the Apache access/error logs, normalizes
everything into the common `Alert` schema (`collector/schema.py`), and
writes to `data/alerts.db` (SQLite) as events arrive. Also runs a small
in-process behavioral detector (sliding-window request-rate heuristic) as a
stand-in for a WAF/UEBA signal.

The collector's own **operational logging** — start-up, parse errors,
throughput, exceptions; not the alert data itself, which goes to
`alerts.db` — is structured, Log4j-style, via `logging_setup.py`:

- one named logger per component (`collector.suricata`, `collector.apache_access`,
  `collector.apache_error`, `collector.writer`), each tagging its thread name
- a **console appender** with a Log4j PatternLayout-style line:
  `2026-08-18T12:34:56.789Z [tail-suricata] INFO  collector.suricata - alert ingested {...}`
- a **rotating file appender** (`data/logs/collector.log`, 10MB × 5 backups)
  that always writes structured JSON, one record per line — e.g.
  `{"timestamp": "...", "level": "INFO", "logger": "collector.writer", "thread": "db-writer", "message": "alert batch progress", "data": {"total_written": 25, ...}}`
- an **MDC-style scoped context** (`log_context(run_id=...)`) so every log
  line emitted inside a block carries that context automatically, the same
  way Log4j's ThreadContext/MDC tags a request's log lines without passing
  the value through every call

Useful flags:

```bash
python3 collector/log_collector.py --log-level DEBUG   # per-alert-level detail
python3 collector/log_collector.py --console-json       # JSON on console too, not just the file
```

`collector/correlation_export.py` uses the same setup — its per-stage /
per-(source,category) summary is emitted as structured `stage_alert_count`
/ `source_category_alert_count` log records (grep/parse-able from
`data/logs/correlation_export.log`) in addition to the human-readable
console table.

### 5.4 Run the attack chain

In another terminal:

```bash
python3 attacks/run_attack_chain.py --episodes 5 --delay 5
```

Each episode logs into DVWA and runs all six stages, writing ground truth
to `data/ground_truth.jsonl` as it goes.

### 5.5 Stop the collector and export the correlated dataset

`Ctrl+C` the collector, then:

```bash
python3 collector/correlation_export.py
```

Joins `ground_truth.jsonl` against `alerts.db` by time window (padded ±3s
around each stage) and writes `data/exports/correlated_dataset_all.csv`,
plus a console summary of alert counts per true stage and per
(source, category) pair — this is your first correlation-accuracy table.

Or run steps 5.1–5.5 in one shot (after Suricata is already running):

```bash
./scripts/run_full_scenario.sh 5 low
```

### 5.6 Explore the dashboard

```bash
streamlit run dashboard/app.py
```

- **Timeline**: every alert plotted against shaded bands for each
  ground-truth attack stage, so you can see visually whether alerts
  cluster where the real attack was happening.
- **Correlation matrix**: heatmap of true stage vs. which alert
  category actually fired — the "confusion matrix" view for the
  correlation baseline.
- **Raw alert table**, filterable by run/category/source.

## 6. Data schema reference

- `data/ground_truth.jsonl` — one JSON object per line: `run_id`, `event`
  (`stage_start`/`stage_end`/`note`), `stage`, `mitre_tactic`,
  `mitre_technique`, `timestamp`, plus stage-specific `details`.
- `data/alerts.db` (SQLite):
  - `alerts` — normalized alerts from all sources (`collector/schema.py`)
  - `ground_truth` — the JSONL above, mirrored in for dashboard convenience
- `data/exports/correlated_dataset_*.csv` — one row per alert, labeled with
  `matched_stage` / `mitre_tactic` / `mitre_technique` (or `unlabeled` if no
  ground-truth stage was active at that time).
- `data/logs/*.log` — the pipeline's own structured **operational** logs
  (JSON lines, see §5.3), separate from the alert data above.

## 7. Where this fits into the RL work

This lab produces the **labeled event stream**; the RL correlator is
separate, future work. The intended framing, given what's exported here:

- **Episode** = one `run_id` (one full attack-chain run).
- **Observation / state** = a sliding window of recent `alerts` rows
  (category, source, severity, src/dest, inter-alert time deltas).
- **Action** = correlate the incoming alert into an existing attack-chain
  cluster, or start a new one / mark it noise.
- **Reward** = shaped from `matched_stage` in the correlated export during
  training — correct grouping against the six-stage MITRE-mapped ground
  truth earns reward; grouping unrelated `unlabeled` noise with a real
  chain is penalized.
- **Baseline to beat**: the summary `correlation_export.py` prints (how
  many alerts land in each true stage's time window) is a naive
  time-window correlator — a reasonable non-RL baseline to compare against.

## 8. Repo layout

```
config.py                    Central config (paths, DVWA URL/creds, subnet, wordlists, MITRE map)
logging_setup.py               Log4j-style structured logging (pattern + JSON layouts, MDC context)
docker-compose.yml            DVWA container on the isolated dvwa_net bridge
deployment/
  deploy_dvwa.py               Bring up + configure DVWA (reset DB, login, security level)
  setup_suricata.sh             Install/configure/run Suricata on the host
  suricata/local.rules           Custom rules, one family per attack stage
attacks/
  dvwa_session.py                DvwaSession (login/CSRF) + GroundTruth (JSONL logger)
  stage1_recon.py .. stage6_exfiltration.py    One script per kill-chain stage
  run_attack_chain.py             Orchestrator (--episodes, --delay)
collector/
  schema.py                        Alert dataclass + SQLite schema
  log_collector.py                  Tails Suricata/Apache -> data/alerts.db
  correlation_export.py              Time-window join -> labeled CSV + summary
dashboard/
  app.py                             Streamlit: timeline, correlation heatmap, alert table
scripts/
  run_full_scenario.sh                One-shot: deploy -> collect -> attack -> export
data/                                  Generated at runtime (gitignored)
```

## 9. Extending this lab

- **Vary difficulty**: run episodes at `medium`/`high` security level to
  study how alert signatures shift as the target hardens (good material
  for an "evasion-aware correlation" chapter).
- **Add ModSecurity** (WAF) in front of DVWA for an additional alert
  source — `collector/log_collector.py` is structured so a new `tail_*`
  source function + `Alert(source="modsecurity", ...)` is all that's needed.
- **More episodes, more variety**: `run_attack_chain.py` runs the six
  stages in a fixed order for label clarity; a follow-up variant that
  randomizes stage order/timing/omits stages would make the correlator's
  job (and the RL formulation) less trivial and more realistic.
