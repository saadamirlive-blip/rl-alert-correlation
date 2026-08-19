#!/usr/bin/env python3
"""
Streamlit dashboard for visual correlation of the DVWA attack-chain lab.

Shows, for one or all attack-chain runs:
  * a timeline of every alert (Suricata / Apache / behavioral) laid over
    shaded bands for each ground-truth attack stage, so you can *see*
    whether alerts cluster where the real attack was happening
  * a stage x alert-category heatmap (how well each stage's alerts get
    correlated)
  * KPI tiles (total alerts, correlated %, stage count, sources)
  * a filterable raw alert table

Run with:
    streamlit run dashboard/app.py
"""
import sys
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
from collector.schema import get_connection  # noqa: E402
from collector.correlation_export import (  # noqa: E402
    load_ground_truth_into_db, build_stage_windows, correlate, parse_ts,
)

# --- Palette (fixed categorical order, validated for CVD-safe adjacency) ---
CATEGORY_COLOR = {
    "recon": "#2a78d6",          # slot 1 blue
    "bruteforce": "#eb6834",     # slot 2 orange
    "sqli": "#1baf7a",           # slot 3 aqua
    "upload_rce": "#eda100",     # slot 4 yellow
    "c2_discovery": "#e87ba4",   # slot 5 magenta
    "exfiltration": "#e34948",   # slot 8 red -- most severe stage, reads as "critical"
    "other": "#898781",          # muted ink -- neutral catch-all, not a real stage
    "unlabeled": "#c3c2b7",      # baseline gray -- no ground-truth match
}
STAGE_ORDER = ["recon", "bruteforce", "sqli", "upload_rce", "c2_discovery", "exfiltration"]
SOURCE_ORDER = ["suricata", "apache_access", "apache_behavioral", "apache_error"]

st.set_page_config(page_title="Alert Correlation Dashboard", layout="wide")


@st.cache_data(ttl=5)
def load_data(db_path: str):
    conn = get_connection(Path(db_path))
    records = load_ground_truth_into_db(conn, config.GROUND_TRUTH_FILE)
    windows = build_stage_windows(records, pad_seconds=3.0)
    rows = correlate(conn, windows, run_id=None)
    alerts_df = pd.read_sql("SELECT * FROM alerts ORDER BY timestamp", conn)
    conn.close()
    correlated_df = pd.DataFrame(rows)
    run_ids = sorted({w["run_id"] for w in windows})
    return alerts_df, correlated_df, windows, run_ids


def render_timeline(correlated_df: pd.DataFrame, windows: list, run_id: str | None):
    df = correlated_df.copy()
    if run_id:
        df = df[(df["matched_run_id"] == run_id) | (df["matched_run_id"].isna())]
        win = [w for w in windows if w["run_id"] == run_id]
    else:
        win = windows
    if df.empty:
        st.info("No alerts to show for this selection yet.")
        return

    df["alert_source"] = pd.Categorical(df["alert_source"], categories=SOURCE_ORDER, ordered=True)
    fig = go.Figure()

    # Shaded bands for each ground-truth attack stage (drawn first, behind alerts).
    for w in win:
        fig.add_vrect(
            x0=w["start"], x1=w["end"],
            fillcolor=CATEGORY_COLOR.get(w["stage"], "#c3c2b7"), opacity=0.12, line_width=0,
            annotation_text=w["stage"], annotation_position="top left",
            annotation=dict(font_size=10, font_color="#52514e"),
        )

    for category in STAGE_ORDER + ["other", "unlabeled"]:
        sub = df[df["alert_category"].fillna("unlabeled").replace({"": "unlabeled"}) == category]
        if category == "unlabeled":
            sub = df[df["matched_stage"] == "unlabeled"]
        if sub.empty:
            continue
        fig.add_trace(go.Scatter(
            x=pd.to_datetime(sub["alert_timestamp"], utc=True, errors="coerce"),
            y=sub["alert_source"],
            mode="markers",
            name=category,
            marker=dict(size=10, color=CATEGORY_COLOR.get(category, "#898781"),
                        line=dict(width=1, color="rgba(255,255,255,0.6)")),
            hovertemplate="<b>%{text}</b><br>%{x}<br>source: %{y}<extra></extra>",
            text=sub["alert_signature"],
        ))

    fig.update_layout(
        height=420, margin=dict(l=10, r=10, t=30, b=10),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
        xaxis_title="time", yaxis_title="alert source",
        plot_bgcolor="#fcfcfb", paper_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig, use_container_width=True)


def render_heatmap(correlated_df: pd.DataFrame, run_id: str | None):
    df = correlated_df.copy()
    if run_id:
        df = df[(df["matched_run_id"] == run_id) | (df["matched_run_id"].isna())]
    if df.empty:
        return
    pivot = pd.crosstab(df["matched_stage"], df["alert_category"])
    stage_rows = [s for s in STAGE_ORDER + ["unlabeled"] if s in pivot.index]
    pivot = pivot.reindex(stage_rows)
    fig = go.Figure(data=go.Heatmap(
        z=pivot.values, x=list(pivot.columns), y=list(pivot.index),
        colorscale=[[0, "#fcfcfb"], [0.5, "#6da7ec"], [1, "#0d366b"]],
        hovertemplate="true stage: %{y}<br>alert category: %{x}<br>count: %{z}<extra></extra>",
        colorbar=dict(title="count"),
    ))
    fig.update_layout(height=380, margin=dict(l=10, r=10, t=10, b=10),
                       xaxis_title="alert category (what fired)", yaxis_title="true attack stage")
    st.plotly_chart(fig, use_container_width=True)


def main():
    st.title("RL Alert-Correlation Lab -- DVWA Attack Chain Dashboard")
    st.caption("Suricata + Apache alerts correlated against attacker-side ground truth (MITRE ATT&CK-mapped stages).")

    with st.sidebar:
        st.header("Filters")
        db_path = st.text_input("Alerts DB", str(config.ALERTS_DB))
        if st.button("Refresh data"):
            st.cache_data.clear()

    try:
        alerts_df, correlated_df, windows, run_ids = load_data(db_path)
    except Exception as e:
        st.error(f"Could not load {db_path}: {e}\n\nRun collector/log_collector.py and "
                 f"attacks/run_attack_chain.py first, then collector/correlation_export.py.")
        return

    with st.sidebar:
        run_id = st.selectbox("Run (episode)", options=["All runs"] + run_ids)
        run_id = None if run_id == "All runs" else run_id
        category_filter = st.multiselect("Alert category", STAGE_ORDER + ["other"], default=STAGE_ORDER + ["other"])
        source_filter = st.multiselect("Alert source", SOURCE_ORDER, default=SOURCE_ORDER)

    scoped = correlated_df
    if run_id:
        scoped = scoped[(scoped["matched_run_id"] == run_id) | (scoped["matched_run_id"].isna())]

    total_alerts = len(scoped)
    correlated_count = int((scoped["matched_stage"] != "unlabeled").sum()) if total_alerts else 0
    correlated_pct = f"{100 * correlated_count / total_alerts:.0f}%" if total_alerts else "0%"
    n_stages = scoped["matched_stage"].nunique() if total_alerts else 0
    n_sources = scoped["alert_source"].nunique() if total_alerts else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total alerts", total_alerts)
    c2.metric("Correlated to a stage", correlated_pct)
    c3.metric("Distinct true stages seen", n_stages)
    c4.metric("Alert sources", n_sources)

    st.subheader("Timeline: alerts vs. ground-truth attack stages")
    filtered = correlated_df[
        correlated_df["alert_category"].isin(category_filter) &
        correlated_df["alert_source"].isin(source_filter)
    ]
    render_timeline(filtered, windows, run_id)

    st.subheader("Correlation matrix: true stage vs. what actually fired")
    render_heatmap(correlated_df, run_id)

    st.subheader("Raw alerts")
    st.dataframe(
        scoped[["alert_timestamp", "alert_source", "alert_category", "matched_stage",
                "alert_signature", "src_ip", "severity"]].sort_values("alert_timestamp", ascending=False),
        use_container_width=True, height=320,
    )


if __name__ == "__main__":
    main()
