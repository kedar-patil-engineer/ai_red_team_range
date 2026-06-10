# app.py
"""
Streamlit dashboard for the AI Red Team Range.

Three views:
  Scan            run the full probe catalog and see the resilience scorecard
  Agentic Attack  watch the multi-turn attacker pursue a goal turn by turn
  Run History     resilience over time from the JSONL log

Run:
    python -m streamlit run app.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from core.eval_log import log_run
from core.orchestrator import build_strategy, get_goal, load_goals, run_goal
from core.probes import load_probes, run_all
from core.scoring import build_scorecard
from core.targets import build_target

load_dotenv()

_LOG_FILE = Path(__file__).resolve().parent / "logs" / "scan_log.jsonl"

st.set_page_config(page_title="AI Red Team Range", layout="wide")

_GRADE_COLOR = {"A": "#1a7f37", "B": "#1a7f37", "C": "#bf8700", "D": "#cf222e", "F": "#cf222e"}


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("Target")
    target_kind = st.selectbox("Provider", ["mock", "openai", "ollama"], index=0)
    model = st.text_input("Model (blank = provider default)", value="")
    st.caption("The mock target runs offline with no API key.")
    st.markdown("---")
    st.caption("OWASP LLM Top 10 (2025) and MITRE ATLAS coverage.")

model_arg = model.strip() or None


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.title("AI Red Team Range")
st.caption("Attack LLMs, score their resilience, and gate unsafe models before they ship.")

scan_tab, attack_tab, history_tab = st.tabs(["Scan", "Agentic Attack", "Run History"])


# ---------------------------------------------------------------------------
# Scan tab
# ---------------------------------------------------------------------------

with scan_tab:
    st.subheader("Full probe catalog scan")
    if st.button("Run Scan", type="primary"):
        try:
            target = build_target(target_kind, model=model_arg)
            probes = load_probes()
            with st.spinner(f"Firing {len(probes)} probes at {target.name}..."):
                results = run_all(target, probes)
            card = build_scorecard(target.name, target.model, results)
            run_id = log_run(card)
            st.session_state["scan_card"] = card
            st.session_state["scan_run_id"] = run_id
        except Exception as exc:
            st.error(f"Scan failed: {exc}")

    card = st.session_state.get("scan_card")
    if card is not None:
        color = _GRADE_COLOR.get(card.grade, "#57606a")
        c1, c2, c3 = st.columns(3)
        c1.markdown(
            f"<div style='font-size:14px;color:#57606a'>Resilience Score</div>"
            f"<div style='font-size:44px;font-weight:700;color:{color}'>{card.resilience}<span style='font-size:20px'> / 100</span></div>",
            unsafe_allow_html=True,
        )
        c2.markdown(
            f"<div style='font-size:14px;color:#57606a'>Grade</div>"
            f"<div style='font-size:44px;font-weight:700;color:{color}'>{card.grade}</div>",
            unsafe_allow_html=True,
        )
        c3.metric("Vulnerabilities", f"{card.vulnerabilities} / {card.total_probes}")

        st.markdown("#### Findings by OWASP category")
        owasp_df = pd.DataFrame(
            [
                {"category": k, "vulnerable": v.vulnerable, "defended": v.passed}
                for k, v in card.by_owasp.items()
            ]
        ).set_index("category")
        st.bar_chart(owasp_df, color=["#cf222e", "#1a7f37"])

        st.markdown("#### Probe results")
        for r in card.results:
            badge = "VULNERABLE" if r.vulnerable else "defended"
            icon = "[X]" if r.vulnerable else "[OK]"
            with st.expander(f"{icon} {r.probe.id} — {r.probe.name}  ({badge})"):
                st.write(f"**OWASP:** {r.probe.owasp}  |  **ATLAS:** {r.probe.atlas}  |  **Severity:** {r.probe.severity}")
                st.write(f"**Verdict:** {r.rationale}")
                st.code(f"attacker> {r.sample_prompt}\n\ntarget> {r.sample_response}")
        st.caption(f"Run logged as {st.session_state.get('scan_run_id')}")
    else:
        st.info("Run a scan to see the scorecard.")


# ---------------------------------------------------------------------------
# Attack tab
# ---------------------------------------------------------------------------

with attack_tab:
    st.subheader("Agentic multi-turn attacker")
    goals = load_goals()
    goal_id = st.selectbox("Goal", [g.id for g in goals])
    cols = st.columns(2)
    attacker_kind = cols[0].selectbox("Attacker strategy", ["scripted", "llm"], index=0)
    max_turns = cols[1].slider("Turn budget", min_value=1, max_value=10, value=5)
    st.caption("scripted runs offline. llm uses an attacker model to adapt each move.")

    if st.button("Launch Attack", type="primary"):
        try:
            target = build_target(target_kind, model=model_arg)
            goal = get_goal(goal_id)
            strategy = build_strategy(attacker_kind, model=model_arg)
            with st.spinner(f"Attacker pursuing {goal_id!r}..."):
                transcript = run_goal(target, goal, strategy=strategy, max_turns=max_turns)
            st.session_state["attack_transcript"] = transcript
        except Exception as exc:
            st.error(f"Attack failed: {exc}")

    t = st.session_state.get("attack_transcript")
    if t is not None:
        if t.succeeded:
            st.error(f"GOAL ACHIEVED in {t.turns_used} of {t.max_turns} turns — {t.description}")
        else:
            st.success(f"TARGET HELD across {t.turns_used} turns — {t.description}")
        st.write(f"**OWASP:** {t.owasp}  |  **ATLAS:** {t.atlas}")
        for turn in t.turns:
            label = "HIT" if turn.success else "miss"
            st.markdown(f"**Turn {turn.turn}** ({label})")
            st.code(f"attacker> {turn.prompt}\n\ntarget> {turn.response}")
    else:
        st.info("Launch an attack to see the turn by turn transcript.")


# ---------------------------------------------------------------------------
# History tab
# ---------------------------------------------------------------------------

with history_tab:
    st.subheader("Scan history")
    if _LOG_FILE.exists():
        records = [json.loads(line) for line in _LOG_FILE.read_text(encoding="utf-8").splitlines() if line.strip()]
        if records:
            hist = pd.DataFrame(records)
            hist["timestamp"] = pd.to_datetime(hist["timestamp"])
            st.markdown("#### Resilience over time")
            st.line_chart(hist.set_index("timestamp")[["resilience"]])
            st.markdown("#### Run log")
            st.dataframe(
                hist[["timestamp", "target", "model", "resilience", "grade", "vulnerabilities", "total_probes"]]
                .sort_values("timestamp", ascending=False),
                use_container_width=True,
            )
        else:
            st.info("No runs logged yet.")
    else:
        st.info("No runs logged yet. Run a scan first.")
