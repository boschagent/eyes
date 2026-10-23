"""Approval UI (Streamlit). Run:  streamlit run ui/app.py

Handshake with the agent is file-based (see agent/act/approval.py::file_approval):
  agent writes  pending/approval.json   -> this page shows it
  Approve/Reject write pending/decision.json (with the same proposal id) -> agent continues
The red KILL button creates ./KILL, which halts the agent before its next action/step.
"""
from __future__ import annotations

import getpass
import json
import os
import sys
import time
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # so `agent` imports work
from agent.act import killswitch  # noqa: E402
from agent.act.approval import _atomic_write_json  # noqa: E402

PENDING = Path(os.environ.get("AGENT_PENDING_DIR", "pending"))
ACTION_LOG = Path("logs/actions.jsonl")

st.set_page_config(page_title="AI On-Call: Approval", page_icon="🛑", layout="wide")
st.title("AI On-Call Engineer - approval & safety")

# ---- sidebar: KILL switch is always reachable
with st.sidebar:
    st.header("Kill switch")
    if killswitch.is_engaged():
        st.error(f"ENGAGED ({killswitch.reason()}). The agent will not act.")
        if st.button("Clear KILL (resume)"):
            killswitch.clear()
            st.rerun()
    else:
        st.success("Not engaged")
    if st.button("KILL - halt the agent now", type="primary", use_container_width=True):
        killswitch.engage(why="UI button")
        st.rerun()
    auto = st.checkbox("Auto-refresh every 2s", value=True)

# ---- pending proposal
approval_f, decision_f = PENDING / "approval.json", PENDING / "decision.json"
pending = None
if approval_f.exists():
    try:
        pending = json.loads(approval_f.read_text())
    except ValueError:
        pending = None  # half-written / garbage: treat as nothing pending

if pending is None:
    st.info("No pending proposal. Waiting for the agent...")
else:
    d, plan = pending.get("diagnosis", {}), pending.get("plan", {})
    st.subheader("The agent wants to change the system")
    c1, c2 = st.columns(2)
    c1.metric("Component", str(d.get("component", "?")))
    c2.metric("Confidence", str(d.get("confidence", "?")))
    st.markdown(f"**Root cause:** {d.get('root_cause', '?')}")
    st.markdown("**Evidence**")
    for e in pending.get("evidence", []):
        st.markdown(f"- `{e.get('id', '?')}` {e.get('summary', '')}")
    st.markdown("**Proposed action**")
    st.code(f"{plan.get('action')}  {json.dumps(plan.get('params', {}))}", language="text")
    if plan.get("rationale"):
        st.caption(plan["rationale"])
    if pending.get("request"):
        st.markdown("**Exact request that will be sent**")
        st.code(json.dumps(pending["request"], indent=2), language="json")

    def decide(choice: str) -> None:
        _atomic_write_json(decision_f, {"id": pending["id"], "decision": choice,
                                        "by": getpass.getuser(), "ts": time.time()})
        st.rerun()

    a, r = st.columns(2)
    if a.button("Approve", type="primary", use_container_width=True, disabled=killswitch.is_engaged()):
        decide("approve")
    if r.button("Reject", use_container_width=True):
        decide("reject")

# ---- audit trail
st.divider()
st.subheader("Action log (latest 10)")
if ACTION_LOG.exists():
    rows = [json.loads(x) for x in ACTION_LOG.read_text().splitlines()[-10:] if x.strip()]
    st.dataframe(rows[::-1], use_container_width=True)
else:
    st.caption("No actions logged yet.")

if auto:
    time.sleep(2)
    st.rerun()
