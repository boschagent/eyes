"""Human approval gate. Nothing is sent to the Action API without an Approval(approved=True).

Two ways to get a decision:
  * request_approval()  - CLI: prints diagnosis + evidence + plan, user must type exactly "yes".
  * file_approval()     - UI: writes pending/approval.json, waits for pending/decision.json
                          (written by ui/app.py's Approve / Reject buttons).
Anything other than an explicit approval (typo, "y", "YES", timeout, KILL) = REJECT.
"""
from __future__ import annotations

import getpass
import json
import os
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent.act import killswitch

# ASSUMPTION: "type exactly yes" means lowercase "yes" (surrounding whitespace/newline ignored).
YES = "yes"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Approval:
    approved: bool
    by: str
    ts: str
    answer: str = ""
    reason: str = ""

    @classmethod
    def make(cls, approved: bool, by: str, answer: str = "", reason: str = "") -> "Approval":
        return cls(approved=approved, by=by, ts=_now(), answer=answer, reason=reason)


def render(diagnosis: dict, evidence: list[dict], plan: dict, request: dict | None = None) -> str:
    """Human-readable approval prompt. `request` = the exact dry-run HTTP request, if known."""
    L = ["=" * 64, "  APPROVAL REQUIRED - the agent wants to change the system", "=" * 64]
    L.append(f"Root cause : {diagnosis.get('root_cause', '?')}")
    L.append(f"Component  : {diagnosis.get('component', '?')}")
    if "confidence" in diagnosis:
        L.append(f"Confidence : {diagnosis['confidence']}")
    L.append("Evidence   :")
    for e in evidence or []:
        L.append(f"  [{e.get('id', '?')}] {str(e.get('summary', ''))[:200]}")
    if not evidence:
        L.append("  (none provided)")
    L.append(f"Plan       : {plan.get('action')}  {json.dumps(plan.get('params', {}))}")
    if plan.get("rationale"):
        L.append(f"Why        : {plan['rationale']}")
    if request:
        L.append(f"Request    : {request.get('method')} {request.get('url')}  {json.dumps(request.get('json'))}")
    L.append("-" * 64)
    return "\n".join(L)


def request_approval(
    diagnosis: dict,
    evidence: list[dict],
    plan: dict,
    request: dict | None = None,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[[str], Any] = print,
    user: str | None = None,
    kill_file: str | None = None,
) -> Approval:
    who = user or _safe_user()
    if killswitch.is_engaged(kill_file):
        return Approval.make(False, who, reason=f"kill switch: {killswitch.reason(kill_file)}")
    print_fn(render(diagnosis, evidence, plan, request))
    try:
        answer = input_fn('Type exactly "yes" to approve (anything else rejects): ')
    except (EOFError, KeyboardInterrupt):
        return Approval.make(False, who, reason="no input / interrupted")
    ok = answer.strip() == YES
    return Approval.make(ok, who, answer=answer.strip(), reason="" if ok else "not 'yes'")


def _atomic_write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


def file_approval(
    diagnosis: dict,
    evidence: list[dict],
    plan: dict,
    request: dict | None = None,
    pending_dir: str | os.PathLike = "pending",
    timeout_s: float = 600.0,
    poll_s: float = 1.0,
    sleep_fn: Callable[[float], Any] = time.sleep,
    clock_fn: Callable[[], float] = time.monotonic,
    kill_file: str | None = None,
) -> Approval:
    """UI handshake via files. Used by ui/app.py. Timeout, KILL or garbage -> reject."""
    d = Path(pending_dir)
    pid = uuid.uuid4().hex[:12]
    approval_f, decision_f = d / "approval.json", d / "decision.json"
    decision_f.unlink(missing_ok=True)  # drop stale decisions from earlier proposals
    _atomic_write_json(approval_f, {
        "id": pid, "ts": _now(), "diagnosis": diagnosis, "evidence": evidence,
        "plan": plan, "request": request,
    })
    start = clock_fn()
    try:
        while True:
            if killswitch.is_engaged(kill_file):
                return Approval.make(False, "system", reason=f"kill switch: {killswitch.reason(kill_file)}")
            if decision_f.exists():
                try:
                    dec = json.loads(decision_f.read_text())
                except ValueError:
                    dec = {}
                if dec.get("id") == pid:
                    ok = dec.get("decision") == "approve"
                    return Approval.make(ok, str(dec.get("by", "ui")), answer=str(dec.get("decision", "")),
                                         reason="" if ok else "rejected in UI")
            if clock_fn() - start >= timeout_s:
                return Approval.make(False, "system", reason="approval timed out")
            sleep_fn(poll_s)
    finally:
        approval_f.unlink(missing_ok=True)
        decision_f.unlink(missing_ok=True)


def _safe_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "unknown"


def selftest() -> None:
    diag = {"root_cause": "payment bug", "component": "payment", "confidence": 0.9}
    ev = [{"id": "ev-001", "summary": "error rate 40%"}]
    plan = {"action": "restart_service", "params": {"service": "payment"}}
    quiet = lambda *_a, **_k: None  # noqa: E731
    with tempfile.TemporaryDirectory() as d:
        kf = Path(d) / "KILL"
        os.environ.pop("AGENT_KILL", None)
        # only exactly "yes" approves
        assert request_approval(diag, ev, plan, input_fn=lambda _: "yes\n", print_fn=quiet, kill_file=kf).approved
        for bad in ["", "y", "YES", "Yes", "no", "yes please", "yes!"]:
            a = request_approval(diag, ev, plan, input_fn=lambda _, b=bad: b, print_fn=quiet, kill_file=kf)
            assert not a.approved, bad
        # EOF / Ctrl-C reject
        def eof(_): raise EOFError
        assert not request_approval(diag, ev, plan, input_fn=eof, print_fn=quiet, kill_file=kf).approved
        # KILL blocks even a "yes"
        killswitch.engage(kf)
        assert not request_approval(diag, ev, plan, input_fn=lambda _: "yes", print_fn=quiet, kill_file=kf).approved
        killswitch.clear(kf)
        # render shows the essentials
        txt = render(diag, ev, plan, {"method": "POST", "url": "http://x/a", "json": {"service": "payment"}})
        assert "payment" in txt and "ev-001" in txt and "POST http://x/a" in txt

        # file handshake: approve
        pend = Path(d) / "pending"
        def approve_on_first_poll(_s):
            pid = json.loads((pend / "approval.json").read_text())["id"]
            _atomic_write_json(pend / "decision.json", {"id": pid, "decision": "approve", "by": "alice"})
        a = file_approval(diag, ev, plan, pending_dir=pend, sleep_fn=approve_on_first_poll, kill_file=kf)
        assert a.approved and a.by == "alice" and not (pend / "approval.json").exists()
        # decision for a different proposal id is ignored -> times out -> reject
        t = [0.0]
        def stale(_s):
            _atomic_write_json(pend / "decision.json", {"id": "other", "decision": "approve"})
            t[0] += 100
        a = file_approval(diag, ev, plan, pending_dir=pend, timeout_s=250, sleep_fn=stale,
                          clock_fn=lambda: t[0], kill_file=kf)
        assert not a.approved and "timed out" in a.reason
        # explicit reject
        def reject(_s):
            pid = json.loads((pend / "approval.json").read_text())["id"]
            _atomic_write_json(pend / "decision.json", {"id": pid, "decision": "reject"})
        assert not file_approval(diag, ev, plan, pending_dir=pend, sleep_fn=reject, kill_file=kf).approved
        # KILL during wait
        def kill_it(_s): killswitch.engage(kf)
        a = file_approval(diag, ev, plan, pending_dir=pend, sleep_fn=kill_it, kill_file=kf)
        assert not a.approved and "kill" in a.reason


if __name__ == "__main__":
    selftest()
    print("ALL TESTS PASSED")
