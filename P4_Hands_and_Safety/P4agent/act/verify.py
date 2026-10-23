"""Verify a fix by re-measuring, and roll back (after approval) + escalate if it didn't work.

You supply health_fn() -> {"error_rate": float, "p95_ms": float} for the affected service
(P2's service_red() can be wrapped to produce this). Recovered = error_rate and p95 both
within baseline * 1.2 for `consecutive` polls in a row.

Statuses: recovered | rolled_back | rollback_failed | rollback_rejected | no_rollback | killed
Everything except "recovered" sets escalate=True (escalation beats a confident wrong fix).
"""
from __future__ import annotations

import time
from typing import Any, Callable

from agent.act import killswitch
from agent.act.action_api import ActionClient, FakeTransport, inverse_of, load_runbook
from agent.act.approval import Approval

# ASSUMPTIONS (tunable; list in docs/DECISIONS.md):
FACTOR = 1.2           # "within baseline*1.2" from the task brief
ERR_FLOOR = 0.005      # if baseline error rate is ~0, 0*1.2 would be impossible to meet -> allow 0.5%
POLL_S = 15            # poll every 15s
MINUTES = 5            # give the fix N minutes
CONSECUTIVE = 2        # must look healthy on 2 polls in a row (avoids a lucky single sample)


def is_recovered(current: dict, baseline: dict, factor: float = FACTOR, err_floor: float = ERR_FLOOR) -> bool:
    try:
        err, p95 = float(current["error_rate"]), float(current["p95_ms"])
        b_err, b_p95 = float(baseline["error_rate"]), float(baseline["p95_ms"])
    except (KeyError, TypeError, ValueError):
        return False  # missing/garbled data is never "recovered"
    return err <= max(b_err * factor, err_floor) and p95 <= b_p95 * factor


def verify_and_rollback(
    health_fn: Callable[[], dict],
    baseline: dict,
    client: ActionClient,
    action: str,
    params: dict,
    approval_fn: Callable[[dict], Approval],
    minutes: float = MINUTES,
    interval_s: float = POLL_S,
    consecutive: int = CONSECUTIVE,
    sleep_fn: Callable[[float], Any] = time.sleep,
    clock_fn: Callable[[], float] = time.monotonic,
) -> dict:
    """Call this AFTER a real (non-dry-run) action. approval_fn(plan) -> Approval is used for the rollback."""
    start, history, streak = clock_fn(), [], 0
    result: dict[str, Any] = {"status": "", "recovered": False, "escalate": True, "polls": history, "rollback": None}

    while clock_fn() - start < minutes * 60:
        if killswitch.is_engaged(client.kill_file):
            result.update(status="killed", note=f"kill switch: {killswitch.reason(client.kill_file)}; "
                          "no further actions taken, human must take over")
            return result
        sleep_fn(interval_s)
        try:
            cur = health_fn()
        except Exception as e:  # noqa: BLE001
            cur = {"error": f"{type(e).__name__}: {e}"}
        ok = is_recovered(cur, baseline)
        history.append({"t": round(clock_fn() - start, 1), "health": cur, "ok": ok})
        streak = streak + 1 if ok else 0
        if streak >= consecutive:
            result.update(status="recovered", recovered=True, escalate=False)
            return result

    # ---- not recovered: try the inverse action, but only with human approval
    inv = inverse_of(client.rb, action, params)
    if inv is None:
        result.update(status="no_rollback", note=f"'{action}' has no automatic inverse; escalate to a human")
        return result
    inv_action, inv_params = inv
    plan = {"action": inv_action, "params": inv_params,
            "rationale": f"ROLLBACK: '{action}' did not restore health within {minutes} min"}
    approval = approval_fn(plan)
    if not (isinstance(approval, Approval) and approval.approved):
        result.update(status="rollback_rejected", note="rollback not approved; escalate")
        return result
    r = client.execute(inv_action, inv_params, approval, dry_run=False)
    result["rollback"] = r
    result["status"] = "rolled_back" if r["ok"] else "rollback_failed"
    return result


def selftest() -> None:
    import os
    os.environ.pop("AGENT_KILL", None)
    base = {"error_rate": 0.0, "p95_ms": 100.0}
    good, bad = {"error_rate": 0.0, "p95_ms": 110.0}, {"error_rate": 0.4, "p95_ms": 900.0}

    # --- is_recovered
    assert is_recovered(good, base)
    assert not is_recovered(bad, base)
    assert not is_recovered({"error_rate": 0.0, "p95_ms": 121.0}, base)       # p95 just above 1.2x
    assert is_recovered({"error_rate": 0.0, "p95_ms": 120.0}, base)
    assert not is_recovered({"error_rate": 0.02, "p95_ms": 100.0}, base)      # above floor
    assert is_recovered({"error_rate": 0.012, "p95_ms": 100.0}, {"error_rate": 0.01, "p95_ms": 100.0})
    assert not is_recovered({}, base) and not is_recovered({"error": "x"}, base)  # garbage != recovered

    import tempfile
    from pathlib import Path
    rb = load_runbook()
    yes = Approval.make(True, "tester", "yes")
    no = Approval.make(False, "tester", "no")

    def make(td, transport):
        clk = [0.0]
        def sleep(s): clk[0] += s
        c = ActionClient("http://api.test", "tok", dry_run=False, runbook=rb,
                         log_path=Path(td) / "a.jsonl", transport=transport, kill_file=Path(td) / "KILL")
        return c, sleep, (lambda: clk[0])

    def seq(vals):
        it = iter(vals)
        return lambda: next(it, vals[-1])

    flag = ("toggle_flag", {"flag": "someFlag", "enabled": False})
    with tempfile.TemporaryDirectory() as td:
        # --- recovered: no rollback call, no escalation
        t = FakeTransport(); c, sl, ck = make(td, t)
        r = verify_and_rollback(seq([bad, good, good]), base, c, *flag, approval_fn=lambda p: yes, sleep_fn=sl, clock_fn=ck)
        assert r["status"] == "recovered" and r["recovered"] and not r["escalate"] and t.calls == []

        # --- one lucky good sample isn't enough (consecutive=2)
        t = FakeTransport(); c, sl, ck = make(td, t)
        r = verify_and_rollback(seq([good, bad, good, bad]), base, c, *flag, approval_fn=lambda p: yes,
                                minutes=1, sleep_fn=sl, clock_fn=ck)
        assert r["status"] == "rolled_back"

        # --- never recovers -> inverse sent (with approval) + escalate
        t = FakeTransport(); c, sl, ck = make(td, t); seen = []
        def appr(plan): seen.append(plan); return yes
        r = verify_and_rollback(seq([bad]), base, c, *flag, approval_fn=appr, sleep_fn=sl, clock_fn=ck)
        assert r["status"] == "rolled_back" and r["escalate"] and not r["recovered"]
        assert len(t.calls) == 1 and t.calls[0]["json"] == {"flag": "someFlag", "enabled": True}
        assert seen and "ROLLBACK" in seen[0]["rationale"]

        # --- rollback not approved -> nothing sent, still escalate
        t = FakeTransport(); c, sl, ck = make(td, t)
        r = verify_and_rollback(seq([bad]), base, c, *flag, approval_fn=lambda p: no, sleep_fn=sl, clock_fn=ck)
        assert r["status"] == "rollback_rejected" and r["escalate"] and t.calls == []

        # --- restart has no inverse -> escalate, nothing sent
        t = FakeTransport(); c, sl, ck = make(td, t)
        r = verify_and_rollback(seq([bad]), base, c, "restart_service", {"service": "payment"},
                                approval_fn=lambda p: yes, sleep_fn=sl, clock_fn=ck)
        assert r["status"] == "no_rollback" and r["escalate"] and t.calls == []

        # --- rollback API call fails -> rollback_failed + escalate
        t = FakeTransport(status=500); c, sl, ck = make(td, t)
        r = verify_and_rollback(seq([bad]), base, c, *flag, approval_fn=lambda p: yes, sleep_fn=sl, clock_fn=ck)
        assert r["status"] == "rollback_failed" and r["escalate"]

        # --- health_fn raising counts as unhealthy, never crashes
        def boom(): raise RuntimeError("prometheus down")
        t = FakeTransport(); c, sl, ck = make(td, t)
        r = verify_and_rollback(boom, base, c, *flag, approval_fn=lambda p: yes, sleep_fn=sl, clock_fn=ck)
        assert r["status"] == "rolled_back" and "prometheus down" in str(r["polls"][0])

        # --- KILL during verification: stop, NO rollback action, escalate
        t = FakeTransport(); c, sl, ck = make(td, t)
        def kill_sleep(s): sl(s); (Path(td) / "KILL").write_text("x")
        r = verify_and_rollback(seq([bad]), base, c, *flag, approval_fn=lambda p: yes, sleep_fn=kill_sleep, clock_fn=ck)
        (Path(td) / "KILL").unlink()
        assert r["status"] == "killed" and r["escalate"] and t.calls == []


if __name__ == "__main__":
    selftest()
    print("ALL TESTS PASSED")
