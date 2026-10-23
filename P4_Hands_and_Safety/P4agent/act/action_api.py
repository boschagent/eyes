"""Client for the organisers' Action API, wrapped in every safety check we have.

execute() order of checks (first failure blocks, nothing is sent, the attempt is logged):
  1. kill switch  2. runbook allowlist + param validation + preconditions
  3. dry-run? -> build + return the exact request, send NOTHING
  4. human approval present and approved  5. kill switch AGAIN (approval can take minutes)
  6. send.
Every call (sent, dry-run, or blocked) appends one JSON line to logs/actions.jsonl.

Like all our tools, execute() never raises; it returns
  {"ok": bool, "summary": str, "data": {...}, "source": "<METHOD url>"}.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from agent.act import killswitch
from agent.act.approval import Approval, request_approval

RUNBOOK_PATH = Path(__file__).with_name("runbook.yaml")
DEFAULT_LOG = Path("logs/actions.jsonl")
# transport(method, url, headers, json_body, timeout_s) -> (http_status, parsed_body); status 0 = network error
Transport = Callable[[str, str, dict, Optional[dict], float], tuple]


# ----------------------------------------------------------------------------- runbook
def load_runbook(path: str | os.PathLike | None = None) -> dict:
    with open(path or RUNBOOK_PATH) as f:
        rb = yaml.safe_load(f)
    assert isinstance(rb.get("actions"), dict) and rb["actions"], "runbook has no actions"
    return rb


def _service_not_denied(rb: dict, params: dict) -> str | None:
    deny = {s.lower() for s in rb.get("denylist_services", [])}
    svc = str(params.get("service", "")).lower()
    return f"service '{svc}' is on the denylist" if svc in deny else None


PRECONDITIONS: dict[str, Callable[[dict, dict], Optional[str]]] = {"service_not_denied": _service_not_denied}


def validate_action(rb: dict, action: str, params: dict | None) -> tuple[bool, list[str], dict]:
    """Return (ok, errors, cleaned_params). Fails closed on anything unknown."""
    spec = rb["actions"].get(action)
    if spec is None:
        return False, [f"action '{action}' is not in the runbook allowlist"], {}
    errors: list[str] = []
    clean: dict[str, Any] = {}
    params = dict(params or {})
    pspecs = spec.get("params", {})
    for k in params:
        if k not in pspecs:
            errors.append(f"unexpected param '{k}'")
    for name, ps in pspecs.items():
        if name not in params:
            if ps.get("required"):
                errors.append(f"missing required param '{name}'")
            continue
        v, t = params[name], ps["type"]
        if t == "str":
            if not isinstance(v, str) or not v:
                errors.append(f"param '{name}' must be a non-empty string")
            elif ps.get("pattern") and not re.fullmatch(ps["pattern"], v):
                errors.append(f"param '{name}'={v!r} does not match {ps['pattern']!r}")
        elif t == "int":
            if isinstance(v, bool) or not isinstance(v, int):
                errors.append(f"param '{name}' must be an integer")
            elif not (ps.get("min", v) <= v <= ps.get("max", v)):
                errors.append(f"param '{name}'={v} outside [{ps.get('min')}, {ps.get('max')}]")
        elif t == "bool":
            if not isinstance(v, bool):
                errors.append(f"param '{name}' must be a boolean")
        else:
            errors.append(f"runbook error: unknown type '{t}' for '{name}'")
        clean[name] = v
    for pre in spec.get("preconditions", []):
        fn = PRECONDITIONS.get(pre)
        if fn is None:
            errors.append(f"unknown precondition '{pre}'")  # fail closed
        elif (msg := fn(rb, clean)):
            errors.append(msg)
    return not errors, errors, clean


def inverse_of(rb: dict, action: str, params: dict) -> tuple[str, dict] | None:
    """The rollback action for (action, params), or None if it can't be undone automatically."""
    inv = rb["actions"].get(action, {}).get("inverse")
    if not inv:
        return None
    out: dict[str, Any] = {}
    try:
        for k, v in inv["params"].items():
            if isinstance(v, str) and v.startswith("!$"):
                out[k] = not params[v[2:]]
            elif isinstance(v, str) and v.startswith("$"):
                out[k] = params[v[1:]]
            else:
                out[k] = v
    except KeyError:
        return None
    return inv["action"], out


# ----------------------------------------------------------------------------- transport
def http_transport(method: str, url: str, headers: dict, body: dict | None, timeout: float) -> tuple:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={**headers, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status, raw = r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read().decode(errors="replace")
    except Exception as e:  # noqa: BLE001  (network errors must not raise)
        return 0, {"error": f"{type(e).__name__}: {e}"}
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, {"raw": raw[:500]}


class FakeTransport:
    """Local stub of the Action API for tests: records every call, returns a canned reply."""

    def __init__(self, status: int = 200, body: Any = None):
        self.status, self.body, self.calls = status, body if body is not None else {"result": "ok"}, []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append({"method": method, "url": url, "headers": headers, "json": body})
        return self.status, self.body


# ----------------------------------------------------------------------------- client
class ActionClient:
    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        dry_run: bool = True,  # SAFE DEFAULT: nothing is sent unless the caller opts in
        runbook: dict | None = None,
        log_path: str | os.PathLike = DEFAULT_LOG,
        transport: Transport | None = None,
        kill_file: str | os.PathLike | None = None,
        timeout_s: float = 15.0,
    ):
        # ASSUMPTION: base URL / token come from env until we see the organisers' Action API docs.
        self.base_url = (base_url or os.environ.get("ACTION_API_URL", "http://localhost:8000")).rstrip("/")
        self.token = token if token is not None else os.environ.get("ACTION_API_TOKEN", "")
        self.dry_run = dry_run
        self.rb = runbook or load_runbook()
        self.log_path = Path(log_path)
        self.transport = transport or http_transport
        self.kill_file = kill_file
        self.timeout_s = timeout_s

    # -- helpers
    def build_request(self, action: str, params: dict, redact: bool = False) -> dict:
        api = self.rb["actions"][action]["api"]
        headers = {}
        if self.token:  # ASSUMPTION: bearer-token auth
            headers["Authorization"] = "Bearer ***" if redact else f"Bearer {self.token}"
        return {"method": api["method"], "url": self.base_url + api["path"], "headers": headers, "json": params}

    def _log(self, action, params, outcome, approval, dry, response=None, errors=None) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "action": action, "params": params, "outcome": outcome,
            "approved_by": approval.by if isinstance(approval, Approval) and approval.approved else None,
            "dry_run": dry, "response": response,
        }
        if errors:
            entry["errors"] = errors
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a") as f:  # single short write per line
            f.write(json.dumps(entry, default=str) + "\n")

    @staticmethod
    def _result(ok: bool, summary: str, data: dict, source: str) -> dict:
        return {"ok": ok, "summary": summary[:1500], "data": data, "source": source}

    def inverse(self, action: str, params: dict) -> tuple[str, dict] | None:
        return inverse_of(self.rb, action, params)

    # -- the one entry point
    def execute(self, action: str, params: dict, approval: Approval | None = None,
                dry_run: bool | None = None) -> dict:
        dry = self.dry_run if dry_run is None else dry_run
        src = f"{action} {json.dumps(params, default=str)}"

        def blocked(reason: str, detail: str, errors=None) -> dict:
            self._log(action, params, f"blocked:{reason}", approval, dry, errors=errors or [detail])
            return self._result(False, f"BLOCKED ({reason}): {detail}", {"blocked": reason, "sent": False}, src)

        if killswitch.is_engaged(self.kill_file):
            return blocked("kill_switch", killswitch.reason(self.kill_file) or "engaged")
        ok, errors, clean = validate_action(self.rb, action, params)
        if not ok:
            reason = "not_allowlisted" if action not in self.rb["actions"] else "invalid_params"
            return blocked(reason, "; ".join(errors), errors)

        if dry:
            req = self.build_request(action, clean, redact=True)
            self._log(action, clean, "dry_run", approval, True)
            return self._result(True, f"DRY RUN - would send {req['method']} {req['url']} {json.dumps(clean)}",
                                {"sent": False, "request": req}, f"{req['method']} {req['url']}")

        if approval is None or not isinstance(approval, Approval) or approval.approved is not True:
            return blocked("no_approval", "a human approval (typed 'yes') is required before any real call")
        if killswitch.is_engaged(self.kill_file):  # approval may have taken minutes
            return blocked("kill_switch", killswitch.reason(self.kill_file) or "engaged")

        req = self.build_request(action, clean)
        status, body = self.transport(req["method"], req["url"], req["headers"], req["json"], self.timeout_s)
        success = 200 <= status < 300
        self._log(action, clean, "executed" if success else f"failed:http_{status}", approval, False,
                  response={"status": status, "body": body})
        shown = self.build_request(action, clean, redact=True)
        return self._result(
            success,
            f"{'EXECUTED' if success else 'FAILED'} {shown['method']} {shown['url']} -> HTTP {status}: "
            f"{json.dumps(body, default=str)[:600]}",
            {"sent": True, "status": status, "response": body}, f"{shown['method']} {shown['url']}")


# ----------------------------------------------------------------------------- tests
def selftest() -> None:
    quiet = lambda *_a, **_k: None  # noqa: E731
    os.environ.pop("AGENT_KILL", None)
    rb = load_runbook()
    plan = {"action": "restart_service", "params": {"service": "payment"}}
    yes = Approval.make(True, "tester", "yes")

    # --- validation / allowlist
    assert validate_action(rb, "restart_service", {"service": "payment"})[0]
    ok, errs, _ = validate_action(rb, "drop_database", {})
    assert not ok and "allowlist" in errs[0]
    assert not validate_action(rb, "restart_service", {"service": "flagd"})[0]          # denylist
    assert not validate_action(rb, "restart_service", {"service": "FLAGD-ui"})[0]       # case-insens.
    assert not validate_action(rb, "restart_service", {"service": "pay; rm -rf /"})[0]  # pattern
    assert not validate_action(rb, "restart_service", {})[0]                            # missing
    assert not validate_action(rb, "restart_service", {"service": "a", "x": 1})[0]      # extra param
    assert not validate_action(rb, "scale_service", {"service": "a", "replicas": 99, "previous_replicas": 1})[0]
    assert not validate_action(rb, "scale_service", {"service": "a", "replicas": True, "previous_replicas": 1})[0]
    assert not validate_action(rb, "toggle_flag", {"flag": "x", "enabled": "false"})[0]  # must be bool

    # --- inverses
    assert inverse_of(rb, "restart_service", {"service": "a"}) is None
    assert inverse_of(rb, "toggle_flag", {"flag": "f", "enabled": False}) == ("toggle_flag", {"flag": "f", "enabled": True})
    assert inverse_of(rb, "scale_service", {"service": "a", "replicas": 3, "previous_replicas": 1}) == \
        ("scale_service", {"service": "a", "replicas": 1, "previous_replicas": 3})
    assert inverse_of(rb, "throttle_loadgen", {"users": 10, "previous_users": 200})[1]["users"] == 200

    with tempfile.TemporaryDirectory() as d:
        log, kf = Path(d) / "logs" / "actions.jsonl", Path(d) / "KILL"
        t = FakeTransport()
        c = ActionClient("http://api.test", "secret-token", dry_run=True, runbook=rb, log_path=log,
                         transport=t, kill_file=kf)

        # --- dry-run sends nothing, shows exact request, hides the token
        r = c.execute("restart_service", {"service": "payment"})
        assert r["ok"] and r["data"]["sent"] is False and t.calls == []
        assert r["data"]["request"]["url"] == "http://api.test/actions/restart_service"
        assert "secret-token" not in json.dumps(r)

        # --- real mode without approval: blocked
        c.dry_run = False
        assert c.execute("restart_service", {"service": "payment"})["data"]["blocked"] == "no_approval"
        assert t.calls == []
        # approval prompt answered anything but "yes": blocked
        for bad in ["no", "y", "YES", ""]:
            a = request_approval({}, [], plan, input_fn=lambda _, b=bad: bad, print_fn=quiet, kill_file=kf)
            assert c.execute("restart_service", {"service": "payment"}, a)["data"]["blocked"] == "no_approval"
        assert t.calls == []
        # forged/garbage approval objects are not accepted
        assert not c.execute("restart_service", {"service": "payment"}, approval=True)["ok"]  # type: ignore[arg-type]
        assert t.calls == []

        # --- typed "yes": exactly one call, with the real token
        a = request_approval({}, [], plan, input_fn=lambda _: "yes", print_fn=quiet, kill_file=kf)
        r = c.execute("restart_service", {"service": "payment"}, a)
        assert r["ok"] and r["data"]["sent"] and len(t.calls) == 1
        assert t.calls[0]["headers"]["Authorization"] == "Bearer secret-token"
        assert t.calls[0]["json"] == {"service": "payment"} and "secret-token" not in json.dumps(r)

        # --- non-allowlisted / denylisted: rejected even WITH approval, nothing sent
        n = len(t.calls)
        assert c.execute("drop_database", {}, yes)["data"]["blocked"] == "not_allowlisted"
        assert c.execute("restart_service", {"service": "flagd"}, yes)["data"]["blocked"] == "invalid_params"
        assert len(t.calls) == n

        # --- KILL file blocks even approved + dry-run calls
        killswitch.engage(kf)
        assert c.execute("restart_service", {"service": "payment"}, yes)["data"]["blocked"] == "kill_switch"
        assert c.execute("restart_service", {"service": "payment"}, dry_run=True)["data"]["blocked"] == "kill_switch"
        killswitch.clear(kf)
        # --- KILL env var blocks
        os.environ["AGENT_KILL"] = "1"
        try:
            assert c.execute("restart_service", {"service": "payment"}, yes)["data"]["blocked"] == "kill_switch"
        finally:
            os.environ.pop("AGENT_KILL")
        # --- KILL pressed while waiting for approval: re-checked right before sending
        a = request_approval({}, [], plan, print_fn=quiet, kill_file=kf,
                             input_fn=lambda _: (killswitch.engage(kf), "yes")[1])
        assert a.approved
        assert c.execute("restart_service", {"service": "payment"}, a)["data"]["blocked"] == "kill_switch"
        killswitch.clear(kf)
        assert len(t.calls) == n

        # --- API errors are reported, not raised
        c.transport = FakeTransport(status=500, body={"error": "boom"})
        r = c.execute("restart_service", {"service": "payment"}, yes)
        assert not r["ok"] and r["data"]["status"] == 500
        c.transport = lambda *a: (0, {"error": "ConnectionRefusedError"})
        assert not c.execute("restart_service", {"service": "payment"}, yes)["ok"]

        # --- audit log: every attempt recorded, valid JSON, approver recorded, no token
        lines = [json.loads(x) for x in log.read_text().splitlines()]
        outcomes = [x["outcome"] for x in lines]
        assert "dry_run" in outcomes and "executed" in outcomes and "blocked:kill_switch" in outcomes
        assert "blocked:no_approval" in outcomes and "blocked:not_allowlisted" in outcomes
        assert "failed:http_500" in outcomes
        ex = next(x for x in lines if x["outcome"] == "executed")
        assert ex["approved_by"] == "tester" or ex["approved_by"]  # approver recorded
        assert ex["dry_run"] is False and ex["action"] == "restart_service"
        assert all({"timestamp", "action", "params", "approved_by", "dry_run", "response"} <= x.keys() for x in lines)
        assert "secret-token" not in log.read_text()


if __name__ == "__main__":
    selftest()
    print("ALL TESTS PASSED")
