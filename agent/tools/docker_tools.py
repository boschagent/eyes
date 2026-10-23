"""Container health + deploy history tools (P3), and the docker data source.

Tool contract (every tool): returns
    {"ok": bool, "summary": str (<=1500 chars), "data": <compact json>, "source": "<exact command run>"}
and never raises: errors come back as ok=False.

Tools here:
  container_health(recent_minutes=10)  state/health/restarts/OOM/exit code per container
  deploy_history(minutes=120)          created/started/stopped events + the agent's own actions

Data source ("backend"): every tool takes an optional `backend=`. It only needs
three methods: ps(), inspect(ids), logs(service, minutes) (+ *_cmd() strings for
the "source" field). DockerSource shells out to the docker CLI (read-only
commands only); FixtureSource serves canned data for tests.
# ASSUMPTION: the team's backend.live / backend.offline objects (P1/P5) will expose
# these same methods, or get a thin adapter once the bundle format is known.

Run the tests:  python -m agent.tools.docker_tools   (or: python docker_tools.py)
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone


# ------------------------------------------------------------------ helpers
def parse_ts(s) -> datetime | None:
    """Parse docker's RFC3339 timestamps (nanoseconds, 'Z'). None for zero/invalid."""
    if not s or not isinstance(s, str):
        return None
    s = re.sub(r"\.(\d+)", lambda m: "." + m.group(1)[:6].ljust(6, "0"), s)
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return None if d.year < 2000 else d  # docker uses 0001-01-01 for "never"


def _label(row: dict, key: str) -> str | None:
    """Read one label from a `docker ps --format '{{json .}}'` row ("k=v,k=v")."""
    for part in str(row.get("Labels", "")).split(","):
        k, _, v = part.partition("=")
        if k == key:
            return v
    return None


def _ok(summary: str, data, source: str) -> dict:
    return {"ok": True, "summary": summary[:1500], "data": data, "source": source}


def _err(msg: str, source: str = "") -> dict:
    return {"ok": False, "summary": f"ERROR: {msg}"[:1500], "data": None, "source": source}


# -------------------------------------------------------------- data sources
class DockerSource:
    """Live source: read-only docker CLI calls (ps, inspect, logs)."""

    def _docker(self, *args: str, timeout: int = 30, merge_stderr: bool = False) -> str:
        p = subprocess.run(
            ["docker", *args], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
            text=True, timeout=timeout)
        if p.returncode != 0:
            raise RuntimeError((p.stderr or p.stdout or "docker failed").strip()[:300])
        return p.stdout

    def ps_cmd(self) -> str:
        return "docker ps -a --format '{{json .}}'"

    def ps(self) -> list[dict]:
        out = self._docker("ps", "-a", "--format", "{{json .}}")
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    def inspect_cmd(self, ids: list[str]) -> str:
        return "docker inspect " + " ".join(ids)

    def inspect(self, ids: list[str]) -> list[dict]:
        return json.loads(self._docker("inspect", *ids, timeout=60)) if ids else []

    def resolve(self, service: str) -> str:
        """Map a service name (payment) to its container name."""
        rows = self.ps()
        names = [r["Names"] for r in rows]
        if service in names:  # the demo sets container_name = service name
            return service
        # compose label is exact even with prefixed names (demo-cart-1 vs demo-valkey-cart-1)
        by_label = [r["Names"] for r in rows
                    if _label(r, "com.docker.compose.service") == service]
        if len(by_label) == 1:
            return by_label[0]
        pat = re.compile(rf"(^|[-_.]){re.escape(service)}([-_.]\d+)?$")
        cands = [n for n in names if pat.search(n)]
        if len(cands) == 1:
            return cands[0]
        raise RuntimeError(f"no unique container for service '{service}' "
                           f"(matches: {cands or 'none'})")

    def logs_cmd(self, service: str, minutes: int) -> str:
        return f"docker logs --since {minutes}m --timestamps {service}"

    def logs(self, service: str, minutes: int) -> list[str]:
        name = self.resolve(service)
        # apps write errors to stderr, so merge both streams
        out = self._docker("logs", "--since", f"{minutes}m", "--timestamps", name,
                           timeout=60, merge_stderr=True)
        return out.splitlines()


class FixtureSource:
    """Offline/test source: canned docker-inspect dicts and log lines."""

    def __init__(self, logs: dict[str, list[str]] | None = None,
                 containers: list[dict] | None = None):
        self._logs = logs or {}
        self._containers = containers or []

    def ps_cmd(self) -> str:
        return "fixture: docker ps -a"

    def ps(self) -> list[dict]:
        return [{"ID": c["Id"][:12], "Names": c["Name"].lstrip("/")} for c in self._containers]

    def inspect_cmd(self, ids: list[str]) -> str:
        return "fixture: docker inspect " + " ".join(ids)

    def inspect(self, ids: list[str]) -> list[dict]:
        return [c for c in self._containers if any(c["Id"].startswith(i) for i in ids)]

    def logs_cmd(self, service: str, minutes: int) -> str:
        return f"fixture: docker logs --since {minutes}m --timestamps {service}"

    def logs(self, service: str, minutes: int) -> list[str]:
        if service not in self._logs:
            raise KeyError(f"no fixture logs for service '{service}'")
        return list(self._logs[service])


# -------------------------------------------------------------------- tools
def _image_tag(image: str) -> str:
    tail = image.rsplit("/", 1)[-1]
    return tail.rsplit(":", 1)[1] if ":" in tail else "latest"


def _inspect_all(src) -> list[dict]:
    ids = [r["ID"] for r in src.ps()]
    return src.inspect(ids)


def container_health(recent_minutes: int = 10, backend=None, now: datetime | None = None) -> dict:
    """State, health, restart count, started_at, OOMKilled, exit code, image tag per
    container. Anything not running/healthy, restarted, or started recently is flagged."""
    src = backend or DockerSource()
    source = f"{src.ps_cmd()} ; docker inspect <all container ids>"
    try:
        now = now or datetime.now(timezone.utc)
        rows = []
        for i in _inspect_all(src):
            st = i.get("State", {})
            name = i.get("Name", "?").lstrip("/")
            health = (st.get("Health") or {}).get("Status")
            restarts = int(i.get("RestartCount", 0))
            started = parse_ts(st.get("StartedAt"))
            issues = []
            if st.get("Restarting"):
                issues.append("restart loop")
            elif not st.get("Running"):
                issues.append(f"not running (status={st.get('Status', '?')}, "
                              f"exit code {st.get('ExitCode')})")
            if health not in (None, "", "healthy"):
                issues.append(f"health={health}")
            if st.get("OOMKilled"):
                issues.append("OOMKilled")
            if restarts > 0:
                issues.append(f"restart count {restarts}")
            if started and now - started < timedelta(minutes=recent_minutes) and st.get("Running"):
                issues.append(f"started {int((now - started).total_seconds())}s ago")
            rows.append({
                "container": name, "status": st.get("Status"), "health": health,
                "restart_count": restarts, "started_at": st.get("StartedAt"),
                "oom_killed": bool(st.get("OOMKilled")), "exit_code": st.get("ExitCode"),
                "image_tag": _image_tag(i.get("Config", {}).get("Image", "")),
                "issues": issues,
            })
        rows.sort(key=lambda r: (-len(r["issues"]), r["container"]))
        problems = [r for r in rows if r["issues"]]
        running = sum(1 for r in rows if r["status"] == "running")
        head = f"{len(rows)} containers, {running} running, {len(problems)} flagged."
        lines = [f"- {r['container']}: {'; '.join(r['issues'])}" for r in problems]
        return _ok("\n".join([head, *lines]) if lines else head + " All healthy.",
                   {"containers": rows, "problems": [r["container"] for r in problems]}, source)
    except Exception as e:  # tools never raise
        return _err(str(e), source)


def deploy_history(minutes: int = 120, actions_log: str = "logs/actions.jsonl",
                   backend=None, now: datetime | None = None) -> dict:
    """Timeline of container created/started/stopped events in the window, merged with
    the agent's own actions from logs/actions.jsonl (written by P4's action client)."""
    src = backend or DockerSource()
    source = f"{src.ps_cmd()} ; docker inspect <all container ids> ; read {actions_log}"
    try:
        now = now or datetime.now(timezone.utc)
        since = now - timedelta(minutes=minutes)
        events = []

        def add(ts, kind, who, detail=""):
            if ts and ts >= since:
                events.append({"ts": ts.isoformat(), "kind": kind, "who": who, "detail": detail})

        for i in _inspect_all(src):
            st = i.get("State", {})
            name = i.get("Name", "?").lstrip("/")
            restarts = int(i.get("RestartCount", 0))
            add(parse_ts(i.get("Created")), "created", name)
            add(parse_ts(st.get("StartedAt")), "started", name,
                f"restart_count={restarts}" if restarts else "")
            if not st.get("Running"):
                add(parse_ts(st.get("FinishedAt")), "stopped", name,
                    f"exit code {st.get('ExitCode')}" + (", OOMKilled" if st.get("OOMKilled") else ""))

        # ASSUMPTION: P4 writes one JSON object per line with "timestamp" (or "ts"),
        # "action", "params", "dry_run". Unknown shapes are skipped, not fatal.
        if os.path.exists(actions_log):
            with open(actions_log, encoding="utf-8") as f:
                for line in f:
                    try:
                        a = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(a, dict):
                        continue
                    add(parse_ts(a.get("timestamp") or a.get("ts")), "agent_action",
                        str(a.get("action", "?")),
                        f"{a.get('params', '')} dry_run={a.get('dry_run')}".strip())

        events.sort(key=lambda e: e["ts"])
        lines = [f"{e['ts'][11:19]} {e['kind']} {e['who']} {e['detail']}".rstrip() for e in events]
        head = f"{len(events)} events in the last {minutes} min."
        return _ok("\n".join([head, *lines]) if lines else head, {"events": events}, source)
    except Exception as e:
        return _err(str(e), source)


# -------------------------------------------------------------------- tests
def _container(cid, name, status, running=True, restarting=False, health=None, restarts=0,
               oom=False, exit_code=0, created="2026-10-23T09:00:00.000000000Z",
               started="2026-10-23T09:00:01.123456789Z",
               finished="0001-01-01T00:00:00Z", image="ghcr.io/x/demo:3.1.0-payment"):
    st = {"Status": status, "Running": running, "Restarting": restarting, "OOMKilled": oom,
          "ExitCode": exit_code, "StartedAt": started, "FinishedAt": finished}
    if health:
        st["Health"] = {"Status": health}
    return {"Id": cid * 8, "Name": "/" + name, "Created": created, "RestartCount": restarts,
            "State": st, "Config": {"Image": image}}


def selftest() -> None:
    now = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
    fx = FixtureSource(containers=[
        _container("aaaa", "payment", "running", health="healthy"),
        _container("bbbb", "cart", "exited", running=False, oom=True, exit_code=137,
                   finished="2026-10-23T11:55:00.000000000Z"),
        _container("cccc", "email", "running", restarts=4, started="2026-10-23T11:58:30Z"),
        _container("dddd", "recommendation", "running", health="unhealthy"),
    ])

    # container_health: flags the right containers and reasons, leaves healthy alone
    r = container_health(backend=fx, now=now)
    assert r["ok"] and r["source"] and len(r["summary"]) <= 1500
    probs = set(r["data"]["problems"])
    assert probs == {"cart", "email", "recommendation"}, probs
    by = {c["container"]: c for c in r["data"]["containers"]}
    assert by["payment"]["issues"] == [] and by["payment"]["image_tag"] == "3.1.0-payment"
    assert "OOMKilled" in by["cart"]["issues"]
    assert any("exit code 137" in x for x in by["cart"]["issues"])
    assert "restart count 4" in by["email"]["issues"]
    assert any(x.startswith("started 90s ago") for x in by["email"]["issues"])
    assert "health=unhealthy" in by["recommendation"]["issues"]
    assert r["data"]["containers"][0]["container"] in probs  # problems sorted first
    assert "All healthy" not in r["summary"]

    all_good = FixtureSource(containers=[_container("aaaa", "payment", "running", health="healthy")])
    assert "All healthy" in container_health(backend=all_good, now=now)["summary"]

    # deploy_history: window filter, ordering, and merge with the agent's action log
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "actions.jsonl")
        with open(p, "w") as f:
            f.write(json.dumps({"timestamp": "2026-10-23T11:57:00Z", "action": "restart_service",
                                "params": {"service": "cart"}, "dry_run": True}) + "\n")
            f.write(json.dumps({"timestamp": "2026-10-23T08:00:00Z", "action": "old"}) + "\n")
            f.write("not json\n")
        h = deploy_history(minutes=120, actions_log=p, backend=fx, now=now)
        assert h["ok"], h
        kinds = [(e["kind"], e["who"]) for e in h["data"]["events"]]
        assert kinds == [("stopped", "cart"), ("agent_action", "restart_service"),
                         ("started", "email")], kinds
        assert "restart_count=4" in h["data"]["events"][2]["detail"]
        # missing actions log is fine
        h2 = deploy_history(minutes=120, actions_log=os.path.join(d, "nope.jsonl"),
                            backend=fx, now=now)
        assert [e["kind"] for e in h2["data"]["events"]] == ["stopped", "started"]

    # a wider window also pulls in boot-time created/started events
    wide = deploy_history(minutes=600, actions_log="/nonexistent", backend=fx, now=now)
    assert sum(e["kind"] == "created" for e in wide["data"]["events"]) == 4

    # tools never raise
    class Broken:
        def ps_cmd(self): return "broken"
        def ps(self): raise RuntimeError("docker daemon not running")
    for tool in (container_health, deploy_history):
        bad = tool(backend=Broken())
        assert bad["ok"] is False and "docker daemon" in bad["summary"], bad

    # DockerSource.resolve: exact name, compose-service label, then suffix match; ambiguity errors
    class Rows(DockerSource):
        def __init__(self, rows): self.rows = rows
        def ps(self): return self.rows
    lab = lambda s: f"a=b,com.docker.compose.service={s},c=d"  # noqa: E731
    prefixed = Rows([{"ID": "1", "Names": "demo-cart-1", "Labels": lab("cart")},
                     {"ID": "2", "Names": "demo-valkey-cart-1", "Labels": lab("valkey-cart")}])
    assert prefixed.resolve("cart") == "demo-cart-1"
    assert prefixed.resolve("valkey-cart") == "demo-valkey-cart-1"
    exact = Rows([{"ID": "1", "Names": "cart"}, {"ID": "2", "Names": "valkey-cart"}])
    assert exact.resolve("cart") == "cart"
    suffix = Rows([{"ID": "1", "Names": "demo-payment-1"}, {"ID": "2", "Names": "demo-email-1"}])
    assert suffix.resolve("payment") == "demo-payment-1"
    for rows in (Rows([{"ID": "1", "Names": "demo-cart-1"}, {"ID": "2", "Names": "x-cart-1"}]),
                 Rows([{"ID": "1", "Names": "demo-email-1"}])):
        try:
            rows.resolve("cart")
            raise AssertionError("should have raised")
        except RuntimeError:
            pass

    assert parse_ts("0001-01-01T00:00:00Z") is None
    assert parse_ts("2026-10-23T11:58:30.123456789Z").microsecond == 123456


if __name__ == "__main__":
    selftest()
    print("ALL TESTS PASSED")
