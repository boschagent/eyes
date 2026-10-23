"""get_logs tool (P3): sanitised, de-duplicated container logs.

    get_logs(service, minutes=10, grep=None, level=None, max_lines=60)

Pipeline: docker logs --since <m>m --timestamps -> drop flag-leaking lines ->
scrub secrets/PII -> parse (JSON or plain) -> filter -> collapse repeats into
templates with counts -> top error/warn lines first.

Tool contract: returns {"ok", "summary" (<=1500 chars), "data", "source"}; never raises.
The flagd containers are on a DENYLIST and refused outright.

See what the sanitiser keeps/drops on real logs (live demo running):
    python -m agent.tools.logs --live payment 10
Run the tests:
    python -m agent.tools.logs        (or: python logs.py)
"""
from __future__ import annotations

import json
import re
import sys

try:
    from agent.tools.docker_tools import DockerSource, FixtureSource
    from agent.tools.sanitize import drop_flag_lines, scrub_secrets
except ImportError:  # running this file directly from its own folder
    from docker_tools import DockerSource, FixtureSource
    from sanitize import drop_flag_lines, scrub_secrets

DENYLIST = {"flagd", "flagd-ui"}

_TS_RX = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)\s?(.*)$")
_LEVEL_TOKEN = re.compile(r"\b(FATAL|CRITICAL|SEVERE|ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE)\b")
_ERRORISH = re.compile(
    r"(?i)\b(error|fatal|panic|exception|critical|fail(?:ed|ure|s)?|refused|timed? ?out|"
    r"unavailable|deadline exceeded|out of memory|oom|unreachable|reset by peer)\b")
_RANK = {"error": 3, "warn": 2, "info": 1, "debug": 0}

# variable parts collapsed so repeated lines group together
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
_HEX = re.compile(r"\b[0-9a-f]{16,}\b")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
_NUM = re.compile(r"\b\d+(?:\.\d+)?(?:ms|us|µs|s|MB|KB|%)?\b")


def _ok(summary: str, data, source: str) -> dict:
    return {"ok": True, "summary": summary[:1500], "data": data, "source": source}


def _err(msg: str, source: str = "") -> dict:
    return {"ok": False, "summary": f"ERROR: {msg}"[:1500], "data": None, "source": source}


def _norm_level(v) -> str | None:
    if isinstance(v, (int, float)):  # pino-style numeric levels
        return "error" if v >= 50 else "warn" if v >= 40 else "info" if v >= 30 else "debug"
    if isinstance(v, str):
        s = v.lower()
        if s in ("fatal", "critical", "severe", "error", "err", "panic"):
            return "error"
        if s.startswith("warn"):
            return "warn"
        if s in ("info", "notice"):
            return "info"
        if s in ("debug", "trace"):
            return "debug"
    return None


def parse_line(raw: str) -> dict:
    """-> {"ts": str|None, "level": error|warn|info|debug, "msg": str}"""
    m = _TS_RX.match(raw)
    ts, rest = (m.group(1), m.group(2)) if m else (None, raw)
    level, msg = None, rest.strip()
    if msg.startswith("{"):  # JSON logs (node/pino, go/logrus, ...)
        try:
            d = json.loads(msg)
        except ValueError:
            d = None
        if isinstance(d, dict):
            text = next((str(d[k]) for k in ("msg", "message", "body", "log") if d.get(k)), "")
            extra = d.get("err") or d.get("error")
            if extra:
                text = f"{text} | {str(extra)[:150]}".strip(" |")
            msg = text or json.dumps(d, separators=(",", ":"))[:200]
            level = _norm_level(d.get("level") or d.get("severity") or d.get("severityText"))
    if level is None:
        t = _LEVEL_TOKEN.search(msg)
        if t:
            level = _norm_level(t.group(1)) or "info"
    if level is None:
        level = "error" if _ERRORISH.search(msg) else "info"
    return {"ts": ts, "level": level, "msg": msg}


def _template(msg: str) -> str:
    msg = _UUID.sub("<uuid>", msg)
    msg = _HEX.sub("<hex>", msg)
    msg = _IP.sub("<ip>", msg)
    return _NUM.sub("<n>", msg).strip()[:200]


def _short(ts: str | None) -> str:
    return ts[11:19] if ts and len(ts) >= 19 else "?"


def get_logs(service: str, minutes: int = 10, grep: str | None = None,
             level: str | None = None, max_lines: int = 60, backend=None) -> dict:
    """Sanitised, de-duplicated logs for one service. `level` is a minimum severity
    (error > warn > info > debug); default is warn, falling back to everything if
    nothing that severe was logged. `grep` is a case-insensitive regex on the message
    and runs AFTER sanitising, so flag lines can't be searched for."""
    src = backend or DockerSource()
    service = (service or "").strip()
    source = ""
    try:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", service):
            return _err("invalid service name")
        if service.lower() in DENYLIST or "flagd" in service.lower():
            return _err(f"service '{service}' is denied: feature-flag services are off limits")
        minutes = max(1, min(int(minutes), 1440))
        max_lines = max(1, min(int(max_lines), 200))
        source = src.logs_cmd(service, minutes)

        raw = src.logs(service, minutes)
        kept, dropped = drop_flag_lines(raw)
        parsed = [parse_line(scrub_secrets(line)) for line in kept if line.strip()]
        if grep:
            try:
                rx = re.compile(grep, re.I)
            except re.error:
                rx = re.compile(re.escape(grep), re.I)
            parsed = [p for p in parsed if rx.search(p["msg"])]

        min_rank = _RANK.get(level or "warn", 2)
        pool = [p for p in parsed if _RANK[p["level"]] >= min_rank]
        fell_back = False
        if not pool and level is None:  # nothing error/warn: show whatever there is
            pool, fell_back = parsed, True

        groups: dict[tuple[str, str], dict] = {}
        for p in pool:
            g = groups.setdefault((p["level"], _template(p["msg"])), {
                "level": p["level"], "count": 0, "first_ts": p["ts"],
                "last_ts": p["ts"], "message": p["msg"][:300]})
            g["count"] += 1
            g["last_ts"] = p["ts"] or g["last_ts"]
        entries = sorted(groups.values(), key=lambda g: (-_RANK[g["level"]], -g["count"],
                                                         g["first_ts"] or ""))
        truncated = len(entries) > max_lines
        entries = entries[:max_lines]

        n_err = sum(1 for e in entries if e["level"] == "error")
        head = (f"{service}: {len(raw)} lines in last {minutes}m, sanitiser dropped {len(dropped)}; "
                f"showing {len(entries)} distinct ({n_err} error)"
                + (" [no error/warn lines; showing all]" if fell_back else "")
                + (" [truncated]" if truncated else ""))
        body = []
        for e in entries[:12]:
            a, b = _short(e["first_ts"]), _short(e["last_ts"])
            body.append(f"[{e['level'].upper()} x{e['count']} {a if a == b else a + '-' + b}] "
                        f"{e['message'][:170]}")
        data = {"service": service, "minutes": minutes, "total_lines": len(raw),
                "sanitiser_removed": len(dropped), "entries": entries, "truncated": truncated}
        return _ok("\n".join([head, *body]), data, source)
    except Exception as e:  # tools never raise
        return _err(f"{type(e).__name__}: {e}", source)


# --------------------------------------------------------- human inspection
def _show_live(service: str, minutes: int) -> None:
    """Print what the sanitiser drops/changes on real logs, then what the agent sees."""
    raw = DockerSource().logs(service, minutes)
    kept, dropped = drop_flag_lines(raw)
    print(f"raw={len(raw)} kept={len(kept)} dropped={len(dropped)}\n")
    print("--- DROPPED (should be flag-related lines only) ---")
    for line in dropped:
        print("  " + line[:200])
    print("\n--- SCRUBBED (before -> after) ---")
    for line in kept:
        after = scrub_secrets(line)
        if after != line:
            print("  " + line[:140] + "\n  -> " + after[:140])
    print("\n--- WHAT THE AGENT SEES ---")
    r = get_logs(service, minutes)
    print(r["summary"])


# -------------------------------------------------------------------- tests
def selftest() -> None:
    lines = [
        '2026-10-23T11:50:01.100000000Z {"level":"error","msg":"Payment request failed. Invalid token. demo.user_context.loyalty_level=gold"}',
        '2026-10-23T11:50:02.200000000Z {"level":"error","msg":"Payment request failed. Invalid token. demo.user_context.loyalty_level=gold"}',
        '2026-10-23T11:50:03.300000000Z {"level":"error","msg":"Payment request failed. Invalid token. demo.user_context.loyalty_level=gold"}',
        "2026-10-23T11:50:05Z ERROR Charge failed for user 3f2a9c1e-1b2d-4c3e-8f90-a1b2c3d4e5f6 "
        "card 4111 1111 1111 1111 token=abc123secret",
        "2026-10-23T11:50:06Z WARN retrying upstream call attempt 2",
        "2026-10-23T11:50:07Z INFO served request in 12ms",
        "2026-10-23T11:50:08Z INFO Feature Flag paymentFailure enabled, failing 50% of charges",
        '2026-10-23T11:50:09Z {"level":"info","msg":"openfeature provider ready"}',
        "2026-10-23T11:50:10Z INFO paymentFailure=0.5",
    ]
    fx = FixtureSource(logs={"payment": lines, "cart": ["2026-10-23T11:50:00Z INFO ok"],
                             "flagd": ["x"]})

    r = get_logs("payment", backend=fx)
    assert r["ok"] and len(r["summary"]) <= 1500 and r["source"], r
    d = r["data"]
    assert d["total_lines"] == 9 and d["sanitiser_removed"] == 3, d
    ents = d["entries"]
    assert [e["level"] for e in ents] == ["error", "error", "warn"], ents  # info hidden by default
    assert ents[0]["count"] == 3 and "Invalid token" in ents[0]["message"]  # deduped + JSON parsed
    assert ents[0]["first_ts"].startswith("2026-10-23T11:50:01")
    assert ents[0]["last_ts"].startswith("2026-10-23T11:50:03")
    blob = json.dumps(r)
    for leak in ("4111", "abc123secret", "paymentFailure", "Feature Flag", "openfeature"):
        assert leak not in blob, leak
    assert "3f2a9c1e-1b2d-4c3e-8f90-a1b2c3d4e5f6" in ents[1]["message"]  # ids survive

    # level / grep / max_lines
    assert len(get_logs("payment", level="info", backend=fx)["data"]["entries"]) == 4
    g = get_logs("payment", grep="retry", backend=fx)["data"]["entries"]
    assert len(g) == 1 and g[0]["level"] == "warn"
    assert len(get_logs("payment", max_lines=1, backend=fx)["data"]["entries"]) == 1
    assert get_logs("payment", max_lines=1, backend=fx)["data"]["truncated"] is True
    assert get_logs("payment", grep="paymentFailure", backend=fx)["data"]["entries"] == []  # can't grep leaks

    # nothing error/warn -> falls back to showing info lines, and says so
    c = get_logs("cart", backend=fx)
    assert c["ok"] and len(c["data"]["entries"]) == 1 and "showing all" in c["summary"]

    # denylist, bad input, unknown service: ok=False, never raises
    for svc in ("flagd", "flagd-ui", "FlagD"):
        bad = get_logs(svc, backend=fx)
        assert bad["ok"] is False and "denied" in bad["summary"], bad
    assert get_logs("pay ment; rm -rf /", backend=fx)["ok"] is False
    assert get_logs("nope", backend=fx)["ok"] is False
    assert get_logs("payment", backend=None.__class__)["ok"] is False

    # parse_line: level detection for plain, JSON and numeric (pino) logs
    assert parse_line("2026-10-23T11:00:00Z GET /api 500 120ms")["level"] == "info"
    assert parse_line("2026-10-23T11:00:00Z dial tcp: connection refused")["level"] == "error"
    assert parse_line('{"level":50,"msg":"boom"}')["level"] == "error"
    assert parse_line('{"level":30,"msg":"hi"}')["level"] == "info"


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--live":
        _show_live(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 10)
    else:
        selftest()
        print("ALL TESTS PASSED")
