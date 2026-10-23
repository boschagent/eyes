"""Read layer over the OTel Demo's Prometheus (metrics) and Jaeger (traces).

The demo already generates and stores telemetry; this module only asks the
backends questions and returns compact, sanitised text the LLM can reason over.
Anything that would reveal feature-flag settings is filtered out.

Override addresses with PROMETHEUS_URL / JAEGER_URL. Otherwise the first
reachable candidate is used (see `check()`).
"""
import json
import os
import time
import urllib.parse
import urllib.request
from collections import Counter

from sanitize import LEAK, redact, template

TIMEOUT = 15
PROM_CANDIDATES = [u for u in [os.getenv("PROMETHEUS_URL"),
                               "http://localhost:9090",
                               "http://localhost:8080/prometheus"] if u]
# Jaeger's API lives under the same base path as its UI.
JAEGER_CANDIDATES = [u for u in [os.getenv("JAEGER_URL"),
                                 "http://localhost:8080/jaeger/ui",
                                 "http://localhost:16686"] if u]

# Span-metrics series names differ between demo versions; the first one that exists wins.
CALLS = ("traces_span_metrics_calls_total", "traces_spanmetrics_calls_total", "calls_total")
BUCKET = ("traces_span_metrics_duration_milliseconds_bucket",
          "traces_spanmetrics_latency_bucket", "duration_milliseconds_bucket")
IGNORED_SERVICES = {"flagd", "flagd-ui", "jaeger", "jaeger-all-in-one", "otel-collector"}

_bases = {}


def _fetch(base, path, params=None):
    url = base.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=TIMEOUT) as r:
        return json.load(r)


def _base(kind):
    """Pick (and cache) the first reachable backend address."""
    if kind in _bases:
        return _bases[kind]
    cands, probe = ((PROM_CANDIDATES, "/api/v1/label/__name__/values") if kind == "prom"
                    else (JAEGER_CANDIDATES, "/api/services"))
    errors = []
    for c in cands:
        try:
            _fetch(c, probe)
            _bases[kind] = c
            return c
        except Exception as e:  # try the next candidate
            errors.append(f"{c}: {e}")
    raise RuntimeError(f"{'Prometheus' if kind == 'prom' else 'Jaeger'} not reachable. Tried "
                       + "; ".join(errors) + ". Set PROMETHEUS_URL / JAEGER_URL.")


def _pick(*candidates):
    names = set(_fetch(_base("prom"), "/api/v1/label/__name__/values")["data"])
    return next((c for c in candidates if c in names), None)


def _vec(q):
    """Run an instant query, return {service_name: float}."""
    res = _fetch(_base("prom"), "/api/v1/query", {"query": q})["data"]["result"]
    out = {}
    for s in res:
        try:
            v = float(s["value"][1])
        except (KeyError, ValueError, IndexError):
            continue
        if v == v:  # drop NaN
            out[s["metric"].get("service_name", "?")] = v
    return out


# --------------------------------------------------------------------- metrics
def query_metrics(window_minutes: int = 2, baseline_offset_minutes: int = 15) -> str:
    """Per-service request rate, error ratio and p95 latency now vs. an earlier baseline."""
    calls, bucket = _pick(*CALLS), _pick(*BUCKET)
    if not calls:
        return json.dumps({"error": "no span-metrics series in Prometheus yet "
                                    "(is the demo up long enough?)"})
    w = f"{int(window_minutes)}m"
    off = f" offset {int(baseline_offset_minutes)}m"

    def snapshot(o):
        total = _vec(f"sum by (service_name) (rate({calls}[{w}]{o}))")
        errs = _vec(f'sum by (service_name) (rate({calls}{{status_code="STATUS_CODE_ERROR"}}[{w}]{o}))')
        p95 = (_vec(f"histogram_quantile(0.95, sum by (le, service_name) (rate({bucket}[{w}]{o})))")
               if bucket else {})
        return {s: {"rps": round(t, 2),
                    "error_ratio": round(errs.get(s, 0.0) / t, 3) if t > 0 else 0.0,
                    "p95_ms": round(p95[s]) if s in p95 else None}
                for s, t in total.items() if s not in IGNORED_SERVICES}

    now, base = snapshot(""), snapshot(off)
    rows = []
    for s, cur in now.items():
        b = base.get(s)
        flags = []
        if b is not None:
            if cur["error_ratio"] - b["error_ratio"] >= 0.05:
                flags.append("error ratio up vs baseline")
            if cur["p95_ms"] and b["p95_ms"] and cur["p95_ms"] > 2 * b["p95_ms"] and cur["p95_ms"] > 200:
                flags.append("p95 latency more than doubled")
            if b["rps"] > 0.5 and cur["rps"] < 0.2 * b["rps"]:
                flags.append("traffic collapsed (service down?)")
        elif cur["error_ratio"] >= 0.05:
            flags.append("error ratio high (no baseline yet)")
        rows.append({"service": s, "now": cur, "baseline": b, "flags": flags})
    # services with the most alarming signals first
    rows.sort(key=lambda r: (len(r["flags"]), r["now"]["error_ratio"]), reverse=True)
    # a service present in the baseline but absent now has stopped reporting
    gone = [s for s in base if s not in now and base[s]["rps"] > 0.5]
    return json.dumps({"window": w, "baseline_offset": off.strip(),
                       "services": rows, "stopped_reporting": gone}, indent=1)


# ---------------------------------------------------------------------- traces
def _tag(span, key):
    for t in span.get("tags", []):
        if t.get("key") == key:
            return t.get("value")
    return None


def _status_message(span):
    msg = _tag(span, "otel.status_description")
    if not msg:
        for log in span.get("logs", []):
            for f in log.get("fields", []):
                if f.get("key") in ("exception.message", "message", "event") and f.get("value"):
                    msg = f["value"]
                    break
            if msg:
                break
    return str(msg or "")


def _leaky(service, span):
    return (service in IGNORED_SERVICES or bool(LEAK.search(span.get("operationName", "")))
            or bool(LEAK.search(_status_message(span))))


def _is_error(span):
    return _tag(span, "error") in (True, "true") or _tag(span, "otel.status_code") == "ERROR"


def query_traces(service: str | None = None, minutes: int = 5, limit: int = 30) -> str:
    """Recent error traces: which spans fail first (the likely cause) and which calls fail."""
    base = _base("jaeger")
    end = int(time.time() * 1e6)
    start = end - int(minutes) * 60 * 1_000_000
    services = [service] if service else [
        s for s in _fetch(base, "/api/services")["data"] if s not in IGNORED_SERVICES]
    traces = {}
    for s in services:
        data = _fetch(base, "/api/traces", {
            "service": s, "start": start, "end": end, "limit": limit,
            "tags": json.dumps({"error": "true"})}).get("data") or []
        for t in data:
            traces[t["traceID"]] = t

    origins, edges = Counter(), Counter()
    for t in traces.values():
        procs = {pid: p["serviceName"] for pid, p in t["processes"].items()}
        spans = {s["spanID"]: s for s in t["spans"]}
        svc = {sid: procs.get(s["processID"], "?") for sid, s in spans.items()}
        err = {sid for sid, s in spans.items() if _is_error(s) and not _leaky(svc[sid], s)}
        parent = {}
        for sid, s in spans.items():
            for ref in s.get("references", []):
                if ref.get("refType") == "CHILD_OF" and ref["spanID"] in spans:
                    parent[sid] = ref["spanID"]
        has_err_child = {parent[c] for c in err if c in parent}
        for sid in err:
            if sid not in has_err_child:  # deepest failing span = likely origin
                msg = template(redact(_status_message(spans[sid]))) or "(no message)"
                origins[(svc[sid], spans[sid]["operationName"], msg)] += 1
            p = parent.get(sid)
            if p and svc[p] != svc[sid]:
                edges[(svc[p], svc[sid])] += 1

    return json.dumps({
        "window_minutes": minutes, "error_traces": len(traces),
        "origin_errors": [{"count": n, "service": a, "operation": b, "message": c}
                          for (a, b, c), n in origins.most_common(10)],
        "failing_calls": [{"count": n, "from": a, "to": b}
                          for (a, b), n in edges.most_common(10)],
    }, indent=1)


# ----------------------------------------------------------------------- check
def check() -> str:
    lines = []
    for kind, label in (("prom", "Prometheus"), ("jaeger", "Jaeger")):
        try:
            b = _base(kind)
            if kind == "prom":
                lines.append(f"{label} OK at {b}: calls={_pick(*CALLS)} buckets={_pick(*BUCKET)}")
            else:
                svcs = _fetch(b, "/api/services")["data"]
                lines.append(f"{label} OK at {b}: {len(svcs)} services ({', '.join(sorted(svcs))[:160]})")
        except Exception as e:
            lines.append(f"{label} FAILED: {e}")
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "--check"
    print({"--check": check, "--metrics": query_metrics, "--traces": query_traces}[cmd]())
