"""Tools the agent can call. Read tools return sanitised, summarised JSON.

The ONLY state-changing tool is restart_service, and it goes through the
Action API (the one allowed way to change the system). Every call is logged.
"""
import json
import os
import re
import subprocess
import time
import urllib.request

import telemetry
from sanitize import sanitise, summarise

DEMO_DIR = os.getenv("DEMO_DIR", ".")          # folder with the demo's docker-compose.yml
LOGS_FILE = os.getenv("LOGS_FILE")             # offline mode: read logs from a file
ACTION_API_URL = os.getenv("ACTION_API_URL", "http://localhost:9000")
DRY_RUN = os.getenv("DRY_RUN", "1") == "1"     # set DRY_RUN=0 (or --act) to really act
MAX_OUT = 6000


def _raw_lines(since_minutes: int):
    if LOGS_FILE:
        with open(LOGS_FILE, encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    p = subprocess.run(
        ["docker", "compose", "logs", "--no-color", "--since", f"{since_minutes}m"],
        capture_output=True, text=True, cwd=DEMO_DIR, timeout=60,
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip()[:500] or "docker compose logs failed")
    return p.stdout.splitlines()


def _clip(s: str) -> str:
    return s if len(s) <= MAX_OUT else s[:MAX_OUT] + "\n...[truncated]"


def error_summary(since_minutes: int = 5, service: str | None = None) -> str:
    try:
        recs = sanitise(_raw_lines(since_minutes))
    except Exception as e:
        return f"ERROR reading logs: {e}"
    summary = summarise(recs)
    if service:
        summary = {k: v for k, v in summary.items() if k == service}
    return _clip(json.dumps(summary, indent=1))


def search_logs(pattern: str, service: str | None = None, limit: int = 20,
                since_minutes: int = 5) -> str:
    try:
        recs = sanitise(_raw_lines(since_minutes))
        rx = re.compile(pattern, re.I)
    except Exception as e:
        return f"ERROR: {e}"
    hits = [f"{r['svc']}: {r['msg'][:250]}" for r in recs
            if rx.search(r["msg"]) and (not service or r["svc"] == service)]
    return _clip("\n".join(hits[-limit:]) or "no matches")


def query_metrics(window_minutes: int = 2, baseline_offset_minutes: int = 15) -> str:
    try:
        return _clip(telemetry.query_metrics(window_minutes, baseline_offset_minutes))
    except Exception as e:
        return f"ERROR querying Prometheus: {e}"


def query_traces(service: str | None = None, minutes: int = 5, limit: int = 30) -> str:
    try:
        return _clip(telemetry.query_traces(service, minutes, limit))
    except Exception as e:
        return f"ERROR querying Jaeger: {e}"


def container_status() -> str:
    """Container state plus live CPU/memory (catches stopped, restarting, starved)."""
    try:
        ps = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}"],
            capture_output=True, text=True, timeout=30).stdout
        stats = subprocess.run(
            ["docker", "stats", "--no-stream", "--format",
             "{{.Name}}\tcpu={{.CPUPerc}}\tmem={{.MemUsage}} ({{.MemPerc}})"],
            capture_output=True, text=True, timeout=60).stdout
    except Exception as e:
        return f"ERROR: {e}"
    return _clip(f"STATUS\n{ps}\nUSAGE\n{stats}")


def _audit(entry: dict):
    entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    with open("actions.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")


def restart_service(service: str, reason: str) -> str:
    if not re.fullmatch(r"[a-z0-9-]+", service):
        return "ERROR: invalid service name"
    _audit({"action": "restart", "service": service, "reason": reason, "dry_run": DRY_RUN})
    if DRY_RUN:
        return f"DRY RUN: would restart {service}"
    # TODO: replace with the real Action API request shape from the organisers' docs.
    req = urllib.request.Request(
        f"{ACTION_API_URL}/restart",
        data=json.dumps({"service": service}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return f"restart sent: HTTP {r.status}"
    except Exception as e:
        return f"ERROR calling Action API: {e}"


TOOLS = [
    {"name": "error_summary",
     "description": "Per-service error counts, error rate and top repeated error templates "
                    "from recent logs (sanitised). Start here; call again later to verify a fix.",
     "input_schema": {"type": "object", "properties": {
         "since_minutes": {"type": "integer", "default": 5},
         "service": {"type": "string", "description": "optional: only this service"}}}},
    {"name": "search_logs",
     "description": "Regex search over sanitised recent log lines to inspect specific errors.",
     "input_schema": {"type": "object", "properties": {
         "pattern": {"type": "string"}, "service": {"type": "string"},
         "limit": {"type": "integer", "default": 20},
         "since_minutes": {"type": "integer", "default": 5}}, "required": ["pattern"]}},
    {"name": "query_metrics",
     "description": "From Prometheus: per-service request rate, error ratio and p95 latency now "
                    "vs an earlier baseline, with flags for error spikes, latency jumps and "
                    "services that stopped reporting. Best first look for latency/outage faults.",
     "input_schema": {"type": "object", "properties": {
         "window_minutes": {"type": "integer", "default": 2},
         "baseline_offset_minutes": {"type": "integer", "default": 15}}}},
    {"name": "query_traces",
     "description": "From Jaeger: recent error traces. Returns the deepest failing spans (likely "
                    "root cause) and which service-to-service calls fail. Use to tell the cause "
                    "from the victims.",
     "input_schema": {"type": "object", "properties": {
         "service": {"type": "string", "description": "optional: only traces touching this service"},
         "minutes": {"type": "integer", "default": 5},
         "limit": {"type": "integer", "default": 30}}}},
    {"name": "container_status",
     "description": "Container up/restarting/exited state and live CPU/memory per container.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "restart_service",
     "description": "Restart one service via the Action API. Only do this once evidence "
                    "supports that a restart addresses the root cause.",
     "input_schema": {"type": "object", "properties": {
         "service": {"type": "string"}, "reason": {"type": "string"}},
         "required": ["service", "reason"]}},
]

DISPATCH = {"error_summary": error_summary, "search_logs": search_logs,
            "query_metrics": query_metrics, "query_traces": query_traces,
            "container_status": container_status, "restart_service": restart_service}
