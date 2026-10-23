"""Incident agent: read sanitised telemetry -> hypothesise -> verify -> act -> re-check.

Usage:
  python agent.py --summary-only                 # no LLM: just print the sanitised error summary
  python agent.py --logs-file sample_logs/payment_fail.log --summary-only
  python agent.py                                # diagnose; actions are DRY RUN by default
  python agent.py --act                          # actually call the Action API
Needs: pip install anthropic ; export ANTHROPIC_API_KEY=...
"""
import argparse
import json
import os

import tools

MODEL = os.getenv("MODEL", "claude-sonnet-5-5")

SYSTEM = """You are an SRE agent diagnosing incidents in a microservices shop
(frontend, cart, checkout, payment, product-catalog, recommendation, ad, shipping, ...).

Rules:
- Reason ONLY from telemetry (logs, container status). Never try to read feature-flag
  settings or flag names; the incident cause must be inferred from symptoms.
- Work like this: (1) query_metrics for error/latency/outage anomalies vs baseline and
  error_summary for log errors, (2) query_traces to find the deepest failing span: the
  loudest service is often a victim, not the cause, (3) form a hypothesis and confirm or
  rule it out with search_logs / container_status (CPU/memory, restarts), (4) only then
  act, using the least disruptive action, (5) re-run query_metrics and error_summary to
  verify the fix worked.
- Several faults can happen at once. Do not stop at the first one you find.
- If a restart cannot fix the cause (e.g. a bad flag you cannot see), say so honestly
  in the output rather than restarting repeatedly.

Finish with ONLY a JSON object (replace with the official schema from the template repo):
{"root_cause": str, "affected_services": [str], "evidence": [str],
 "actions_taken": [str], "verified": bool, "confidence": 0-1}"""


def run(task: str, max_turns: int = 14) -> str:
    import anthropic
    client = anthropic.Anthropic()
    messages = [{"role": "user", "content": task}]
    for _ in range(max_turns):
        resp = client.messages.create(model=MODEL, max_tokens=2000, system=SYSTEM,
                                      tools=tools.TOOLS, messages=messages)
        messages.append({"role": "assistant", "content": resp.content})
        if resp.stop_reason != "tool_use":
            return "".join(b.text for b in resp.content if b.type == "text")
        results = []
        for b in resp.content:
            if b.type == "tool_use":
                print(f"  -> {b.name}({json.dumps(b.input)})")
                out = tools.DISPATCH[b.name](**b.input)
                results.append({"type": "tool_result", "tool_use_id": b.id, "content": out})
        messages.append({"role": "user", "content": results})
    return json.dumps({"root_cause": "unresolved: turn limit reached", "verified": False})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs-file", help="offline mode: read logs from this file")
    ap.add_argument("--summary-only", action="store_true", help="print sanitised summary, no LLM")
    ap.add_argument("--act", action="store_true", help="really call the Action API")
    ap.add_argument("--minutes", type=int, default=5)
    ap.add_argument("--check", action="store_true",
                    help="test connection to Prometheus and Jaeger, then exit")
    args = ap.parse_args()

    if args.check:
        import telemetry
        print(telemetry.check())
        raise SystemExit(0)

    if args.logs_file:
        tools.LOGS_FILE = args.logs_file
    if args.act:
        tools.DRY_RUN = False

    if args.summary_only:
        print(tools.error_summary(args.minutes))
    else:
        print(run("An incident may be in progress. Investigate, fix what you can, "
                  "verify, and report."))
