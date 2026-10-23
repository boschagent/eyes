# Incident agent (starter)

Reads sanitised logs from the OpenTelemetry Demo, reasons about root cause,
acts through the Action API, and re-checks.

## Layout
- `sanitize.py`: parse compose logs, drop flag-leaking lines, redact PII/secrets, group repeated errors into templates
- `telemetry.py`: read layer over the demo's Prometheus (metrics) and Jaeger (traces); finds anomalies vs baseline and the deepest failing span
- `tools.py`: tools the LLM can call (`query_metrics`, `query_traces`, `error_summary`, `search_logs`, `container_status`, `restart_service`)
- `tests/test_telemetry.py`: offline test against fake Prometheus/Jaeger servers
- `agent.py`: the tool-use loop + CLI
- `sample_logs/`: offline test input

## Run
```bash
pip install anthropic
# 1) No LLM, just see what the agent will see (offline):
python agent.py --logs-file sample_logs/payment_fail.log --summary-only
# 1b) Offline test of the Prometheus/Jaeger layer (fake servers):
python tests/test_telemetry.py
# 2a) With the demo running, check the agent can reach Prometheus and Jaeger:
python agent.py --check
#     (auto-tries localhost:9090 and localhost:8080/prometheus for Prometheus,
#      localhost:8080/jaeger/ui and localhost:16686 for Jaeger; override with
#      PROMETHEUS_URL / JAEGER_URL)
python telemetry.py --metrics ; python telemetry.py --traces
# 2) Live, from the demo folder (docker compose must be running):
DEMO_DIR=/path/to/opentelemetry-demo python agent.py --summary-only
# 3) Full agent, actions are DRY RUN (logged to actions.jsonl, nothing changes):
export ANTHROPIC_API_KEY=...   # or the key organisers give you
DEMO_DIR=/path/to/opentelemetry-demo python agent.py
# 4) Let it really act:
python agent.py --act
```

## TODO before the evaluation
1. Replace the request in `restart_service` with the real Action API shape; add toggle_flag, throttle_loadgen, scale tools.
2. Replace the JSON output in `agent.py` SYSTEM prompt with the official schema from the template repo.
3. Extend sanitiser LEAK patterns if you spot other lines that reveal flag settings.
4. Verify against the real demo: Prometheus address and span-metric names vary by version (`python agent.py --check` shows what it found). CPU/memory starvation is only visible via `container_status` for now.
5. Add a human-approval step for risky actions (ask admin, then act with feedback).
6. Build faultctl to inject practice incidents and score the agent.
