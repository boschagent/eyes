# P3: Logs, Infra, Sanitiser

Drop the `agent/` folder into the team repo (merge with P1's `agent/`; P3 owns only `agent/tools/{logs,docker_tools,sanitize}.py`).

| File              | Tool(s)                                                              | What it does                                                                                                                                                         |
| ----------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sanitize.py`     | `redact(obj)`, `drop_flag_lines(lines)`, `scrub_secrets(text)`       | Removes feature-flag leaks (tags/events/keys named `feature_flag*`/`flagd`/`openfeature`, log lines mentioning them, known flag names) and masks tokens/emails/cards |
| `logs.py`         | `get_logs(service, minutes=10, grep=None, level=None, max_lines=60)` | `docker logs --since --timestamps` -> sanitise -> parse JSON/plain -> dedupe with counts -> errors/warns first. flagd/flagd-ui refused                               |
| `docker_tools.py` | `container_health(recent_minutes=10)`, `deploy_history(minutes=120)` | State/health/restarts/OOM/exit code per container; created/started/stopped timeline merged with `logs/actions.jsonl`                                                 |

All tools return `{"ok", "summary" (<=1500 chars), "data", "source"}` and never raise. Each tool takes an optional `backend=` (see Assumptions).

## Test (no docker, no network)

```bash
python -m agent.tools.sanitize      # each prints ALL TESTS PASSED
python -m agent.tools.docker_tools
python -m agent.tools.logs
```

(P1: wire these three into `python -m agent.selftest`.)

## See and assess the sanitiser on REAL logs (demo running)

```bash
python -m agent.tools.logs --live payment 10     # any service name, last 10 min
```

Prints: lines DROPPED, lines SCRUBBED (before -> after), and what the agent sees. Check:

1. **No leaks:** DROPPED should be flag-related lines only; the agent view must contain no `flagd` / flag names.
2. **No signal lost:** if a genuine error line shows up under DROPPED, a pattern in `sanitize.py` is too broad. Fix it and add the line to `selftest()`.
3. **No PII/secrets:** SCRUBBED shows masks; nothing sensitive should remain in the agent view.
4. Repeat for every service, especially `ad` (logs "Feature Flag ... enabled"), `checkout`, `product-catalog`, `payment`.

## Capture real fixtures (do this once on the live laptop)

The selftests use small invented samples. Save real output so tests run on real data:

```bash
mkdir -p eval/fixtures
for s in payment ad cart checkout product-catalog; do docker logs --since 10m --timestamps $s > eval/fixtures/logs_$s.txt 2>&1; done
docker ps -a --format '{{json .}}' > eval/fixtures/docker_ps.jsonl
docker inspect $(docker ps -aq) > eval/fixtures/docker_inspect.json
```

Then add asserts against them in `selftest()` (e.g. real `ad` log has its flag line dropped).

## Verified against the OTel demo docs/source (what the sanitiser is built on)

- **Span event `feature_flag`** (attrs `feature_flag.key`, `.provider_name`, `.variant`) and the newer **`feature_flag.evaluation`** event (attrs `feature_flag.key`, `.result.value`, `.result.variant`, `.provider.name`, `.context.id`, ...): any key/tag/event named `feature_flag*` is removed.
- **Ad service log:** `Feature Flag adManualGc enabled, performing a manual gc now` (`logger.warn` in `AdService.java`).
- **Checkout** registers `otelhooks.NewTracesHook()` (adds `feature_flag` span events) and logs `Error creating flagd provider` / `Failed to set flagd as the provider` if flagd is down.
- **Envoy front proxy** routes `/flagservice/` -> flagd and `/feature` -> flagd-ui, and its access logs record `url.path`. Toggling or reading flags would therefore leave `/feature` and `/flagservice/...` entries in logs and spans, so those are now dropped too.
- **Flag names differ between sources** (plan list vs docs page vs `demo.flagd.json` on main): newer ones include `aiRunawayAgent`, `aiSlowResponse`, `emitRawPii`, `loadGeneratorTraffic`, `loadGeneratorVUs`. `FLAG_NAMES` is the union. The organisers' pinned version may differ again.
- **Real failure symptoms are NOT in the logs.** Payment's `charge.js` logs only `Transaction complete.` on success; on `paymentFailure` it throws `Payment request failed. Invalid token. demo.user_context.loyalty_level=gold` and records it on the span (no log line). Checkout also writes no log line when the charge fails (`failed to charge card: ...` is a gRPC error + span). **Diagnosis for these needs traces/metrics (P2), not `docker logs`.**
- **Many services log via OTLP, not stdout** (checkout uses `otelslog` -> OTLP exporter; envoy's access log goes to the collector). The fuller log store is **OpenSearch** (`otel-logs-*`). `docker logs` may miss lines; see "Next" below.

## Next (not built yet)

- An **OpenSearch-backed log source** with the same tool interface, if `--live` shows `docker logs` is too thin. Needs the OpenSearch port: `docker compose port opensearch 9200`.
- `emitRawPii` suggests the demo can emit raw PII; `scrub_secrets` masks cards/emails/tokens only (not names or addresses). Look at real output with the flag on before relying on it.

## Assumptions (marked `# ASSUMPTION:` in the code)

- **Backend interface:** tools call `backend.ps()`, `.inspect(ids)`, `.logs(service, minutes)` (+ `*_cmd()` for the source string). P1/P5's live/offline backends must expose these, or we write a thin adapter once the bundle format is known. `FixtureSource` in `docker_tools.py` shows the shape.
- **Flag names:** the list can't be exhaustive (see above). It is deliberately an explicit list, not a camelCase pattern, so real errors like `onFailure` aren't dropped. Extend it if you see others.
- **Actions log:** `deploy_history` expects P4's `logs/actions.jsonl` lines to have `timestamp`/`ts`, `action`, `params`, `dry_run`. Unknown lines are skipped.
- **Mentor Q2:** the plan strips flag spans/lines; confirm this is what organisers expect.
- Tested only against fixtures and a stub `docker` CLI, **not** a live demo yet.
