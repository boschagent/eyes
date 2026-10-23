"""Flag-leak sanitiser (P3).

The agent must reason from telemetry and must NEVER see feature-flag settings.
This module strips anything that reveals them from tool output:

  redact(obj) -> (clean_obj, n_removed)
      Recursively removes keys / tags / span events whose NAME mentions
      feature_flag, flagd or openfeature, and any log line that mentions them
      (or names one of the known demo flags).
  drop_flag_lines(lines) -> (kept, dropped)
      Same line rule for a plain list of log lines.
  scrub_secrets(text) -> text
      Light PII/secret masking (tokens, emails, card numbers) for log text.

Run the tests:  python -m agent.tools.sanitize   (or: python sanitize.py)
"""
from __future__ import annotations

import re
from typing import Any

# Names of keys / tags / events that carry flag info (e.g. "feature_flag.key").
#
# Verified against the OTel demo docs/source (see README_P3.md, "Verified"):
#   span event "feature_flag"            attrs feature_flag.key / .provider_name / .variant
#   log/event  "feature_flag.evaluation" attrs feature_flag.key / .result.value / .result.variant ...
#   ad service logs "Feature Flag adManualGc enabled, performing a manual gc now"
#   checkout logs "Error creating flagd provider" / "Failed to set flagd as the provider"
#   frontend-proxy (envoy) routes /flagservice/ -> flagd and /feature -> flagd-ui, and its
#   access logs record url.path, so flag traffic would show up in logs/spans.
KEY_RX = re.compile(r"(?i)feature[_\s.-]?flag|flagd|openfeature|flagservice")
# Log lines that mention flags: the plan's rule (section 10 / P3) plus the envoy flag routes.
LINE_RX = re.compile(r"(?i)feature.?flag|flagd|openfeature|flagservice|/feature(?![\w-])")

# Flag names = UNION of three sources that disagree with each other (the plan's list, the
# demo docs page, and src/flagd/demo.flagd.json on main), so the organisers' pinned
# version may have a different set. A line that names one is a leak even if it never says
# "flag". If you see another flag name in real telemetry, add it here and to selftest().
# (Deliberately NOT a camelCase pattern: that would drop real error lines like "onFailure".)
FLAG_NAMES = (
    "adFailure", "adHighCpu", "adManualGc", "aiRunawayAgent", "aiSlowResponse",
    "cartFailure", "emailMemoryLeak", "emitRawPii", "failedReadinessProbe",
    "imageSlowLoad", "intlShippingSlowdown", "kafkaConsumerDead", "kafkaQueueProblems",
    "loadGeneratorFloodHomepage", "loadGeneratorTraffic", "loadGeneratorVUs",
    "paymentFailure", "paymentUnreachable", "productCatalogFailure",
    "productCatalogLockContention", "recommendationCacheFailure",
)
# Case-sensitive on purpose: "payment failure" in plain words is a real symptom.
NAME_RX = re.compile(r"\b(?:" + "|".join(FLAG_NAMES) + r")\b")

_DROP = object()  # sentinel: "this node was removed"


def is_flag_line(line: str) -> bool:
    return bool(LINE_RX.search(line) or NAME_RX.search(line))


def drop_flag_lines(lines: list[str]) -> tuple[list[str], list[str]]:
    """Split log lines into (kept, dropped)."""
    kept: list[str] = []
    dropped: list[str] = []
    for line in lines:
        (dropped if is_flag_line(line) else kept).append(line)
    return kept, dropped


def _flag_node(d: dict) -> bool:
    """True if this dict IS a flag tag / span event / Jaeger log entry."""
    for k in ("key", "name", "event"):  # OTel event / Jaeger tag name
        v = d.get(k)
        if isinstance(v, str) and KEY_RX.search(v):
            return True
    # Jaeger tag shaped {"key": "...", "value": "..."}: drop the whole tag when its VALUE
    # leaks (e.g. value "feature_flag", or http.target "/flagservice/...")
    if "key" in d and isinstance(d.get("value"), str) and is_flag_line(d["value"]):
        return True
    # Jaeger span log entry shaped {"fields": [{"key": ..., "value": ...}, ...]}
    fields = d.get("fields")
    if isinstance(fields, list):
        for f in fields:
            if isinstance(f, dict):
                if KEY_RX.search(str(f.get("key", ""))):
                    return True
                v = f.get("value")
                if isinstance(v, str) and KEY_RX.search(v):
                    return True
    return False


def redact(obj: Any) -> tuple[Any, int]:
    """Return (clean copy of obj, number of items removed). Never mutates obj."""
    n = 0

    def walk(x: Any) -> Any:
        nonlocal n
        if isinstance(x, str):
            if "\n" in x:  # a blob of log text: filter line by line
                lines = x.split("\n")
                kept = [ln for ln in lines if not is_flag_line(ln)]
                n += len(lines) - len(kept)
                return "\n".join(kept)
            if is_flag_line(x):
                n += 1
                return _DROP
            return x
        if isinstance(x, dict):
            if _flag_node(x):
                n += 1
                return _DROP
            out = {}
            for k, v in x.items():
                if KEY_RX.search(str(k)):
                    n += 1
                    continue
                c = walk(v)
                if c is not _DROP:
                    out[k] = c
            return out
        if isinstance(x, (list, tuple)):
            return [c for c in (walk(i) for i in x) if c is not _DROP]
        return x

    res = walk(obj)
    return ("" if res is _DROP else res), n


# ----------------------------------------------------------- secrets / PII
_SECRET_RX = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|passwd|authorization|bearer)\b"
    r"(\"?\s*[:=]\s*\"?)[^\s\",;}]+"
)
_EMAIL_RX = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
# 4-4-4-4 groups or 13-19 bare digits; lookarounds stop it eating UUIDs/ids.
_CARD_RX = re.compile(
    r"(?<![\w-])(?:\d{4}[ -]){3}\d{1,4}(?![\w-])|(?<![\w-])\d{13,19}(?![\w-])")


def scrub_secrets(text: str) -> str:
    text = _SECRET_RX.sub(r"\1\2<redacted>", text)
    text = _EMAIL_RX.sub("<email>", text)
    return _CARD_RX.sub("<card>", text)


# ------------------------------------------------------------------- tests
def selftest() -> None:
    # 1. Jaeger-like span: flag tags + flag span events removed, rest survives.
    span = {
        "traceID": "t1",
        "spans": [{
            "spanID": "a", "operationName": "PlaceOrder",
            "tags": [
                {"key": "http.status_code", "value": 500},
                {"key": "feature_flag.key", "value": "paymentFailure"},
                {"key": "feature_flag.provider_name", "value": "flagd"},
                {"key": "error", "value": True},
            ],
            "logs": [
                {"timestamp": 1, "fields": [{"key": "event", "value": "feature_flag"},
                                            {"key": "feature_flag.key", "value": "x"}]},
                {"timestamp": 2, "fields": [{"key": "event", "value": "exception"},
                                            {"key": "exception.message", "value": "boom"}]},
            ],
        }],
    }
    clean, n = redact(span)
    tags = [t["key"] for t in clean["spans"][0]["tags"]]
    assert tags == ["http.status_code", "error"], tags
    logs = clean["spans"][0]["logs"]
    assert len(logs) == 1 and logs[0]["fields"][1]["value"] == "boom", logs
    assert n == 3, n
    assert "feature_flag" not in str(clean) and "flagd" not in str(clean)
    assert len(span["spans"][0]["tags"]) == 4, "input must not be mutated"

    # 2. OTel-style attribute dict: flag keys dropped, others kept.
    clean, n = redact({"attributes": {"feature_flag.key": "k", "feature_flag.variant": "on",
                                      "demo.user_context.loyalty_level": "gold"}})
    assert clean == {"attributes": {"demo.user_context.loyalty_level": "gold"}}, clean
    assert n == 2

    # 3. Log lines: leaks dropped, real symptoms survive.
    lines = [
        "Feature Flag adManualGc enabled, performing a manual gc now",
        "flagd: evaluating flag",
        "openfeature provider ready",
        "paymentFailure=0.5",
        "Payment request failed. Invalid token. demo.user_context.loyalty_level=gold",
        "payment failure while charging",          # plain words must survive
        "country flag icon loaded",                # the word "flag" alone must survive
    ]
    kept, dropped = drop_flag_lines(lines)
    assert dropped == lines[:4], dropped
    assert kept == lines[4:], kept
    clean, n = redact(lines)
    assert clean == lines[4:] and n == 4, (clean, n)

    # 4. Multi-line blob.
    blob = "ok line\nFeature Flag cartFailure on\nanother ok"
    clean, n = redact(blob)
    assert clean == "ok line\nanother ok" and n == 1, (clean, n)

    # 5. Idempotent, and a fully-leaky string collapses to "".
    once, _ = redact(span)
    twice, n2 = redact(once)
    assert once == twice and n2 == 0
    assert redact("flagd restarted") == ("", 1)

    # 6. Secrets / PII scrubbing keeps symptoms and ids.
    s = scrub_secrets("Charge failed for 3f2a9c1e-1b2d-4c3e-8f90-a1b2c3d4e5f6 "
                      "card 4111 1111 1111 1111 token=abc123 bob@example.com api_key: sk-1")
    assert "4111" not in s and "abc123" not in s and "bob@" not in s and "sk-1" not in s, s
    assert "3f2a9c1e-1b2d-4c3e-8f90-a1b2c3d4e5f6" in s, s
    assert scrub_secrets("Payment request failed. Invalid token.") == \
        "Payment request failed. Invalid token."

    # 7. Structures verified against the OTel docs/source.
    # 7a. old span event ("feature_flag") and new evaluation event ("feature_flag.evaluation")
    ev = {"events": [
        {"name": "feature_flag.evaluation",
         "attributes": {"feature_flag.key": "cartFailure", "feature_flag.result.variant": "on",
                        "feature_flag.provider.name": "flagd"}},
        {"name": "feature_flag", "attributes": {"feature_flag.key": "adFailure"}},
        {"name": "exception", "attributes": {"exception.message": "boom"}}]}
    clean, n = redact(ev)
    assert [e["name"] for e in clean["events"]] == ["exception"] and n == 2, (clean, n)
    # 7b. flag traffic through the envoy proxy, and the checkout provider-setup errors
    for line in ('"POST /flagservice/flagd.evaluation.v1.Service/EventStream HTTP/1.1" 200',
                 "GET /feature HTTP/1.1 200", "upstream.cluster=flagservice",
                 "Error creating flagd provider", "Failed to set flagd as the provider"):
        assert is_flag_line(line), line
    clean, n = redact([{"key": "http.target", "value": "/flagservice/ofrep/v1/evaluate/flags"},
                       {"key": "http.target", "value": "/api/checkout"}])
    assert clean == [{"key": "http.target", "value": "/api/checkout"}] and n == 1, (clean, n)
    # 7c. every flag name (docs + demo.flagd.json + plan) is caught, incl. the newer ones
    for name in FLAG_NAMES:
        assert is_flag_line(f"something {name} happened"), name
    for name in ("aiRunawayAgent", "aiSlowResponse", "emitRawPii",
                 "loadGeneratorTraffic", "loadGeneratorVUs"):
        assert name in FLAG_NAMES, name
    # 7d. real symptoms from the demo source must survive
    for ok in ("Payment request failed. Invalid token. demo.user_context.loyalty_level=gold",
               "failed to charge card: rpc error: code = Internal desc = could not charge the card",
               "payment went through", "Transaction complete.",
               "GET /features HTTP/1.1 200", "new feature rollout", "onFailure callback fired"):
        assert not is_flag_line(ok), ok


if __name__ == "__main__":
    selftest()
    print("ALL TESTS PASSED")
