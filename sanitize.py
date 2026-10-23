"""Parse, sanitise and compress docker-compose logs before the agent sees them.

Pipeline: raw line -> parse service/message -> drop answer-leaking lines
-> redact secrets/PII -> classify error vs normal -> template repeated lines.
"""
import re
from collections import Counter, defaultdict

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# "payment-1  | message"  or  "payment  | message"
COMPOSE = re.compile(r"^(?P<svc>[A-Za-z0-9_.-]+?)(?:-\d+)?\s*\|\s?(?P<msg>.*)$")

SECRETS = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|passwd|authorization|bearer)\b"
    r"(\"?\s*[:=]\s*\"?)[^\s\",;}]+"
)
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
# 4-4-4-4 groups, or 13-19 bare digits; lookarounds stop it eating UUIDs/IDs
CARD = re.compile(r"(?<![\w-])(?:\d{4}[ -]){3}\d{1,4}(?![\w-])|(?<![\w-])\d{13,19}(?![\w-])")

# Lines that would hand the agent the answer (rules: reason from telemetry,
# do NOT read feature-flag settings). Flag names are camelCase, so that part
# is case-sensitive; a plain "payment failure" message must survive.
LEAK = re.compile(
    r"(?i)flagd|feature[\s_-]?flag|flag[\s_-]?(key|eval)"
    r"|(?-i:\b[a-z]+(?:Failure|Unreachable|ManualGc|HighCpu|QueueProblems"
    r"|FloodHomepage|SlowLoad|MemoryLeak)\b)"
)

ERRORISH = re.compile(
    r"(?i)\b(error|exception|fatal|panic|fail(?:ed|ure|s)?|timeout|timed out|"
    r"refused|unavailable|out of memory|oom|deadline exceeded|traceback|"
    r"50[0-4]|unreachable|reset by peer)\b"
)

TS = re.compile(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?")
UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
HEX = re.compile(r"\b[0-9a-f]{16,}\b")
IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
NUM = re.compile(r"\b\d+(?:\.\d+)?(?:ms|us|µs|s|MB|KB|%)?\b")


def redact(msg: str) -> str:
    msg = SECRETS.sub(r"\1\2<redacted>", msg)
    msg = EMAIL.sub("<email>", msg)
    msg = CARD.sub("<card>", msg)
    return msg


def template(msg: str) -> str:
    """Collapse variable parts so repeated errors group together."""
    msg = TS.sub("<ts>", msg)
    msg = UUID.sub("<uuid>", msg)
    msg = HEX.sub("<hex>", msg)
    msg = IP.sub("<ip>", msg)
    msg = NUM.sub("<n>", msg)
    return msg.strip()[:200]


def sanitise(raw_lines):
    """Return a list of {svc, msg, is_error} with leaks dropped and PII redacted."""
    records = []
    for line in raw_lines:
        line = ANSI.sub("", line).rstrip()
        if not line:
            continue
        m = COMPOSE.match(line)
        svc, msg = (m["svc"], m["msg"]) if m else ("unknown", line)
        if svc.startswith("flagd") or LEAK.search(msg):
            continue
        msg = redact(msg)
        records.append({"svc": svc, "msg": msg, "is_error": bool(ERRORISH.search(msg))})
    return records


def summarise(records, top_n=5):
    """Per-service error counts/rate and the top error templates."""
    lines = Counter(r["svc"] for r in records)
    errs = defaultdict(Counter)
    examples = {}
    for r in records:
        if r["is_error"]:
            t = template(r["msg"])
            errs[r["svc"]][t] += 1
            examples.setdefault((r["svc"], t), r["msg"][:200])
    out = {}
    for svc, total in lines.items():
        n_err = sum(errs[svc].values())
        out[svc] = {
            "total_lines": total,
            "error_lines": n_err,
            "error_rate": round(n_err / total, 3),
            "top_errors": [
                {"count": c, "template": t, "example": examples[(svc, t)]}
                for t, c in errs[svc].most_common(top_n)
            ],
        }
    # noisiest services first
    return dict(sorted(out.items(), key=lambda kv: kv[1]["error_lines"], reverse=True))
