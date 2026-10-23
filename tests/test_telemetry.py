"""Offline test: fake Prometheus + Jaeger servers with canned responses.

Run from the project folder:  python tests/test_telemetry.py
Checks: backend auto-detection, metric parsing and anomaly flags, deepest-failing-span
(origin) logic, and that flag-leaking spans are filtered out.
"""
import json
import os
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

os.environ["no_proxy"] = "localhost,127.0.0.1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def vec(vals):
    return {"status": "success", "data": {"resultType": "vector", "result": [
        {"metric": {"service_name": s}, "value": [0, str(v)]} for s, v in vals.items()]}}


def span(sid, op, pid, parent=None, err=False, msg=None):
    tags = [{"key": "error", "value": True}, {"key": "otel.status_code", "value": "ERROR"}] if err else []
    if msg:
        tags.append({"key": "otel.status_description", "value": msg})
    return {"spanID": sid, "operationName": op, "processID": pid, "tags": tags,
            "references": [{"refType": "CHILD_OF", "spanID": parent}] if parent else []}


TRACE = {"traceID": "t1",
         "processes": {"p1": {"serviceName": "frontend"}, "p2": {"serviceName": "checkout"},
                       "p3": {"serviceName": "payment"}, "p4": {"serviceName": "flagd"}},
         "spans": [span("a", "POST /api/checkout", "p1", err=True, msg="500"),
                   span("b", "PlaceOrder", "p2", "a", err=True, msg="failed to charge card"),
                   span("c", "Charge", "p3", "b", err=True, msg="Charge failed for user 4521"),
                   # flag-evaluation span: must be ignored, and must NOT make `c` look non-origin
                   span("d", "flagd.evaluation.v1.Service/ResolveBoolean", "p4", "c", err=True,
                        msg="paymentFailure variant on")]}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/api/v1/label/__name__/values":
            return self._send({"status": "success", "data": [
                "traces_span_metrics_calls_total",
                "traces_span_metrics_duration_milliseconds_bucket", "up"]})
        if u.path == "/api/v1/query":
            e = q["query"][0]
            base = "offset" in e
            if "histogram_quantile" in e:
                return self._send(vec({"payment": 120 if base else 900, "cart": 40, "frontend": 60}))
            if "STATUS_CODE_ERROR" in e:
                return self._send(vec({"payment": 0 if base else 4.5, "frontend": 0 if base else 4.0}))
            vals = {"payment": 5, "cart": 8, "frontend": 10}
            if base:
                vals["email"] = 2  # reported in baseline, gone now
            else:
                vals["flagd"] = 3  # must be ignored
            return self._send(vec(vals))
        if u.path == "/api/services":
            return self._send({"data": ["frontend", "checkout", "payment", "flagd"]})
        if u.path == "/api/traces":
            return self._send({"data": [TRACE]})
        self.send_response(404)
        self.end_headers()


srv = HTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{srv.server_port}"
os.environ["PROMETHEUS_URL"] = url
os.environ["JAEGER_URL"] = url

import telemetry  # noqa: E402  (after env is set)

print(telemetry.check(), "\n")

m = json.loads(telemetry.query_metrics())
print(json.dumps(m, indent=1)[:900], "...\n")
svcs = {r["service"]: r for r in m["services"]}
assert "flagd" not in svcs, "flagd must be ignored"
assert svcs["payment"]["now"]["error_ratio"] == 0.9, svcs["payment"]
assert "error ratio up vs baseline" in svcs["payment"]["flags"]
assert "p95 latency more than doubled" in svcs["payment"]["flags"]
assert m["services"][0]["service"] in ("payment", "frontend")  # alarming ones first
assert m["stopped_reporting"] == ["email"], m["stopped_reporting"]

t = json.loads(telemetry.query_traces())
print(json.dumps(t, indent=1), "\n")
assert t["error_traces"] == 1  # deduped across services
origins = [(o["service"], o["operation"]) for o in t["origin_errors"]]
assert origins == [("payment", "Charge")], origins
assert "paymentFailure" not in json.dumps(t) and "flagd" not in json.dumps(t)
assert {"count": 1, "from": "checkout", "to": "payment"} in t["failing_calls"]
assert "<n>" in t["origin_errors"][0]["message"]  # ids templated for grouping

print("ALL OK")
