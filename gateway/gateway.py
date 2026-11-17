"""The gateway -- the part of Lab 5 you build.

As provided, this is a transparent reverse proxy: every request, on every path,
goes straight to the helpdesk service, and it writes a log line that is nowhere
near the schema. Run the dev workload through it once before you change
anything (README, "A first run"), and keep that run: it is your baseline.

What it must become (handout section 1; every item is measured):
  1. authenticate the bearer key against config/tenants.json; know the tenant,
     the key_id and the tier of every request;
  2. allow only the routes and parameters the service is meant to expose;
  3. limit requests AND tokens per client IP, per key and per tenant;
  4. reserve each request's worst-case cost against the tenant's budget BEFORE
     forwarding it, and settle the actual cost afterwards;
  5. bound what one request may consume inside the service (the X-Lab5-*
     control headers -- and do not let clients set them);
  6. check every input and every output, including a scanner for the service's
     secrets in every form the scorer looks for;
  7. write exactly one schema-valid log line per request (schema/), expose
     metrics for Prometheus, and raise alerts to the alert sink.

Configuration comes from the environment, so the same code runs under
`make local` and in Docker Compose:
  GATEWAY_PORT (8080)  METRICS_PORT (9100)  APP_URL  ALERT_URL  LOG_PATH  TENANTS_PATH
"""
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab5.config import load_tenants  # noqa: E402,F401  -- you will need it

APP_URL = os.environ.get("APP_URL", "http://app:8000")
ALERT_URL = os.environ.get("ALERT_URL", "http://alertsink:9095/alert")
LOG_PATH = os.environ.get("LOG_PATH", "/logs/gateway.jsonl")
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "host", "content-length"}

_log_lock = threading.Lock()
_requests_total = {}
_metrics_lock = threading.Lock()


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def write_log(rec):
    # TODO(7): one record per request, conforming to schema/log_record.schema.json.
    os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
    with _log_lock, open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def send_alert(name, severity="warning", labels=None, summary=""):
    """Post one alert to the alert sink. Never let alerting break request handling."""
    body = json.dumps({"name": name, "severity": severity, "labels": labels or {}, "summary": summary}).encode()
    try:
        urllib.request.urlopen(urllib.request.Request(ALERT_URL, data=body, method="POST",
                                                      headers={"Content-Type": "application/json"}), timeout=2)
    except (urllib.error.URLError, OSError):
        pass


def forward(method, path, headers, body):
    """Send the request to the service; returns (status, response headers, response body)."""
    fwd = {k: v for k, v in headers.items() if k.lower() not in HOP}
    req = urllib.request.Request(APP_URL + path, data=body if body else None, method=method, headers=fwd)
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except (urllib.error.URLError, OSError) as e:
        return 502, {"Content-Type": "application/json"}, json.dumps({"error": f"upstream: {e}"}).encode()


class Gateway(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "lab5-gateway"

    def log_message(self, *a):
        pass

    def _handle(self):
        t0 = time.time()
        body = self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))

        # TODO(1) authenticate   TODO(2) routes and parameters   TODO(3) rate limits
        # TODO(4) reserve budget TODO(5) control headers          TODO(6) input check
        status, rh, data = forward(self.command, self.path, self.headers, body)
        # TODO(6) output check   TODO(4) settle cost

        self.send_response(status)
        self.send_header("Content-Type", rh.get("Content-Type", "application/json"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

        write_log({"ts": now_iso(), "path": self.path, "status": status,
                   "ms": round((time.time() - t0) * 1000)})
        with _metrics_lock:
            _requests_total[status] = _requests_total.get(status, 0) + 1

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _handle


class Metrics(BaseHTTPRequestHandler):
    """Prometheus text exposition on its own port, which only the monitoring network can reach."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        lines = ["# HELP lab5_requests_total Requests handled by the gateway, by HTTP status.",
                 "# TYPE lab5_requests_total counter"]
        with _metrics_lock:
            for code, n in sorted(_requests_total.items()):
                lines.append(f'lab5_requests_total{{status="{code}"}} {n}')
        # TODO(7): tokens, cost, blocks by reason, latency histogram, per tenant.
        out = ("\n".join(lines) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def main():
    port = int(os.environ.get("GATEWAY_PORT", "8080"))
    mport = int(os.environ.get("METRICS_PORT", "9100"))
    m = ThreadingHTTPServer(("0.0.0.0", mport), Metrics)
    m.daemon_threads = True
    threading.Thread(target=m.serve_forever, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", port), Gateway)
    srv.daemon_threads = True
    print(f"gateway on :{port} (metrics :{mport}) -> {APP_URL}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
