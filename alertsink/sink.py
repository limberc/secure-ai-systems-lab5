"""The alert sink -- stands in for your pager. Do not modify it.

An alert counts when it arrives here; the arrival time is what time-to-detect is
measured from. Two ways in:

  POST /alert          {"name": str, "severity": "info"|"warning"|"critical",
                        "labels": {str: str}, "summary": str}
                       -- for alerts your gateway raises itself
  POST /alertmanager   Alertmanager's webhook payload (version 4)
                       -- for alerts from Prometheus rules, routed by Alertmanager
  GET  /alerts         everything received so far, as JSON lines

Each received alert is appended to ALERTS_PATH as one JSON line. Resolved
notifications from Alertmanager are recorded but are not alerts.
"""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()
SEVERITIES = {"info", "warning", "critical"}


def path():
    return os.environ.get("ALERTS_PATH", "logs/alerts/alerts.jsonl")


def record(rec):
    p = path()
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    with LOCK, open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, b'{"ok": true}')
        if self.path == "/alerts":
            data = open(path(), "rb").read() if os.path.exists(path()) else b""
            return self._send(200, data, "application/x-ndjson")
        self._send(404, b'{"error": "not found"}')

    def do_POST(self):
        now = time.time()
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0") or 0)) or b"{}")
        except ValueError:
            return self._send(400, b'{"error": "bad json"}')
        if self.path == "/alert":
            name = str(body.get("name", "")).strip()
            if not name:
                return self._send(400, b'{"error": "name is required"}')
            sev = body.get("severity", "warning")
            record({"received_ts": now, "source": "direct", "status": "firing", "name": name,
                    "severity": sev if sev in SEVERITIES else "warning",
                    "labels": {str(k): str(v) for k, v in (body.get("labels") or {}).items()},
                    "summary": str(body.get("summary", ""))[:500]})
            return self._send(200, b'{"ok": true}')
        if self.path == "/alertmanager":
            for a in body.get("alerts", []):
                labels = {str(k): str(v) for k, v in (a.get("labels") or {}).items()}
                record({"received_ts": now, "source": "alertmanager", "status": a.get("status", "firing"),
                        "name": labels.get("alertname", "unnamed"), "severity": labels.get("severity", "warning"),
                        "labels": labels, "summary": str((a.get("annotations") or {}).get("summary", ""))[:500],
                        "starts_at": a.get("startsAt")})
            return self._send(200, b'{"ok": true}')
        self._send(404, b'{"error": "not found"}')


def main():
    host = os.environ.get("SINK_HOST", "0.0.0.0")
    port = int(os.environ.get("SINK_PORT", "9095"))
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    print(f"alert sink on {host}:{port} -> {path()}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
