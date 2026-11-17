"""Run the whole system as local processes -- no Docker needed.

    python3 run_local.py                      # backend, service, alert sink and your gateway
    python3 run_local.py --gateway other.py   # a different gateway entry point

The same programs as the containers, wired together through environment
variables, on these ports:

    gateway   http://localhost:8080   (metrics on 9100)    <- point the load generator here
    service   http://localhost:18000  backend  http://localhost:19000  alert sink  http://localhost:19095

Logs go to logs/gateway/, logs/backend/ and logs/alerts/, exactly where the
compose file puts them. Ctrl-C stops everything. Use this to develop; your
submission is graded under Docker Compose, so test that too before you submit.
"""
import argparse
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def wait(url, name, procs, timeout=20):
    t = time.time()
    while time.time() - t < timeout:
        for p in procs:
            if p.poll() is not None:
                sys.exit(f"{name}: a process exited early (code {p.returncode})")
        try:
            urllib.request.urlopen(url, timeout=1).read()
            return
        except OSError:
            time.sleep(0.2)
    sys.exit(f"{name} did not become healthy at {url}")


def start(env_extra, ports=None, gateway="gateway/gateway.py", logs=None, quiet=False):
    """Start the four processes; returns them. Used by this script and by the graders."""
    ports = ports or {}
    logs = logs or os.path.join(HERE, "logs")
    sec = os.path.join(HERE, "secrets")
    gp, mp = ports.get("gateway", 8080), ports.get("metrics", 9100)
    ap, bp, sp = ports.get("app", 18000), ports.get("backend", 19000), ports.get("sink", 19095)
    for port in (gp, mp, ap, bp, sp):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                sys.exit(f"port {port} is already in use -- is an earlier run_local.py (or `make up`) still running?")
    base = dict(os.environ, PYTHONUNBUFFERED="1", TENANTS_PATH=os.path.join(HERE, "config", "tenants.json"))
    base.update(env_extra)
    out = subprocess.DEVNULL if quiet else None
    procs = []

    def run(script, env):
        procs.append(subprocess.Popen([sys.executable, script], cwd=HERE, env=dict(base, **env),
                                      stdout=out, stderr=out))

    run("backend/sim.py", {"SIM_PORT": str(bp), "BACKEND_API_KEY_FILE": os.path.join(sec, "backend_api_key"),
                           "LEDGER_PATH": os.path.join(logs, "backend", "ledger.jsonl")})
    run("alertsink/sink.py", {"SINK_PORT": str(sp), "ALERTS_PATH": os.path.join(logs, "alerts", "alerts.jsonl")})
    wait(f"http://localhost:{bp}/healthz", "backend", procs)
    run("service/app.py", {"APP_PORT": str(ap), "BACKEND_URL": f"http://localhost:{bp}",
                           "BACKEND_API_KEY_FILE": os.path.join(sec, "backend_api_key"),
                           "ESCALATION_CODE_FILE": os.path.join(sec, "escalation_code"),
                           "TICKETS_API_TOKEN_FILE": os.path.join(sec, "tickets_api_token")})
    wait(f"http://localhost:{ap}/healthz", "service", procs)
    run(gateway, {"GATEWAY_PORT": str(gp), "METRICS_PORT": str(mp), "APP_URL": f"http://localhost:{ap}",
                  "ALERT_URL": f"http://localhost:{sp}/alert",
                  "LOG_PATH": os.path.join(logs, "gateway", "gateway.jsonl")})
    wait(f"http://localhost:{mp}/metrics", "gateway", procs)
    return procs


def stop(procs):
    for p in procs:
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
    for p in procs:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--gateway", default="gateway/gateway.py")
    a = ap.parse_args()
    if not os.path.exists(os.path.join(HERE, "secrets", "backend_api_key")):
        sys.exit("no secrets yet: run `python3 make_secrets.py` (or `make secrets`) first")
    procs = start({}, gateway=a.gateway)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))     # `kill` stops the children too
    print("all up: gateway http://localhost:8080 -- Ctrl-C to stop", flush=True)
    try:
        while all(p.poll() is None for p in procs):
            time.sleep(0.5)
        print("a process exited; stopping", file=sys.stderr)
    except KeyboardInterrupt:
        pass
    finally:
        stop(procs)


if __name__ == "__main__":
    main()
