"""Replays a workload against the gateway and records what every client saw.

    python3 loadgen/loadgen.py --target http://localhost:8080 --profile dev

The load generator plays two roles. It is every client -- Hanbit's staff and
the attackers -- and it is the load balancer in front of your gateway, which is
why it sets X-Client-IP and why you may trust that header. It writes
out/<run>/results.jsonl (one line per request, with the response body),
segments.json (when each segment ran, in wall-clock time) and meta.json.

Scored runs use --speed 1. A higher speed compresses the clock for a quick
smoke test; it also multiplies every rate, so the numbers mean nothing.
"""
import argparse
import hashlib
import http.client
import json
import os
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import workload as W  # noqa: E402

TIMEOUT = 30.0


def send(target, r):
    body = W.materialise(r["body"])
    headers = {"X-Client-IP": r["ip"], "X-Request-ID": r["rid"], "User-Agent": "lab5-loadgen/1.0"}
    if r["key"]:
        headers["Authorization"] = "Bearer " + r["key"]
    if body:
        headers["Content-Type"] = "application/json"
    headers.update(r.get("headers") or {})      # whatever else this client chose to send
    u = urllib.parse.urlsplit(target)
    rec = {k: r[k] for k in ("rid", "t", "actor", "kind", "segment", "tenant", "key_id", "ip", "method", "path")}
    rec["prompt_sha256"] = hashlib.sha256(body).hexdigest()
    rec["request_bytes"] = len(body)
    t0 = time.time()
    rec["sent"] = t0
    try:
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=TIMEOUT)
        conn.request(r["method"], r["path"], body=body or None, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        rec.update(status=resp.status, response_sha256=hashlib.sha256(data).hexdigest(),
                   response=data.decode("utf-8", "replace"), error=None)
    except Exception as e:  # timeouts, resets, refused connections: the client saw a failure
        rec.update(status=0, response_sha256=None, response="", error=f"{type(e).__name__}: {e}"[:200])
    rec["done"] = time.time()
    rec["latency_ms"] = round((rec["done"] - t0) * 1000, 1)
    return rec


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--target", default=os.environ.get("TARGET", "http://localhost:8080"))
    ap.add_argument("--profile", default="dev")
    ap.add_argument("--profile-file", help="a Python file defining PROFILE (the graded run uses one)")
    ap.add_argument("--out", help="output directory (default out/<profile>-<time>)")
    ap.add_argument("--speed", type=float, default=1.0, help="clock compression; scored runs use 1")
    ap.add_argument("--until", type=float, help="stop scheduling after this many workload seconds")
    ap.add_argument("--workers", type=int, default=600)
    a = ap.parse_args()

    profile = W.load_profile(a.profile, a.profile_file)
    reqs, segments, t_end = W.build(profile)
    if a.until:
        reqs = [r for r in reqs if r["t"] < a.until]
        t_end = min(t_end, a.until)
    out = a.out or os.path.join("out", f"{profile['name']}-{time.strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(out, exist_ok=True)

    print(f"{profile['name']}: {len(reqs)} requests over {t_end / a.speed:.0f} s -> {a.target}", flush=True)
    start = time.time() + 2.0
    results, lock = [], threading.Lock()

    def job(r):
        rec = send(a.target, r)
        with lock:
            results.append(rec)

    seg_iter = iter(sorted(segments, key=lambda s: s["start"]))
    next_seg = next(seg_iter, None)
    with ThreadPoolExecutor(max_workers=a.workers) as pool:
        for r in reqs:
            due = start + r["t"] / a.speed
            while next_seg and next_seg["start"] <= r["t"]:
                print(f"  [{time.strftime('%H:%M:%S')}] {next_seg['name']}", flush=True)
                next_seg = next(seg_iter, None)
            delay = due - time.time()
            if delay > 0:
                time.sleep(delay)
            pool.submit(job, r)
        print(f"  [{time.strftime('%H:%M:%S')}] all requests sent; waiting for responses", flush=True)

    results.sort(key=lambda x: (x["t"], x["rid"]))
    with open(os.path.join(out, "results.jsonl"), "w", encoding="utf-8") as f:
        for rec in results:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    segs = []
    for s in segments:
        segs.append({k: v for k, v in s.items() if k not in ("start", "end")} |
                    {"start_ts": start + s["start"] / a.speed, "end_ts": start + s["end"] / a.speed,
                     "start": s["start"], "end": s["end"]})
    with open(os.path.join(out, "segments.json"), "w", encoding="utf-8") as f:
        json.dump(segs, f, indent=1)
    with open(os.path.join(out, "meta.json"), "w", encoding="utf-8") as f:
        json.dump({"profile": profile["name"], "seed": profile["seed"], "target": a.target, "speed": a.speed,
                   "start_ts": start, "end_ts": start + t_end / a.speed, "requests": len(results),
                   "spend_ratio_max": profile.get("spend_ratio_max", {})}, f, indent=1)
    bad = sum(1 for r in results if r["status"] == 0)
    print(f"wrote {out}: {len(results)} results, {bad} client-side failures", flush=True)
    print(out)


if __name__ == "__main__":
    main()
