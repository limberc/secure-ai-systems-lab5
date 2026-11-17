"""Every number Lab 5 measures, from one replayed run.

Inputs: the load generator's run directory (what clients saw, and the ground
truth), the backend's ledger (what was billed), the gateway's log (what you
recorded) and the alert sink's file (what paged). The gateway log is compared
with the other two; it is never trusted on its own.
"""
import hashlib
import json
import os
from collections import Counter, defaultdict
from datetime import datetime

from .config import load_tenants
from .leaks import find_leaks
from .schema import validate
from .stats import percentile, wilson

SLO_MS = 5000             # a benign answer slower than this did not serve its user
EPISODE_GAP_S = 10        # alerts of one name closer than this are one episode
DETECT_FULL_S = 20        # time-to-detect for full credit
DETECT_GRACE_S = 10       # an alert this long after a segment ends still counts, for half
BUDGET_SLACK = 1.10       # a tenant may overshoot its per-minute budget by 10% (in-flight requests)
SECRET_NAMES = ("backend_api_key", "escalation_code", "tickets_api_token")


def _jsonl(path):
    out, bad = [], 0
    if not path or not os.path.exists(path):
        return out, 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                bad += 1
    return out, bad


def _ts(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def load_secrets(d):
    out = {}
    for n in SECRET_NAMES:
        p = os.path.join(d, n)
        if os.path.exists(p):
            out[n] = _read(p).strip()
    return out


def _good(r, ledger):
    """Served: 200, within the SLO, not truncated, and the answer is text the model actually generated
    for this request -- an answer the gateway made up itself serves nobody."""
    if r["status"] != 200 or r["latency_ms"] > SLO_MS:
        return False
    try:
        j = json.loads(r["response"])
    except ValueError:
        return False
    if not isinstance(j, dict) or not isinstance(j.get("answer"), str) or not j["answer"].strip() or j.get("truncated"):
        return False
    made = {h for e in ledger.get(r["rid"], []) for h in e.get("text_sha256", [])}
    return hashlib.sha256(j["answer"].encode("utf-8")).hexdigest() in made


def _episodes(alerts):
    eps, last = [], {}
    for a in sorted(alerts, key=lambda a: a["received_ts"]):
        n = a["name"]
        if n in last and a["received_ts"] - last[n]["last"] <= EPISODE_GAP_S:
            last[n]["last"] = a["received_ts"]
            last[n]["count"] += 1
        else:
            ep = {"name": n, "start": a["received_ts"], "last": a["received_ts"], "count": 1,
                  "severity": a.get("severity")}
            eps.append(ep)
            last[n] = ep
    return eps


def _max_window(events, width=60.0):
    """Largest sum of amounts in any window of `width` seconds. events: [(ts, amount)]."""
    events.sort()
    best, s, j = 0.0, 0.0, 0
    for i, (t, a) in enumerate(events):
        s += a
        while events[j][0] < t - width:
            s -= events[j][1]
            j += 1
        best = max(best, s)
    return best


def score(run_dir, gateway_log, ledger_path, alerts_path, secrets_dir, undefended=None, tenants_path=None,
          keys_path=None):
    with open(os.path.join(run_dir, "meta.json")) as f:
        meta = json.load(f)
    with open(os.path.join(run_dir, "segments.json")) as f:
        segments = json.load(f)
    results, _ = _jsonl(os.path.join(run_dir, "results.jsonl"))
    rids = {r["rid"] for r in results}
    ledger_all, _ = _jsonl(ledger_path)
    ledger = defaultdict(list)
    for e in ledger_all:
        if e.get("request_id") in rids:
            ledger[e["request_id"]].append(e)
    for v in ledger.values():
        v.sort(key=lambda e: e.get("call", 0))
    logs, bad_lines = _jsonl(gateway_log)
    alerts_all, _ = _jsonl(alerts_path)
    t_lo, t_hi = meta["start_ts"] - 5, meta["end_ts"] + 60
    alerts = [a for a in alerts_all if a.get("status", "firing") == "firing" and t_lo <= a["received_ts"] <= t_hi]
    secrets = load_secrets(secrets_dir)
    tiers, tenants, _, platform = load_tenants(tenants_path)
    spend_ratio_max = meta.get("spend_ratio_max", {})
    seg_by_name = {s["name"]: s for s in segments}
    attack_segs = [s for s in segments if s["attack"]]

    out = {"run": os.path.basename(os.path.normpath(run_dir)), "profile": meta["profile"],
           "requests": len(results), "secrets_loaded": sorted(secrets)}

    # ------------------------------------------------------------ benign service
    benign = [r for r in results if r["actor"] == "benign"]
    good = [r for r in benign if _good(r, ledger)]
    k, n = len(good), len(benign)

    def in_attack(r):
        ts = r["sent"]
        return any(s["start_ts"] <= ts <= s["end_ts"] for s in attack_segs)

    lat_q = [r["latency_ms"] for r in benign if r["status"] == 200 and not in_attack(r)]
    lat_a = [r["latency_ms"] for r in benign if r["status"] == 200 and in_attack(r)]
    by_seg = {}
    for s in segments:
        rs = [r for r in benign if s["start_ts"] <= r["sent"] <= s["end_ts"]]
        by_seg[s["name"]] = {"n": len(rs), "goodput": round(sum(_good(r, ledger) for r in rs) / len(rs), 4) if rs else None}
    log_by_rid = defaultdict(list)
    for rec in logs:
        if isinstance(rec, dict) and rec.get("request_id") in rids:
            log_by_rid[rec["request_id"]].append(rec)
    why = Counter()
    for r in benign:
        if not _good(r, ledger):
            recs = log_by_rid.get(r["rid"])
            if r["status"] == 200:
                why["slow, truncated, or not the model's answer"] += 1
            elif recs and recs[0].get("block_reason"):
                why[f"blocked: {recs[0]['block_reason']}"] += 1
            else:
                why[f"status {r['status']}"] += 1
    out["benign"] = {
        "n": n, "good": k, "goodput": round(k / n, 4) if n else 0.0,
        "goodput_ci95": [round(x, 4) for x in wilson(k, n)],
        "p50_ms_quiet": round(percentile(lat_q, 50), 1), "p95_ms_quiet": round(percentile(lat_q, 95), 1),
        "p95_ms_under_attack": round(percentile(lat_a, 95), 1),
        "by_segment": by_seg, "not_good_because": dict(why.most_common()),
    }

    # ------------------------------------------------------------ attacker spend
    seg_rows = []
    und = (undefended or {}).get("segments", {})
    for s in attack_segs:
        rs = [r for r in results if r.get("segment") == s["name"] and r["actor"] == "attack"]
        spend = sum(e["cost_usd"] for r in rs for e in ledger.get(r["rid"], []))
        base = und.get(s["name"])
        ratio = (spend / base) if base else None
        lim = spend_ratio_max.get(s["kind"])
        seg_rows.append({"segment": s["name"], "kind": s["kind"], "attack_requests": len(rs),
                         "served_200": sum(1 for r in rs if r["status"] == 200),
                         "spend_usd": round(spend, 4), "undefended_usd": base,
                         "ratio": round(ratio, 4) if ratio is not None else None, "ratio_max": lim,
                         "pass": (ratio is not None and lim is not None and ratio <= lim)})
    out["attack_spend"] = seg_rows
    out["total_spend_usd"] = round(sum(e["cost_usd"] for v in ledger.values() for e in v), 4)
    out["attacker_spend_usd"] = round(sum(x["spend_usd"] for x in seg_rows), 4)

    # ------------------------------------------------------------ tenant budgets (ground truth tenant)
    gt_tenant = {r["rid"]: r["tenant"] for r in results}
    ev = defaultdict(list)
    plat = []
    for rid, es in ledger.items():
        for e in es:
            t = _ts(e["ts"])
            if t is None:
                continue
            plat.append((t, e["cost_usd"]))
            if gt_tenant.get(rid):
                ev[gt_tenant[rid]].append((t, e["cost_usd"]))
    worst = []
    for tn, es in ev.items():
        budget = tiers[tenants[tn]["tier"]]["budget_usd_per_min"]
        peak = _max_window(es)
        worst.append({"tenant": tn, "peak_usd_per_60s": round(peak, 4), "budget": budget,
                      "ratio": round(peak / budget, 3)})
    worst.sort(key=lambda x: -x["ratio"])
    out["budgets"] = {"violations": sum(1 for w in worst if w["ratio"] > BUDGET_SLACK),
                      "worst": worst[:8],
                      "platform_peak_usd_per_60s": round(_max_window(plat), 4),
                      "platform_budget": platform["budget_usd_per_min"]}

    # ------------------------------------------------------------ secrets
    leaked = []
    for r in results:
        names = find_leaks(r["response"], secrets)
        if names:
            leaked.append({"rid": r["rid"], "segment": r.get("segment"), "path": r["path"], "secrets": names})
    emitted = sum(1 for v in ledger.values() for e in v if e.get("leaked"))
    log_text = _read(gateway_log) if os.path.exists(gateway_log) else ""
    keys = json.loads(_read(keys_path))["keys"] if keys_path and os.path.exists(keys_path) else {}
    creds_in_logs = sum(1 for v in keys.values() if v and v in log_text)
    out["secrets"] = {"leaks_to_clients": len(leaked), "leaked_examples": leaked[:10],
                      "model_emitted_secret": emitted,
                      "secrets_in_gateway_log": find_leaks(log_text, secrets) if log_text else [],
                      "api_keys_in_gateway_log": creds_in_logs}

    # ------------------------------------------------------------ detection
    eps = _episodes(alerts)
    det = []
    for s in attack_segs:
        starts = [e for e in eps if s["start_ts"] <= e["start"] <= s["end_ts"] + DETECT_GRACE_S]
        if starts:
            first = min(starts, key=lambda e: e["start"])
            ttd = first["start"] - s["start_ts"]
            credit = 1.0 if ttd <= DETECT_FULL_S else 0.5
            det.append({"segment": s["name"], "ttd_s": round(ttd, 1), "alert": first["name"], "credit": credit})
        else:
            det.append({"segment": s["name"], "ttd_s": None, "alert": None, "credit": 0.0})
    tp = [e for e in eps if any(s["start_ts"] <= e["start"] <= s["end_ts"] + DETECT_GRACE_S for s in attack_segs)]
    fp = [e for e in eps if e not in tp]
    out["detection"] = {"segments": det, "episodes": len(eps), "true_episodes": len(tp),
                        "false_episodes": len(fp), "false_examples": [
                            {"name": e["name"], "at_s": round(e["start"] - meta["start_ts"], 1)} for e in fp[:8]],
                        "precision": round(len(tp) / len(eps), 3) if eps else None,
                        "alerts_received": len(alerts)}

    # ------------------------------------------------------------ log completeness
    checked = [r for r in results if r["status"] != 0]
    fails = Counter()
    complete = 0
    for r in checked:
        recs = log_by_rid.get(r["rid"], [])
        if len(recs) != 1:
            fails["no record" if not recs else "duplicate records"] += 1
            continue
        rec, ok = recs[0], True
        errs = validate(rec)
        if errs:
            fails["schema: " + errs[0].split(" has ")[0].split(" not ")[0][:40]] += 1
            continue
        L = ledger.get(r["rid"], [])
        checks = [
            ("prompt_sha256", rec["prompt_sha256"] == r["prompt_sha256"]),
            ("response_sha256", rec["response_sha256"] == r["response_sha256"]),
            ("status", rec["status"] == r["status"]),
            ("client_ip", rec["client_ip"] == r["ip"]),
            ("tenant", rec["tenant"] == r["tenant"]),
            ("key_id", rec["key_id"] == r["key_id"]),
            ("tokens_in", rec["tokens_in"] == sum(e["tokens_in"] for e in L)),
            ("tokens_out", rec["tokens_out"] == sum(e["tokens_out"] for e in L)),
            ("cost_usd", abs(rec["cost_usd"] - sum(e["cost_usd"] for e in L)) <= 1e-6 + 0.01 * sum(e["cost_usd"] for e in L)),
            ("backend_calls", rec["backend_calls"] == len(L)),
            ("tool_calls", rec["tool_calls"] == [e["tool"] for e in L if e.get("tool")]),
        ]
        for name, passed in checks:
            if not passed:
                fails[name] += 1
                ok = False
        complete += ok
    orphans = sum(1 for rec in logs if not (isinstance(rec, dict) and rec.get("request_id") in rids))
    out["logs"] = {"requests_checked": len(checked), "complete": complete,
                   "completeness": round(complete / len(checked), 4) if checked else 0.0,
                   "failures": dict(fails.most_common(12)), "unparseable_lines": bad_lines,
                   "records_not_matching_a_request": orphans}

    # ------------------------------------------------------------ forensics, from the gateway log alone
    out["forensics"] = forensics(logs, segments, results, ledger)
    return out


def forensics(logs, segments, results, ledger):
    """Questions an incident responder asks, answered from the gateway log alone, then checked."""
    recs = [x for x in logs if isinstance(x, dict) and isinstance(x.get("ts"), str)]
    for x in recs:
        x["_t"] = _ts(x["ts"])
    gt = defaultdict(lambda: {"ips": set(), "keys": set()})
    for r in results:
        if r["actor"] == "attack" and r.get("segment"):
            gt[r["segment"]]["ips"].add(r["ip"])
            if r["key_id"]:
                gt[r["segment"]]["keys"].add(r["key_id"])
    items = []
    for s in segments:
        if not s["attack"]:
            continue
        win = [x for x in recs if x["_t"] is not None and s["start_ts"] - 1 <= x["_t"] <= s["end_ts"] + 1]
        g = gt[s["name"]]
        if s["kind"] == "distributed_flood":
            ips = defaultdict(set)
            for x in win:
                if x.get("key_id"):
                    ips[x["key_id"]].add(x.get("client_ip"))
            ans = max(ips, key=lambda k: len(ips[k])) if ips else None
            items.append({"segment": s["name"], "question": "which key was driven from the most IPs?",
                          "answer": ans, "correct": ans in g["keys"]})
        elif s["kind"] == "key_rotation":
            keys = defaultdict(set)
            for x in win:
                keys[x.get("client_ip")].add(x.get("key_id") or "unauthenticated")
            ans = max(keys, key=lambda k: len(keys[k])) if keys else None
            items.append({"segment": s["name"], "question": "which IP used the most distinct keys?",
                          "answer": ans, "correct": ans in g["ips"]})
        else:
            blocked = Counter(x.get("key_id") for x in win
                              if x.get("outcome") == "blocked" and x.get("key_id"))
            ans = blocked.most_common(1)[0][0] if blocked else None
            items.append({"segment": s["name"], "question": "which key had the most blocked requests?",
                          "answer": ans, "correct": ans in g["keys"]})
    # spend reconciliation per tenant: the log's cost against the ledger's
    led, lg = defaultdict(float), defaultdict(float)
    tenant_of = {r["rid"]: r["tenant"] for r in results}
    for rid, es in ledger.items():
        if tenant_of.get(rid):
            led[tenant_of[rid]] += sum(e["cost_usd"] for e in es)
    for x in recs:
        if x.get("tenant") and isinstance(x.get("cost_usd"), (int, float)):
            lg[x["tenant"]] += x["cost_usd"]
    big = [t for t, v in led.items() if v >= 0.01]
    rec_ok = [t for t in big if abs(lg.get(t, 0.0) - led[t]) <= 0.02 * led[t] + 1e-6]
    items.append({"segment": None, "question": "does per-tenant spend in the log reconcile with the ledger (±2%)?",
                  "answer": f"{len(rec_ok)}/{len(big)} tenants", "correct": bool(big) and len(rec_ok) == len(big)})
    return {"items": items, "fraction_correct": round(sum(i["correct"] for i in items) / len(items), 3) if items else 0}
