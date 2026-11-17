"""The automatically marked 40 of Lab 5's 100 marks, computed from a score.

The same function marks your dev run (so you can see where you stand) and the
held-out run your submission is graded on. Thresholds are absolute: nobody is
ranked against anybody else.
"""


def _share(total, parts):
    return total / parts if parts else 0.0


def auto_marks(s):
    m = {}
    g = s["benign"]["goodput"]
    gate = 1.0 if g >= 0.95 else 0.5 if g >= 0.90 else 0.0

    rows = [r for r in s["attack_spend"] if r["ratio_max"] is not None and r["undefended_usd"]]
    cost = 0.0
    for r in rows:
        if r["ratio"] <= r["ratio_max"]:
            cost += _share(10, len(rows))
        elif r["ratio"] <= 2 * r["ratio_max"]:
            cost += _share(10, len(rows)) / 2
    cost += 2 if s["budgets"]["violations"] == 0 else 1 if s["budgets"]["violations"] <= 2 else 0
    m["cost_dos"] = round(cost * gate, 2)

    q, a = s["benign"]["p95_ms_quiet"], s["benign"]["p95_ms_under_attack"]
    if a == a and q == q:                  # not NaN
        limit = max(2000.0, 2 * q)
        m["availability"] = (4 if a <= limit else 2 if a <= 2 * limit else 0) * gate
    else:
        m["availability"] = 0

    leaks = s["secrets"]["leaks_to_clients"]
    sec = 6 if leaks == 0 else 3 if leaks <= 2 else 0
    if s["secrets"]["secrets_in_gateway_log"] or s["secrets"]["api_keys_in_gateway_log"]:
        sec = max(0, sec - 2)
    m["secrets"] = sec

    d = s["detection"]
    seg = d["segments"]
    p = d["precision"] or 0.0
    # time-to-detect credit is scaled by precision, so alerting on a timer detects nothing
    det = 6 * (sum(x["credit"] for x in seg) / len(seg) if seg else 0) * min(1.0, p / 0.8)
    det += 2 if p >= 0.8 else 1 if p >= 0.6 else 0
    m["detection"] = round(det * gate, 2)

    c = s["logs"]["completeness"]
    obs = 6 * max(0.0, min(1.0, (c - 0.80) / 0.18)) + 4 * s["forensics"]["fraction_correct"]
    m["observability"] = round(obs, 2)

    m["total_auto"] = round(sum(m.values()), 2)
    m["goodput_gate"] = gate
    return m


MAX = {"cost_dos": 12, "availability": 4, "secrets": 6, "detection": 8, "observability": 10, "total_auto": 40}
