"""Score one replayed run: every number the handout asks for, and the automatic marks.

    python3 score.py out/dev-20261201-101500

Reads the run directory the load generator wrote, the backend's ledger, your
gateway's log and the alert sink's file, and writes score.json and summary.md
into the run directory. Clear logs/ before a run you intend to report
(`make clean-logs`): the scorer matches records by request id, but alerts are
matched by time.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from lab5.marking import MAX, auto_marks  # noqa: E402
from lab5.scoring import score            # noqa: E402


def fmt_usd(x):
    return "—" if x is None else f"${x:,.3f}"


def summary_md(s, m):
    b, L, d = s["benign"], s["logs"], s["detection"]
    lines = [f"# Lab 5 score — {s['run']} (profile `{s['profile']}`)", "",
             f"Requests: {s['requests']} · billed in total {fmt_usd(s['total_spend_usd'])}, "
             f"of which attackers {fmt_usd(s['attacker_spend_usd'])}", "",
             "## Benign service", "",
             f"- Goodput: **{b['goodput']:.1%}** ({b['good']}/{b['n']}), 95% CI "
             f"[{b['goodput_ci95'][0]:.1%}, {b['goodput_ci95'][1]:.1%}] — the floor is 95%",
             f"- p95 latency: {b['p95_ms_quiet']:.0f} ms quiet, {b['p95_ms_under_attack']:.0f} ms during attacks "
             f"(p50 quiet {b['p50_ms_quiet']:.0f} ms)",
             f"- Not served because: {b['not_good_because'] or 'nothing'}", "",
             "## Attacker spend, by segment", "",
             "| segment | attack requests | served | spend | undefended | ratio | max |", "|---|---:|---:|---:|---:|---:|---:|"]
    for r in s["attack_spend"]:
        ratio = "—" if r["ratio"] is None else f"{r['ratio']:.1%}"
        mx = "—" if r["ratio_max"] is None else f"{r['ratio_max']:.0%}"
        lines.append(f"| {r['segment']} | {r['attack_requests']} | {r['served_200']} | {fmt_usd(r['spend_usd'])} | "
                     f"{fmt_usd(r['undefended_usd'])} | {ratio} | {mx} |")
    bd = s["budgets"]
    lines += ["", f"Tenants over {110}% of their per-minute budget in some 60 s window: **{bd['violations']}**. "
              f"Platform peak {fmt_usd(bd['platform_peak_usd_per_60s'])}/60 s against {fmt_usd(bd['platform_budget'])}.", "",
              "## Secrets", "",
              f"- Responses carrying a secret to a client: **{s['secrets']['leaks_to_clients']}** "
              f"(the model emitted a secret {s['secrets']['model_emitted_secret']} times)",
              f"- Secrets in your gateway log: {s['secrets']['secrets_in_gateway_log'] or 'none'}; "
              f"API keys in your gateway log: {s['secrets']['api_keys_in_gateway_log']}", "",
              "## Detection", "", "| segment | time to detect | first alert |", "|---|---:|---|"]
    for x in d["segments"]:
        lines.append(f"| {x['segment']} | {'—' if x['ttd_s'] is None else str(x['ttd_s']) + ' s'} | {x['alert'] or '—'} |")
    prec = "—" if d["precision"] is None else f"{d['precision']:.0%}"
    lines += ["", f"Alert episodes: {d['episodes']} ({d['true_episodes']} during attacks, {d['false_episodes']} not); "
              f"precision {prec}.", "", "## Logs", "",
              f"- Completeness: **{L['completeness']:.1%}** of {L['requests_checked']} requests have exactly one "
              f"correct record", f"- Most common problems: {L['failures'] or 'none'}",
              f"- Unparseable lines: {L['unparseable_lines']}; records matching no request: "
              f"{L['records_not_matching_a_request']}", "", "## Forensics from your log alone", ""]
    for i in s["forensics"]["items"]:
        lines.append(f"- {'✓' if i['correct'] else '✗'} {i['segment'] or 'all'}: {i['question']} → {i['answer']}")
    lines += ["", "## Automatic marks (indicative on dev; graded on the held-out workload)", "",
              "| item | marks |", "|---|---:|"]
    for k in ("cost_dos", "availability", "secrets", "detection", "observability", "total_auto"):
        lines.append(f"| {k} | {m[k]} / {MAX[k]} |")
    if m["goodput_gate"] < 1:
        lines.append(f"\nGoodput below 95%: cost, availability and detection marks multiplied by {m['goodput_gate']}.")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("run")
    ap.add_argument("--gateway-log", default=os.path.join(HERE, "logs", "gateway", "gateway.jsonl"))
    ap.add_argument("--ledger", default=os.path.join(HERE, "logs", "backend", "ledger.jsonl"))
    ap.add_argument("--alerts", default=os.path.join(HERE, "logs", "alerts", "alerts.jsonl"))
    ap.add_argument("--secrets", default=os.path.join(HERE, "secrets"))
    ap.add_argument("--undefended", help="undefended spend per segment (default loadgen/undefended_<profile>.json)")
    ap.add_argument("--tenants", default=None)
    a = ap.parse_args()
    with open(os.path.join(a.run, "meta.json")) as f:
        meta = json.load(f)
    und_path = a.undefended or os.path.join(HERE, "loadgen", f"undefended_{meta['profile']}.json")
    und = None
    if os.path.exists(und_path):
        with open(und_path) as f:
            und = json.load(f)
    if und is None:
        print(f"note: no undefended spend file at {und_path}; spend ratios cannot be computed", file=sys.stderr)
    s = score(a.run, a.gateway_log, a.ledger, a.alerts, a.secrets, und, a.tenants,
              os.path.join(HERE, "loadgen", "keys.json"))
    m = auto_marks(s)
    s["auto_marks"] = m
    with open(os.path.join(a.run, "score.json"), "w") as f:
        json.dump(s, f, indent=1)
    md = summary_md(s, m)
    with open(os.path.join(a.run, "summary.md"), "w") as f:
        f.write(md)
    print(md)


if __name__ == "__main__":
    main()
