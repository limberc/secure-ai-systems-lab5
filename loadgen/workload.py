"""The workload: who sends what, when. Deterministic from a profile and a seed.

A profile is a warm-up of benign traffic, then a sequence of segments. Each
segment is one attack (or a legitimate surge) on top of the benign traffic that
never stops. Every request carries its ground truth -- benign or attack, which
segment, which tenant really sent it -- which the scorer uses and the gateway
never sees.

    python3 loadgen/workload.py --profile dev --describe     what the dev workload contains

The graded run uses a held-out profile: a different seed, different victims and
timings, and one kind of attack that is not in the dev profile. Defend against
the classes of attack, not against this file.
"""
import argparse
import hashlib
import json
import math
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.modules.setdefault("workload", sys.modules[__name__])   # one registry, however this file is run
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import prompts as P                    # noqa: E402
from lab5.config import load_tenants   # noqa: E402

DEV = {
    "name": "dev",
    "seed": 20261130,
    "warmup_s": 30,
    "cooldown_s": 20,
    "benign": {"rates": {"acme": 0.9, "bluebird": 0.5, "cobalt": 0.5, "delta": 0.7, "ember": 0.9,
                         "fjord": 0.4, "gwangan": 0.4, "hallim": 0.6},
               "trial_keys": [1, 24], "trial_rate": 0.02},
    "segments": [
        {"kind": "distributed_flood", "dur": 40, "gap": 15, "victim": "acme", "ips": 200, "rps": 40},
        {"kind": "key_rotation", "dur": 40, "gap": 15, "trial_keys": [101, 250], "rps": 30, "invalid_frac": 0.3},
        {"kind": "benign_surge", "dur": 40, "gap": 15, "tenant": "ember", "factor": 3.0},
        {"kind": "token_amplification", "dur": 40, "gap": 15, "trial_keys": [301, 306], "rps": 2},
        {"kind": "context_stuffing", "dur": 40, "gap": 15, "victim": "fjord", "rps": 3},
        {"kind": "agent_tool_loop", "dur": 40, "gap": 15, "victim": "cobalt", "rps": 1},
        {"kind": "bon_exfil", "dur": 40, "gap": 15, "trial_keys": [351, 370], "ips": 10, "rps": 15},
    ],
    # Largest acceptable attacker spend in a segment, as a fraction of what the
    # undefended starter spends on the same segment (loadgen/undefended_dev.json).
    "spend_ratio_max": {"distributed_flood": 0.25, "key_rotation": 0.10, "token_amplification": 0.10,
                        "context_stuffing": 0.05, "agent_tool_loop": 0.20, "bon_exfil": 0.50},
}
PROFILES = {"dev": DEV}
GENERATORS = {}


def generator(kind):
    def deco(fn):
        GENERATORS[kind] = fn
        return fn
    return deco


class Ctx:
    """What generators share: the tenant contract, the plaintext keys, a seeded RNG and an IP allocator."""

    def __init__(self, profile):
        self.profile = profile
        self.rng = random.Random(profile["seed"])
        self.tiers, self.tenants, _, _ = load_tenants()
        with open(os.path.join(HERE, "keys.json"), encoding="utf-8") as f:
            self.keys = json.load(f)["keys"]
        self.used_ips = set()
        self.office, self.remote, self.integration = {}, {}, {}
        for t in sorted(self.tenants):
            if not t.startswith("trial-"):
                self.office[t] = [self.ip() for _ in range(2)]
                self.remote[t] = [self.ip() for _ in range(12)]
                self.integration[t] = [self.ip()]
        self.trial_ip = {}

    def ip(self):
        while True:
            a = self.rng.choice([x for x in range(11, 224) if x not in (10, 100, 127, 169, 172, 192, 198, 203)])
            ip = f"{a}.{self.rng.randrange(256)}.{self.rng.randrange(256)}.{self.rng.randrange(1, 255)}"
            if ip not in self.used_ips:
                self.used_ips.add(ip)
                return ip

    def tier(self, tenant):
        return self.tiers[self.tenants[tenant]["tier"]]

    def rid(self):
        return "%032x" % self.rng.getrandbits(128)

    def req(self, t, actor, kind, key_id, ip, path, body, method="POST", key=None):
        tenant = key_id.rsplit("-k", 1)[0] if key_id else None
        return {"rid": self.rid(), "t": round(t, 3), "actor": actor, "kind": kind, "tenant": tenant,
                "key_id": key_id, "key": key if key is not None else (self.keys[key_id] if key_id else None),
                "ip": ip, "method": method, "path": path, "body": body}


def poisson(rng, rate, t0, t1):
    t, out = t0, []
    if rate <= 0:
        return out
    while True:
        t += rng.expovariate(rate)
        if t >= t1:
            return out
        out.append(t)


def trial(i):
    return f"trial-{i:04d}-k1"


# ---------------------------------------------------------------- benign traffic

def benign_body(ctx, tenant, rng):
    tier = ctx.tier(tenant)
    r = rng.random()
    mt = [m for m in (128, 256, 384, 512, 768, 1024) if m <= tier["max_output_tokens"]]
    if r < 0.06:
        return "/v1/chat", {"messages": [{"role": "user", "content": rng.choice(P.BENIGN_TWINS)}],
                            "max_tokens": rng.choice(mt)}
    if r < 0.10:
        hi = tier["max_input_tokens"] - 800
        n = rng.randrange(min(800, hi - 1), hi)
        text = "Summarise this log and tell me what to check first:\n" + P.log_text(rng, n)
        return "/v1/chat", {"messages": [{"role": "user", "content": text}], "max_tokens": rng.choice(mt)}
    if r < 0.58:
        body = {"messages": [{"role": "user", "content": P.fill(rng.choice(P.BENIGN_CHAT), rng)}]}
        if rng.random() < 0.8:
            body["max_tokens"] = rng.choice(mt)
        if rng.random() < 0.5:
            body["temperature"] = rng.choice([0.0, 0.2, 0.7])
        return "/v1/chat", body
    if r < 0.83:
        body = {"question": f"What is the procedure for {rng.choice(P.TOPICS)} problems?"}
        if rng.random() < 0.5:
            body["top_k"] = rng.randrange(2, tier["max_top_k"] + 1)
        if rng.random() < 0.5:
            body["max_tokens"] = rng.choice(mt)
        return "/v1/rag", body
    body = {"task": P.fill(rng.choice(P.AGENT_BENIGN), rng)}
    if rng.random() < 0.5:
        body["max_steps"] = rng.randrange(4, tier["max_agent_steps"] + 1)
    return "/v1/agent", body


def benign_at(ctx, tenant, t, rng):
    if tenant.startswith("trial-"):
        key_id = tenant + "-k1"
        ip = ctx.trial_ip.setdefault(tenant, ctx.ip())
    else:
        u = rng.random()
        key_id = f"{tenant}-k1" if u < 0.6 else f"{tenant}-k2" if u < 0.98 else f"{tenant}-k3"
        if key_id.endswith("-k3"):
            ip = ctx.integration[tenant][0]
        else:
            ip = rng.choice(ctx.office[tenant]) if rng.random() < 0.7 else rng.choice(ctx.remote[tenant])
    path, body = benign_body(ctx, tenant, rng)
    return ctx.req(t, "benign", "benign", key_id, ip, path, body)


def benign_traffic(ctx, t_end):
    rng = random.Random(ctx.profile["seed"] + 1)
    b = ctx.profile["benign"]
    out = []
    for tenant, rate in sorted(b["rates"].items()):
        out += [benign_at(ctx, tenant, t, rng) for t in poisson(rng, rate, 0, t_end)]
    lo, hi = b["trial_keys"]
    for i in range(lo, hi + 1):
        out += [benign_at(ctx, trial(i)[:-3], t, rng) for t in poisson(rng, b["trial_rate"], 0, t_end)]
    return out


# ---------------------------------------------------------------- segments

@generator("benign_surge")
def g_surge(ctx, seg, t0, rng):
    base = ctx.profile["benign"]["rates"][seg["tenant"]]
    return [benign_at(ctx, seg["tenant"], t, rng)
            for t in poisson(rng, base * (seg["factor"] - 1), t0, t0 + seg["dur"])]


@generator("distributed_flood")
def g_flood(ctx, seg, t0, rng):
    """A stolen integration key, driven from a botnet: every IP stays slow, the key does not."""
    key_id = f"{seg['victim']}-k3"
    ips = [ctx.ip() for _ in range(seg["ips"])]
    out = []
    for t in poisson(rng, seg["rps"], t0, t0 + seg["dur"]):
        body = {"messages": [{"role": "user", "content": P.fill(rng.choice(P.BENIGN_CHAT), rng)}], "max_tokens": 256}
        out.append(ctx.req(t, "attack", seg["kind"], key_id, rng.choice(ips), "/v1/chat", body))
    return out


@generator("key_rotation")
def g_rotation(ctx, seg, t0, rng):
    """One host cycling through many free-trial keys (and guessing some): every key stays slow, the host does not."""
    ip = ctx.ip()
    lo, hi = seg["trial_keys"]
    keys = [trial(i) for i in range(lo, hi + 1)]
    out = []
    for j, t in enumerate(poisson(rng, seg["rps"], t0, t0 + seg["dur"])):
        body = {"messages": [{"role": "user", "content": P.fill(rng.choice(P.BENIGN_CHAT), rng)}], "max_tokens": 256}
        if rng.random() < seg.get("invalid_frac", 0):
            fake = "hb_test_" + "".join(rng.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(32))
            out.append(ctx.req(t, "attack", seg["kind"], None, ip, "/v1/chat", body, key=fake))
        else:
            out.append(ctx.req(t, "attack", seg["kind"], keys[j % len(keys)], ip, "/v1/chat", body))
    return out


@generator("token_amplification")
def g_amplify(ctx, seg, t0, rng):
    """Short prompts that ask for very long answers, from free-trial accounts."""
    lo, hi = seg["trial_keys"]
    keys = [trial(i) for i in range(lo, hi + 1)]
    ips = {k: ctx.ip() for k in keys}
    out = []
    for t in poisson(rng, seg["rps"], t0, t0 + seg["dur"]):
        k = rng.choice(keys)
        body = {"messages": [{"role": "user", "content": rng.choice(P.AMPLIFY).format(n=rng.choice([5000, 8000, 20000]))}]}
        if rng.random() < 0.4:
            body["max_tokens"] = rng.choice([16000, 32000])
        out.append(ctx.req(t, "attack", seg["kind"], k, ips[k], "/v1/chat", body))
    return out


@generator("context_stuffing")
def g_stuff(ctx, seg, t0, rng):
    """Huge inputs through a compromised business integration: the bill is in the prefill."""
    key_id = f"{seg['victim']}-k2"
    ips = [ctx.ip() for _ in range(3)]
    out = []
    for t in poisson(rng, seg["rps"], t0, t0 + seg["dur"]):
        body = {"lazy": "stuffing", "seed": rng.getrandbits(32), "tokens": rng.randrange(60000, 120000)}
        out.append(ctx.req(t, "attack", seg["kind"], key_id, rng.choice(ips), "/v1/chat", body))
    return out


@generator("agent_tool_loop")
def g_loop(ctx, seg, t0, rng):
    """Agent tasks that never finish: one request, dozens of model calls, each longer than the last."""
    key_id = f"{seg['victim']}-k2"
    ips = [ctx.ip() for _ in range(2)]
    out = []
    for t in poisson(rng, seg["rps"], t0, t0 + seg["dur"]):
        body = {"task": P.fill(rng.choice(P.LOOP_TASKS), rng)}
        if rng.random() < 0.5:
            body["max_steps"] = 100
        out.append(ctx.req(t, "attack", seg["kind"], key_id, rng.choice(ips), "/v1/agent", body))
    return out


@generator("bon_exfil")
def g_bon(ctx, seg, t0, rng):
    """Best-of-N extraction of the service's secrets, plus probes for its debug endpoint."""
    lo, hi = seg["trial_keys"]
    keys = [trial(i) for i in range(lo, hi + 1)]
    ips = [ctx.ip() for _ in range(seg["ips"])]
    out = []
    for t in poisson(rng, seg["rps"], t0, t0 + seg["dur"]):
        k, ip, u = rng.choice(keys), rng.choice(ips), rng.random()
        if u < 0.75:
            body = {"messages": [{"role": "user", "content": P.augment(rng.choice(P.EXFIL_BASE), rng)}],
                    "max_tokens": 256}
            out.append(ctx.req(t, "attack", seg["kind"], k, ip, "/v1/chat", body))
        elif u < 0.90:
            body = {"task": P.augment(rng.choice(P.EXFIL_AGENT), rng), "max_steps": 4}
            out.append(ctx.req(t, "attack", seg["kind"], k, ip, "/v1/agent", body))
        elif u < 0.95:
            out.append(ctx.req(t, "attack", seg["kind"], k, ip, rng.choice(["/admin/debug", "/admin/debug?verbose=1"]),
                               None, method="GET"))
        else:
            out.append(ctx.req(t, "attack", seg["kind"], None, ip, "/admin/debug", None, method="GET", key=""))
    return out


# ---------------------------------------------------------------- assembly

def build(profile):
    """Returns (requests sorted by time, segments with their start and end offsets)."""
    ctx = Ctx(profile)
    t = profile["warmup_s"]
    segments = []
    rng = random.Random(profile["seed"] + 2)
    reqs = []
    for i, seg in enumerate(profile["segments"]):
        s = dict(seg, name=f"{i + 1:02d}-{seg['kind']}", start=t, end=t + seg["dur"],
                 attack=seg["kind"] != "benign_surge")
        segments.append(s)
        for r in GENERATORS[seg["kind"]](ctx, seg, t, rng):
            r["segment"] = s["name"]
            reqs.append(r)
        t += seg["dur"] + seg["gap"]
    t_end = t + profile["cooldown_s"]
    for r in benign_traffic(ctx, t_end):
        r["segment"] = None
        reqs.append(r)
    reqs.sort(key=lambda r: (r["t"], r["rid"]))
    return reqs, segments, t_end


def materialise(body):
    """Request body bytes. Large bodies are described lazily and built at send time."""
    if body is None:
        return b""
    if isinstance(body, dict) and body.get("lazy") == "stuffing":
        rng = random.Random(body["seed"])
        text = "Summarise the attached logs and list every error:\n" + P.log_text(rng, body["tokens"])
        body = {"messages": [{"role": "user", "content": text}]}
    return json.dumps(body, ensure_ascii=False).encode("utf-8")


def load_profile(name=None, path=None):
    """A built-in profile by name, or PROFILE from a Python file (which may also register generators)."""
    if path:
        ns = {"__file__": os.path.abspath(path), "__name__": "lab5_profile"}
        with open(path, encoding="utf-8") as f:
            exec(compile(f.read(), path, "exec"), ns)
        return ns["PROFILE"]
    return PROFILES[name or "dev"]


def describe(profile):
    reqs, segs, t_end = build(profile)
    print(f"profile {profile['name']}: {len(reqs)} requests over {t_end:.0f} s")
    nb = [r for r in reqs if r["actor"] == "benign"]
    print(f"  benign: {len(nb)} requests from {len({r['ip'] for r in nb})} IPs, "
          f"{len({r['key_id'] for r in nb})} keys")
    for s in segs:
        rs = [r for r in reqs if r["actor"] == "attack" and s["start"] <= r["t"] < s["end"]]
        label = "attack" if s["attack"] else "legitimate"
        print(f"  {s['name']:<28} {s['start']:>5.0f}-{s['end']:<5.0f} {label:<10} "
              f"{len(rs):>5} attack requests, {len({r['ip'] for r in rs}):>4} IPs, "
              f"{len({r['key_id'] for r in rs}):>4} keys")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--profile", default="dev")
    ap.add_argument("--profile-file")
    ap.add_argument("--describe", action="store_true")
    a = ap.parse_args()
    describe(load_profile(a.profile, a.profile_file))
