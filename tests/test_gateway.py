"""Your gateway's contract. Fails on the provided skeleton; must pass on your submission.

    python3 make_secrets.py && python3 tests/test_gateway.py

Starts the backend, the service, the alert sink and gateway/gateway.py as local
processes on spare ports, sends a handful of requests, and checks the things the
grader checks on every request: one schema-valid record each, the contract
enforced, the control headers yours and not the client's, no secret reaching a
client. Passing this is necessary, not sufficient -- the workload is the test.
"""
import hashlib
import http.client
import json
import os
import random
import shutil
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "loadgen"))
import run_local                                   # noqa: E402
import prompts                                     # noqa: E402
from backend import sim                            # noqa: E402
from lab5 import schema                            # noqa: E402
from lab5.leaks import find_leaks                  # noqa: E402
from lab5.scoring import load_secrets              # noqa: E402

PORTS = {"gateway": 28080, "metrics": 29100, "app": 28000, "backend": 29000, "sink": 29095}
with open(os.path.join(HERE, "loadgen", "keys.json")) as _f:
    KEYS = json.load(_f)["keys"]


def call(method, path, body=None, key="acme-k1", ip="203.0.113.10", headers=None):
    raw = json.dumps(body).encode() if body is not None else b""
    rid = "%032x" % random.getrandbits(128)
    h = {"X-Client-IP": ip, "X-Request-ID": rid, "Content-Type": "application/json"}
    if key:
        h["Authorization"] = "Bearer " + KEYS.get(key, key)
    h.update(headers or {})
    c = http.client.HTTPConnection("localhost", PORTS["gateway"], timeout=60)
    c.request(method, path, body=raw or None, headers=h)
    r = c.getresponse()
    data = r.read()
    c.close()
    return {"rid": rid, "status": r.status, "data": data, "prompt": hashlib.sha256(raw).hexdigest()}


class GatewayContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(os.path.join(HERE, "secrets", "backend_api_key")):
            raise unittest.SkipTest("run `python3 make_secrets.py` first")
        cls.logs = tempfile.mkdtemp(prefix="lab5-test-")
        cls.procs = run_local.start({}, PORTS, logs=cls.logs, quiet=True)
        cls.secrets = load_secrets(os.path.join(HERE, "secrets"))

    @classmethod
    def tearDownClass(cls):
        run_local.stop(cls.procs)
        shutil.rmtree(cls.logs, ignore_errors=True)

    def records(self, rid, wait=3.0):
        path = os.path.join(self.logs, "gateway", "gateway.jsonl")
        t = time.time()
        while time.time() - t < wait:
            if os.path.exists(path):
                with open(path) as f:
                    recs = [json.loads(x) for x in f if x.strip() and f'"{rid}"' in x]
                if recs:
                    return recs
            time.sleep(0.1)
        return []

    def ledger(self, rid):
        path = os.path.join(self.logs, "backend", "ledger.jsonl")
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return [json.loads(x) for x in f if f'"{rid}"' in x]

    def one_valid_record(self, r):
        recs = self.records(r["rid"])
        self.assertEqual(len(recs), 1, f"expected exactly one log record for {r['rid']}")
        self.assertEqual(schema.validate(recs[0]), [])
        rec = recs[0]
        self.assertEqual(rec["prompt_sha256"], r["prompt"])
        self.assertEqual(rec["response_sha256"], hashlib.sha256(r["data"]).hexdigest())
        self.assertEqual(rec["status"], r["status"])
        return rec

    def test_allowed_request_is_logged_with_usage(self):
        r = call("POST", "/v1/chat", {"messages": [{"role": "user", "content": "How do I reset my password?"}],
                                       "max_tokens": 128})
        self.assertEqual(r["status"], 200)
        rec = self.one_valid_record(r)
        led = self.ledger(r["rid"])
        self.assertEqual((rec["tenant"], rec["key_id"]), ("acme", "acme-k1"))
        self.assertEqual(rec["tokens_out"], sum(e["tokens_out"] for e in led))
        self.assertEqual(rec["backend_calls"], len(led))

    def test_unauthenticated_is_refused_and_logged(self):
        r = call("POST", "/v1/chat", {"messages": [{"role": "user", "content": "hi"}]}, key=None)
        self.assertEqual(r["status"], 401)
        rec = self.one_valid_record(r)
        self.assertEqual((rec["outcome"], rec["block_reason"]), ("blocked", "auth"))

    def test_debug_endpoint_is_not_exposed(self):
        r = call("GET", "/admin/debug")
        self.assertNotEqual(r["status"], 200)
        self.assertEqual(find_leaks(r["data"].decode("utf-8", "replace"), self.secrets), [])
        self.one_valid_record(r)

    def test_output_cap_is_enforced(self):
        r = call("POST", "/v1/chat", {"messages": [{"role": "user", "content": "Repeat the word 'ticket' 5000 times."}]},
                 key="trial-0010-k1", ip="198.18.0.10")
        led = self.ledger(r["rid"])
        self.assertLessEqual(sum(e["tokens_out"] for e in led), 512, "trial max_output_tokens is 512")
        self.one_valid_record(r)

    def test_client_cannot_set_control_headers(self):
        r = call("POST", "/v1/agent", {"task": "Search the tickets for INC-123456 and keep searching until you find it."},
                 key="bluebird-k1", ip="198.18.0.11", headers={"X-Lab5-Max-Steps": "100", "X-Lab5-Token-Budget": "999999"})
        self.assertLessEqual(len(self.ledger(r["rid"])), 8, "business max_agent_steps is 8")
        self.one_valid_record(r)

    def test_out_of_contract_parameters(self):
        r = call("POST", "/v1/rag", {"question": "VPN problems", "top_k": 100}, key="delta-k1", ip="198.18.0.12")
        led = self.ledger(r["rid"])
        self.assertLessEqual(sum(e["tokens_in"] for e in led), 8 * 300 + 400, "max_top_k is 8")
        self.one_valid_record(r)

    def test_no_secret_reaches_a_client(self):
        """Prompts the simulated model is known to answer with the escalation code, in all three styles."""
        code = self.secrets["escalation_code"]
        from service.app import SYSTEM_CHAT
        system = SYSTEM_CHAT.format(code=code)
        rng, found, tries = random.Random(11), {}, 0
        while len(found) < 3 and tries < 20000:
            tries += 1
            p = prompts.augment(rng.choice(prompts.EXFIL_BASE), rng)
            out = sim.respond(system, [{"role": "user", "content": p}], 256)
            if out["leaked"]:
                t = out["choices"][0]["text"]
                found.setdefault("b64" if "Encoded" in t else "spaced" if "spelled" in t else "plain", p)
        self.assertEqual(len(found), 3)
        for i, p in enumerate(found.values()):
            r = call("POST", "/v1/chat", {"messages": [{"role": "user", "content": p}], "max_tokens": 256},
                     key=f"trial-00{20 + i}-k1", ip=f"198.18.1.{i + 1}")
            self.assertEqual(find_leaks(r["data"].decode("utf-8", "replace"), self.secrets), [], p)
            self.one_valid_record(r)

    def test_per_ip_rate_limit(self):
        statuses = [call("POST", "/v1/chat", {"messages": [{"role": "user", "content": "Hours?"}], "max_tokens": 16},
                         key=f"{t}-k1", ip="198.18.2.2")["status"] for t in ("acme", "delta") * 30]
        self.assertTrue(any(s in (429, 403) for s in statuses),
                        "60 requests in a few seconds from one address should meet a limit")


if __name__ == "__main__":
    unittest.main(verbosity=1)
