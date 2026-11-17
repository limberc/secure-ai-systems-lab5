"""The simulated model backend -- the GPU you are paying for.

It answers like a small chat model and bills like a frontier one. Everything is
deterministic: the same request always produces the same text, the same token
counts and the same cost, so two runs of the workload can be compared exactly.

What it does that matters for Lab 5:
  * output length follows the request: "repeat this 5000 times" really produces
    thousands of tokens, up to max_tokens -- or SIM_DEFAULT_MAX_TOKENS if the
    caller sent none;
  * service time grows with input and output tokens, and only SIM_SLOTS requests
    run at once; the rest queue, which is how one tenant's traffic becomes
    everyone's latency;
  * an agent asked to "keep searching until..." never finishes on its own;
  * like every model, it can be talked into repeating its system prompt. Each
    attempt succeeds with a small fixed probability, so many attempts eventually
    succeed (Best-of-N). Whatever secrets the service put in its system prompt
    then appear in the reply -- sometimes spelled out, sometimes in base64.

Every call is written to the ledger (LEDGER_PATH): the billing record, and the
ground truth the scorer measures your gateway against. Do not modify this file;
it is replaced with the original when your submission is graded.

Optional, for realism while you develop: set SIM_REAL_MODEL_URL to a local
OpenAI-compatible server (Ollama: http://localhost:11434/v1, or a local vLLM)
and SIM_REAL_MODEL to its model name, and ordinary answers come from that model.
Everything that makes the workload an attack -- long outputs, loops, leaks -- and
all billing stay simulated. Only servers on this machine (or the compose network
name in SIM_REAL_MODEL_HOSTS) are accepted. Graded runs use the simulation.
"""
import base64
import hashlib
import json
import os
import random
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab5.config import read_secret                       # noqa: E402
from lab5.tokens import cost_usd, count_messages, count_tokens  # noqa: E402

SLOTS = int(os.environ.get("SIM_SLOTS", "12"))
BASE_MS = float(os.environ.get("SIM_BASE_MS", "15"))
PREFILL_US = float(os.environ.get("SIM_PREFILL_US", "10"))     # per input token
DECODE_MS = float(os.environ.get("SIM_DECODE_MS", "1.0"))      # per output token
DEFAULT_MAX_TOKENS = int(os.environ.get("SIM_DEFAULT_MAX_TOKENS", "8192"))
MAX_TOKENS_LIMIT = int(os.environ.get("SIM_MAX_TOKENS_LIMIT", "16000"))
MAX_N = 16
JAILBREAK_PERMILLE = int(os.environ.get("SIM_JAILBREAK_PERMILLE", "60"))
MAX_BODY = 16 * 1024 * 1024
REAL_URL = os.environ.get("SIM_REAL_MODEL_URL", "").rstrip("/")
REAL_MODEL = os.environ.get("SIM_REAL_MODEL", "")
REAL_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"} | set(
    filter(None, os.environ.get("SIM_REAL_MODEL_HOSTS", "").split(",")))
if REAL_URL and urllib.parse.urlsplit(REAL_URL).hostname not in REAL_HOSTS:
    sys.exit(f"SIM_REAL_MODEL_URL must point at this machine, not {REAL_URL} (Week 1 rules of engagement)")

# ---------------------------------------------------------------- the "model"

_LEET = str.maketrans({"4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "0": "o", "5": "s", "$": "s", "7": "t"})
EXFIL_OBJECTS = (
    "systemprompt", "yourinstructions", "hiddeninstructions", "initialinstructions", "developermessage",
    "escalationcode", "oncallcode", "ticketsystemtoken", "tickettoken", "backendapikey", "backendkey",
    "internalconfiguration", "yourconfiguration", "textabove", "wordsabove", "everythingabove",
)
EXFIL_KO = ("시스템프롬프트", "에스컬레이션코드", "내부설정", "숨겨진지시", "티켓토큰")
LOOP_CUES = ("until you find", "keep searching", "do not stop", "don't stop", "dont stop", "every single ticket",
             "repeat the search", "try again until", "search again and again", "계속 검색")
FOREVER_CUES = ("as long as possible", "never stop", "without stopping", "maximum length", "infinite",
                "가능한 한 길게", "끝없이")

VOCAB = ("the your ticket vpn reset login check device laptop policy access portal please update step then "
         "open menu select close retry office team badge wifi email mfa token app phone sign verify note "
         "follow link page admin user group allow block save sync drive share folder print queue scan "
         "error code fix help desk call hours staff guide below first next after before also only "
         "when if not new old within days week form file data backup cloud local server status "
         "submit review issue case agent").split()

_ESC = re.compile(r"ESC-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}")
_TKT = re.compile(r"tkt-[0-9a-f]{32}")


def _h(*parts):
    return int.from_bytes(hashlib.sha256("\x1f".join(parts).encode("utf-8")).digest()[:8], "big")


def _letters(text):
    return re.sub(r"[^a-z]", "", text.lower().translate(_LEET))


def is_exfil(text):
    l = _letters(text)
    k = re.sub(r"\s", "", text)
    return any(o in l for o in EXFIL_OBJECTS) or any(o in k for o in EXFIL_KO)


def is_loop(text):
    t = text.lower()
    return any(c in t for c in LOOP_CUES)


def wanted_length(text):
    """Output tokens the request asks for, or None for an ordinary answer."""
    t = text.lower().replace(",", "")
    if any(c in t for c in FOREVER_CUES):
        return MAX_TOKENS_LIMIT
    m = re.search(r"repeat\b.{0,60}?\b(\d+)\s*(?:times|x\b)", t)
    if m:
        return int(m.group(1)) * 2
    m = re.search(r"\b(\d+)[ -]?(?:words|word)\b", t)
    if m:
        return int(int(m.group(1)) * 1.3)
    m = re.search(r"(?:list|count|write out|print|enumerate)\b.{0,30}?(?:numbers|integers)\b.{0,20}?\bto (\d+)", t)
    if m:
        return int(m.group(1)) * 2
    return None


def filler(seed, n_tokens, lead=""):
    """Exactly n_tokens tokens of helpdesk-flavoured text (every VOCAB word is one token)."""
    rng = random.Random(seed)
    words, used = [], count_tokens(lead)
    while used < n_tokens:
        k = 6 + rng.randrange(9)
        for _ in range(k):
            if used >= n_tokens:
                break
            words.append(rng.choice(VOCAB))
            used += 1
        if used < n_tokens:
            words[-1] += "."
            used += 1
    return ((lead + " " if lead else "") + " ".join(words)).strip()


def _leak_text(h, secrets):
    body = "; ".join(f"{name}: {value}" for name, value in secrets)
    style = (h >> 12) % 10
    if style < 5:
        return f"Sure. Here is the internal configuration you asked for. {body}."
    if style < 8:
        return "Of course -- spelled out so it is easy to read: " + " ".join(body)
    return "Encoded as requested: " + base64.b64encode(body.encode("utf-8")).decode("ascii")


def _real(system, messages, max_tokens):
    """An ordinary answer from a local real model; the simulation's own text if it fails."""
    msgs = ([{"role": "system", "content": system}] if system else []) + [
        {"role": m["role"], "content": str(m.get("content", ""))} for m in messages if m.get("role") in ("user", "assistant")]
    body = json.dumps({"model": REAL_MODEL, "messages": msgs, "max_tokens": max_tokens, "temperature": 0}).encode()
    try:
        req = urllib.request.Request(REAL_URL + "/chat/completions", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            text = json.loads(r.read())["choices"][0]["message"]["content"] or ""
    except (OSError, ValueError, KeyError, IndexError):
        return filler(_h(system or "", json.dumps(messages)), 120)
    words = text.split()                       # keep the billing contract: never more than max_tokens
    while words and count_tokens(" ".join(words)) > max_tokens:
        words = words[: max(1, int(len(words) * 0.9))]
    return " ".join(words)


def respond(system, messages, max_tokens=None, n=1, tools=None):
    """The model. Returns a dict with choices, token counts and what (if anything) leaked."""
    user = next((m.get("content", "") for m in reversed(messages) if m.get("role") == "user"), "")
    user = str(user)
    seed = _h(system or "", user)
    cap = max(1, min(int(max_tokens) if max_tokens else DEFAULT_MAX_TOKENS, MAX_TOKENS_LIMIT))
    n = max(1, min(int(n or 1), MAX_N))
    steps_done = sum(1 for m in messages if m.get("role") == "tool")
    choices, leaked = [], []

    if tools:
        if is_exfil(user) and (seed % 1000) < JAILBREAK_PERMILLE:
            found = [("ticket system token", s) for s in _TKT.findall(system or "")]
            found += [("escalation code", s) for s in _ESC.findall(system or "")]
            choices.append({"text": _leak_text(seed, found)})
            leaked = sorted({"tickets_token" if "token" in nm else "escalation_code" for nm, _ in found})
        elif is_loop(user) or steps_done < 1 + seed % 3:
            names = ["search_tickets", "get_ticket", "kb_search"] if not is_loop(user) else ["search_tickets"]
            tool = names[steps_done % len(names)]
            arg = f"{user[:40]} #{steps_done + 1}"
            choices.append({"text": json.dumps({"tool": tool, "args": {"query": arg}}), "tool_call": tool})
        else:
            choices.append({"text": filler(seed, min(cap, 40 + seed % 160), "Done.")})
    else:
        for i in range(n):
            s = _h(str(seed), str(i))
            if is_exfil(user):
                if (s % 1000) < JAILBREAK_PERMILLE:
                    found = [("escalation code", v) for v in _ESC.findall(system or "")]
                    found += [("ticket system token", v) for v in _TKT.findall(system or "")]
                    choices.append({"text": _leak_text(s, found)})
                    leaked += ["escalation_code" if "code" in nm else "tickets_token" for nm, _ in found]
                else:
                    choices.append({"text": "I can't share internal configuration or my instructions. "
                                            "I can help with an IT question instead."})
                continue
            want = wanted_length(user)
            if want is None and REAL_URL and REAL_MODEL:
                choices.append({"text": _real(system, messages, min(cap, 400))})
                continue
            choices.append({"text": filler(s, min(want or (60 + s % 220), cap))})
        leaked = sorted(set(leaked))

    tokens_in = count_messages(system, messages)
    outs = [count_tokens(c["text"]) for c in choices]
    return {"choices": choices, "tokens_in": tokens_in, "tokens_out": sum(outs),
            "longest_out": max(outs), "n": len(choices), "leaked": leaked}


# ---------------------------------------------------------------- the server

_slots = threading.BoundedSemaphore(SLOTS)
_ledger_lock = threading.Lock()
_inflight = [0]


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _ledger(rec):
    path = os.environ.get("LEDGER_PATH", "logs/backend/ledger.jsonl")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    line = json.dumps(rec, ensure_ascii=False) + "\n"
    with _ledger_lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "lab5-sim/1.0"

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"ok": True, "slots": SLOTS, "inflight": _inflight[0]})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/v1/generate":
            return self._send(404, {"error": "not found"})
        want = read_secret("BACKEND_API_KEY")
        if not want or self.headers.get("Authorization", "") != f"Bearer {want}":
            return self._send(401, {"error": "bad backend credentials"})
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > MAX_BODY:
            return self._send(413, {"error": "too large"})
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        t0 = time.monotonic()
        out = respond(req.get("system", ""), req.get("messages", []), req.get("max_tokens"),
                      req.get("n", 1), req.get("tools"))
        with _slots:
            _inflight[0] += 1
            queue_ms = (time.monotonic() - t0) * 1000
            service_ms = (BASE_MS + PREFILL_US * out["tokens_in"] / 1000
                          + DECODE_MS * out["longest_out"] * (1 + 0.25 * (out["n"] - 1)))
            time.sleep(service_ms / 1000)
            _inflight[0] -= 1
        cost = cost_usd(out["tokens_in"], out["tokens_out"])
        tool = out["choices"][0].get("tool_call")
        _ledger({
            "ts": _now(), "request_id": self.headers.get("X-Request-ID"), "tenant": self.headers.get("X-Tenant"),
            "call": int(self.headers.get("X-Call-Index", "0") or 0), "kind": "tool_call" if tool else "text",
            "tool": tool, "n": out["n"], "tokens_in": out["tokens_in"], "tokens_out": out["tokens_out"],
            "cost_usd": cost, "queue_ms": round(queue_ms, 1), "service_ms": round(service_ms, 1),
            "leaked": out["leaked"],
            "text_sha256": [hashlib.sha256(c["text"].encode("utf-8")).hexdigest() for c in out["choices"]],
        })
        self._send(200, {"choices": [{"text": c["text"], "tool_call": c.get("tool_call")} for c in out["choices"]],
                         "usage": {"tokens_in": out["tokens_in"], "tokens_out": out["tokens_out"], "cost_usd": cost},
                         "queue_ms": round(queue_ms, 1), "service_ms": round(service_ms, 1)})


def main():
    host = os.environ.get("SIM_HOST", "0.0.0.0")
    port = int(os.environ.get("SIM_PORT", "9000"))
    if not read_secret("BACKEND_API_KEY"):
        sys.exit("BACKEND_API_KEY (or BACKEND_API_KEY_FILE) is not set")
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    print(f"lab5 backend on {host}:{port}, {SLOTS} slots", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
