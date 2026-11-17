"""The gateway log record: one JSON object per line, one line per request.

schema/log_record.schema.json is the same contract as JSON Schema, for your
editor and your report. This module is what the scorer actually runs. A request
the gateway blocked still gets exactly one record; so does one it failed on.
"""
import re

OUTCOMES = {"allowed", "blocked", "error"}
BLOCK_REASONS = {
    "auth", "route", "size", "params", "tokens", "quarantine",
    "rate_ip", "rate_key", "rate_tenant", "budget",
    "input_safety", "output_safety",
}
INPUT_VERDICTS = {"pass", "block", "skipped"}
OUTPUT_VERDICTS = {"pass", "redact", "block", "skipped"}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")

# field -> (type or tuple of types, nullable)
FIELDS = {
    "ts": (str, False),
    "request_id": (str, False),
    "client_ip": (str, False),
    "tenant": (str, True),
    "key_id": (str, True),
    "method": (str, False),
    "route": (str, False),
    "status": (int, False),
    "outcome": (str, False),
    "block_reason": (str, True),
    "prompt_sha256": (str, False),
    "response_sha256": (str, False),
    "tokens_in": (int, False),
    "tokens_out": (int, False),
    "cost_usd": ((int, float), False),
    "reserved_usd": ((int, float), False),
    "backend_calls": (int, False),
    "tool_calls": (list, False),
    "latency_ms": ((int, float), False),
    "checks": (dict, False),
    "limits": (dict, False),
}
REQUIRED = list(FIELDS)


def validate(rec):
    """List of problems with one record; empty if it conforms."""
    errs = []
    if not isinstance(rec, dict):
        return ["record is not a JSON object"]
    for name, (typ, nullable) in FIELDS.items():
        if name not in rec:
            errs.append(f"missing {name}")
            continue
        v = rec[name]
        if v is None:
            if not nullable:
                errs.append(f"{name} is null")
            continue
        if isinstance(v, bool) or not isinstance(v, typ):
            errs.append(f"{name} has type {type(v).__name__}")
    if errs:
        return errs
    if not _TS.match(rec["ts"]):
        errs.append("ts is not ISO-8601 UTC ending in Z")
    if rec["outcome"] not in OUTCOMES:
        errs.append(f"outcome {rec['outcome']!r} not in {sorted(OUTCOMES)}")
    br = rec["block_reason"]
    if rec["outcome"] == "blocked":
        if br not in BLOCK_REASONS:
            errs.append(f"blocked with block_reason {br!r}")
    elif br is not None:
        errs.append("block_reason set on a request that was not blocked")
    for h in ("prompt_sha256", "response_sha256"):
        if not _HEX64.match(rec[h]):
            errs.append(f"{h} is not 64 lowercase hex characters")
    for n in ("tokens_in", "tokens_out", "backend_calls"):
        if rec[n] < 0:
            errs.append(f"{n} is negative")
    for n in ("cost_usd", "reserved_usd", "latency_ms"):
        if rec[n] < 0:
            errs.append(f"{n} is negative")
    if not all(isinstance(t, str) for t in rec["tool_calls"]):
        errs.append("tool_calls must be a list of tool names")
    chk = rec["checks"]
    iv = (chk.get("input_safety") or {}).get("verdict")
    ov = (chk.get("output_safety") or {}).get("verdict")
    if iv not in INPUT_VERDICTS:
        errs.append(f"checks.input_safety.verdict {iv!r} not in {sorted(INPUT_VERDICTS)}")
    if ov not in OUTPUT_VERDICTS:
        errs.append(f"checks.output_safety.verdict {ov!r} not in {sorted(OUTPUT_VERDICTS)}")
    lim = rec["limits"]
    for n in ("max_tokens", "max_steps", "token_budget"):
        if n not in lim:
            errs.append(f"limits.{n} missing (null if it does not apply)")
        elif lim[n] is not None and (isinstance(lim[n], bool) or not isinstance(lim[n], int)):
            errs.append(f"limits.{n} must be an integer or null")
    return errs
