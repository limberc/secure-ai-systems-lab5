"""The tenant contract: who may call the service, and on what terms.

config/tenants.json is the billing system's view of every customer. Keys are
stored only as SHA-256 hashes; a gateway hashes the bearer token it receives and
looks the hash up. The plaintext keys exist only in the load generator's key file.
"""
import hashlib
import json
import os

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TENANTS = os.path.join(HERE, "config", "tenants.json")


def key_hash(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def load_tenants(path=None):
    """Returns (tiers, tenants, keys_by_hash, platform).

    keys_by_hash maps sha256(key) -> {"key_id", "tenant", "tier"}.
    """
    with open(path or os.environ.get("TENANTS_PATH", DEFAULT_TENANTS), encoding="utf-8") as f:
        cfg = json.load(f)
    by_hash = {}
    for t in cfg["tenants"]:
        for k in t["keys"]:
            by_hash[k["sha256"]] = {"key_id": k["key_id"], "tenant": t["tenant"], "tier": t["tier"]}
    return cfg["tiers"], {t["tenant"]: t for t in cfg["tenants"]}, by_hash, cfg["platform"]


def read_secret(name, default=None):
    """A secret from NAME_FILE (a Docker secret) if set, else from NAME, else default."""
    path = os.environ.get(name + "_FILE")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    return os.environ.get(name, default)
