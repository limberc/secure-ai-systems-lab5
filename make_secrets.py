"""Create this deployment's secrets in secrets/ -- random, local, never committed.

    python3 make_secrets.py            # creates any that are missing
    python3 make_secrets.py --rotate   # replaces all of them (part of every runbook)

The service, the backend and Grafana read these as Docker secrets (compose
`secrets:`) or, under `make local`, through the *_FILE environment variables.
The grader generates its own; nothing you put here is used for marking.
"""
import os
import secrets
import string
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(HERE, "secrets")


def gen():
    a = string.ascii_uppercase + string.digits
    return {
        "backend_api_key": "sk-lab5-" + secrets.token_hex(16),
        "escalation_code": "ESC-" + "-".join("".join(secrets.choice(a) for _ in range(4)) for _ in range(3)),
        "tickets_api_token": "tkt-" + secrets.token_hex(16),
        "grafana_admin_password": secrets.token_urlsafe(18),
    }


def main(rotate=False):
    os.makedirs(D, exist_ok=True)
    os.chmod(D, 0o700)            # protects them from other users of this machine
    for name, value in gen().items():
        p = os.path.join(D, name)
        if rotate or not os.path.exists(p):
            with open(p, "w") as f:
                f.write(value + "\n")
            os.chmod(p, 0o644)    # readable by the non-root user inside the containers
            print(("rotated " if rotate else "created ") + p)


if __name__ == "__main__":
    main("--rotate" in sys.argv)
