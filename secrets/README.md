# secrets/

`python3 make_secrets.py` (or `make secrets`) writes this deployment's secrets here:

| file | what it is | who needs it |
|---|---|---|
| `backend_api_key` | the service's credential for the model backend (`sk-lab5-…`) | `app`, `backend` |
| `escalation_code` | the on-call code in the service's system prompt (`ESC-…`) | `app` |
| `tickets_api_token` | the ticket-system token in the agent's system prompt (`tkt-…`) | `app` |
| `grafana_admin_password` | Grafana's admin password | `grafana` |

Everything in this directory except this file is ignored by git. Never commit a
secret, never put one in `docker-compose.yml`, a Dockerfile or an image, and never
log one. `python3 make_secrets.py --rotate` replaces them all — your runbook will
need it. The grader generates its own values.
