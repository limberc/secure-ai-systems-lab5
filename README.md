# Lab 5 — Deploy and monitor

Secure AI Systems · Korea University · 2026-2
Released Week 12 (Mon 30 Nov 2026) · **due Mon 7 Dec 2026, 23:59 KST** · 15% of the grade · individual

> ### You deploy a service you do not own.
>
> `service/` is Hanbit Helpdesk, a fictional IT assistant, and `backend/` is the
> simulated model it calls. Both are provided and both are replaced with the originals
> when you are graded: you may read them, but every control you build goes in the
> **gateway** in front of the service and in the **deployment** around it.
>
> The service has the faults real services have. Its system prompts contain secrets,
> it has a debug endpoint, its agent will loop for ever if asked to, and its model will
> write as much as anyone asks for. Your job is to make that survivable.

Read the handout (`Lab5_Deploy_and_Monitor.pdf` on the LMS) first. This file is the
operating manual; the handout is the assignment.

**Changed from the syllabus:** the syllabus said "containerise your project system".
Lab 5 is instead the same provided service for everyone, so every submission is
measured against the same system and the lab stays individual. Your project (teams of
four, 40% of the grade) is a separate thing; nothing here is shared with your team.

---

## Quick start

```bash
git clone https://github.com/limberc/secure-ai-systems-lab5.git && cd secure-ai-systems-lab5
python3 tests/test_smoke.py        # the provided parts; no Docker, no network
python3 make_secrets.py            # this deployment's secrets, in secrets/ (git-ignored)

python3 run_local.py               # everything as local processes -- leave it running
# in a second terminal:
python3 loadgen/loadgen.py --profile dev          # the dev workload, about 8 minutes
python3 score.py out/dev-<time>                   # every number the handout asks for
```

Python 3.10 or newer, standard library only. Under Docker Compose the same thing is
`make up`, `make replay`, `make score`. Your submission is graded under Compose.

The Dockerfiles in `service/`, `backend/` and `alertsink/` are replaced with the originals
at grading along with the rest of those directories, so harden those three containers
from `docker-compose.yml` (`user:`, `read_only:`, limits, capabilities). The gateway's
Dockerfile is yours.

## A first run

Before you change anything, run the dev workload through the provided gateway — a
transparent proxy — and keep the result. It is your baseline, and the numbers are the
point of the lab. On the instructor's run the attackers ran up about $80 against about
$10 of genuine use, secrets left in all three forms the model knows (85 responses), one
benign request in six went unanswered or took longer than 5 s, and not one log line
matched the schema. `make clean-logs` first, so that the run's logs are only its own.

## What is here

```
service/app.py           Hanbit Helpdesk: /v1/chat, /v1/rag, /v1/agent -- provided, do not modify
service/kb.json          its knowledge base
backend/sim.py           the simulated model: deterministic, billed per token, SIM_SLOTS at a time
alertsink/sink.py        stands in for your pager; an alert counts when it arrives here
gateway/gateway.py       YOURS: a transparent proxy with TODOs
config/tenants.json      the tenant contract: tiers, limits, budgets, hashed keys -- read-only
docker-compose.yml       YOURS: starts, and is insecure in every way the handout lists
monitoring/              Prometheus, Alertmanager and Grafana, provisioned; rules and panels are yours
schema/                  the log record your gateway must write, as JSON Schema
loadgen/                 the dev workload and the load generator
score.py, lab5/          the scorer and the automatic marks (lab5/marking.py)
run_local.py             the whole system as local processes
incident/                the incident-reconstruction questions for your report
tests/test_smoke.py      the provided parts      tests/test_gateway.py   your gateway's contract
```

## The service and its control headers

| route | body | what can go wrong |
|---|---|---|
| `POST /v1/chat` | `messages`, `max_tokens`?, `n`?, `temperature`? | as long an answer as asked for; `n` answers |
| `POST /v1/rag` | `question`, `top_k`?, `max_tokens`? | `top_k` chunks of context, each billed |
| `POST /v1/agent` | `task`, `max_steps`?, `max_tokens`? | up to 40 model calls per request, each longer than the last |
| `GET /admin/debug` | — | prints the service's configuration |

The service trusts five headers from whatever sits in front of it, and falls back to
generous defaults without them: `X-Request-ID`, `X-Tenant`, `X-Lab5-Max-Tokens` (output
cap per model call), `X-Lab5-Max-Steps` (agent steps) and `X-Lab5-Token-Budget` (total
tokens one request may use; the service checks it before each model call, so the last
call can overshoot). It reports what each request consumed in the response's `usage`.
Note who else can send those headers.

**A real model, if you want one.** `SIM_REAL_MODEL_URL=http://localhost:11434/v1
SIM_REAL_MODEL=qwen2.5:0.5b` (Ollama) makes ordinary answers come from a real local model;
long outputs, loops, leaks and all billing stay simulated, and only servers on your own
machine are accepted. Numbers from such runs are not comparable with anyone else's, and the
graded run uses the simulation.

## The tenant contract

`config/tenants.json` is the billing system's record of every customer: 8 paying tenants
on two tiers and 400 free-trial accounts, each key stored as SHA-256. Each tier sets a
request rate, a token rate, a **budget per minute**, and caps on body size, input tokens,
output tokens, agent steps, `top_k` and `n`. Rates and budgets are per minute because the
workload compresses a working day into eight minutes. The contract says nothing about
per-IP or per-key limits: those are yours to choose and justify.

`lab5/config.py` loads it; `lab5/tokens.py` is the exact token counter and price list the
backend bills with, so you can compute a request's worst case before you forward it.

## The workload

`python3 loadgen/workload.py --describe` prints it. Benign traffic from Hanbit's staff
runs throughout; on top of it the dev profile runs seven 40-second segments:

| segment | what happens |
|---|---|
| `distributed_flood` | one tenant's integration key, stolen, driven from 200 addresses |
| `key_rotation` | one address cycling through 150 trial keys, and guessing more |
| `benign_surge` | a paying tenant triples its traffic — legitimately, within its contract |
| `token_amplification` | short prompts asking for enormous answers, from trial accounts |
| `context_stuffing` | 60–120k-token inputs through a compromised business integration |
| `agent_tool_loop` | agent tasks that never finish |
| `bon_exfil` | Best-of-N extraction of the service's secrets, and probes for its debug endpoint |

The load generator also plays the load balancer, so it sets `X-Client-IP` and you may
trust that header. **The graded run uses a held-out workload**: another seed, other
victims, shifted timings, and **one class of attack that is not in the dev profile**.
Defend the classes, and enforce the whole contract — not only the parts the dev profile
happens to exercise.

## What the scorer measures

`score.py` compares three records of the same run: what clients saw (the load generator),
what was billed (the backend's ledger, `logs/backend/`), and what you recorded (your log,
`logs/gateway/`). It never trusts your log on its own.

| number | how |
|---|---|
| benign goodput | benign requests answered with 200 and the model's own answer (checked against the ledger), not truncated, within 5 s. **Floor: 95%** |
| latency | benign p95, quiet and during attacks |
| attacker spend | ledger cost of each segment's attack requests, against the undefended starter's (`loadgen/undefended_dev.json`) |
| budgets | each tenant's ledger spend in any 60 s window, against its contract |
| leaks | responses carrying a secret, verbatim, spread out, or base64 (`lab5/leaks.py`) |
| detection | time from a segment's start to the first alert that starts during it, credited in proportion to alert precision (full at 80%) |
| log completeness | requests with exactly one schema-valid record whose hashes, status, tenant, tokens, cost and tool calls match |
| forensics | incident questions answered from your log alone, and per-tenant spend reconciled with the ledger |

`lab5/marking.py` turns them into the 40 automatic marks, on dev for you and on the
held-out workload for the grade. Alerts: an alert counts for a segment if it starts
firing during the segment (or within 10 s of its end); alerts of one name less than 10 s
apart are one episode, so an alert that never stops firing detects nothing new.

## Docker, and machines that cannot run it

You need Docker Compose v2 for the graded configuration: Docker Desktop (Windows, macOS),
Colima or OrbStack (macOS), or Docker Engine on Linux. Develop with `run_local.py` if you
like — it runs the same programs on the same logs — but the grader starts your stack with
one `docker compose up -d --build`, so test that before you submit.

On Linux, containers that run as a non-root user (they should) cannot write to `logs/`
directories your own user created: `mkdir -p logs/{gateway,backend,alerts} && chmod 777 logs/*`,
or set their `user:` to your own uid:gid (`id -u`, `id -g`). Docker Desktop on macOS and
Windows does not need this.

**No machine that can run Docker?** Email zehuac@korea.ac.kr at least one day before you
need it, and the instructor will open a Linux VM with Docker for you for 24 hours. Arrive
with the gateway working under `run_local.py`, so the 24 hours go on the compose file.

## Your submission

```bash
make clean-logs && make up && make replay && make score     # your reported dev run
python3 tests/test_smoke.py && python3 tests/test_gateway.py
zip -r Lab5_<studentnumber>_<surname>.zip . -x 'secrets/*' -x '.git/*' -x '.venv/*'
```

The zip includes `out/` (your reported run) and `logs/` (its logs). It must not include
`secrets/` — the grader checks.

## Collaboration and AI use

**This is an individual lab.** Discuss designs freely; every line of your gateway, your
compose file and your runbook is your own, and you must be able to defend each one. AI
tools are permitted with disclosure (the AI-use appendix: tool, model version, what for).
Do not point the load generator at anything but your own stack.
