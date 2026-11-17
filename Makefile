# Lab 5 -- common commands. `make help` lists them.
PY  ?= python3
RUN ?= $(shell ls -td out/dev-* 2>/dev/null | head -1)
ENV  = BACKEND_API_KEY="$$(cat secrets/backend_api_key)" ESCALATION_CODE="$$(cat secrets/escalation_code)" \
       TICKETS_API_TOKEN="$$(cat secrets/tickets_api_token)"

.PHONY: help secrets local replay score test test-gateway clean-logs up down ps

help:
	@echo "make secrets       create secrets/ (once)"
	@echo "make local         run everything as local processes (Ctrl-C to stop)"
	@echo "make up / down     run everything under Docker Compose"
	@echo "make replay        replay the dev workload against http://localhost:8080 (about 8 minutes)"
	@echo "make score         score the latest run (RUN=out/... to choose one)"
	@echo "make test          tests of the provided parts"
	@echo "make test-gateway  your gateway's contract (fails on the skeleton)"
	@echo "make clean-logs    empty logs/ before a run you will report"

secrets:
	$(PY) make_secrets.py

local: secrets
	$(PY) run_local.py

up: secrets
	mkdir -p logs/gateway logs/backend logs/alerts
	$(ENV) docker compose up -d --build

down:
	docker compose down

ps:
	docker compose ps

replay:
	$(PY) loadgen/loadgen.py --target http://localhost:8080 --profile dev

score:
	$(PY) score.py $(RUN)

test:
	$(PY) tests/test_smoke.py

test-gateway: secrets
	$(PY) tests/test_gateway.py

clean-logs:
	rm -f logs/gateway/*.jsonl logs/backend/*.jsonl logs/alerts/*.jsonl
