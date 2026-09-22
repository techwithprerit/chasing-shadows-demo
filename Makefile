SHELL := /bin/bash
PY    := python3
PROFILE ?= stage

.DEFAULT_GOAL := help
.PHONY: help up down clean setup bootstrap load detect demo rehearse verify \
        snapshot-repo dashboards diagnose rollup logs reset reload

help:  ## show this help
	@echo ""
	@echo "  Chasing shadows with OpenSearch — demo"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "    \033[1m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  First run:   make up && make setup && make verify"
	@echo "  On stage:    make demo"
	@echo ""

up:  ## start OpenSearch + Dashboards
	@test -f .env || cp .env.example .env
	docker compose up -d
	@echo "  waiting for the cluster ..."
	@$(PY) -c "import sys; sys.path.insert(0,'bin'); from os_http import OS; OS().wait_until_ready(300)"

down:  ## stop the stack, keep the data
	docker compose down

clean:  ## stop the stack and delete all data
	docker compose down -v
	rm -rf data .demo-state.json

setup: bootstrap load detect  ## bootstrap + load + detect, end to end

bootstrap:  ## apply templates, scripts, pipeline, ISM
	$(PY) bin/bootstrap.py --profile $(PROFILE)

load:  ## generate and index the incident
	$(PY) bin/load.py --profile $(PROFILE) --keep-files

reload: bootstrap  ## wipe the data and rebuild everything cleanly
	$(PY) bin/load.py --profile $(PROFILE) --keep-files --fresh
	$(PY) bin/detect.py --wait

detect:  ## monitors, detector, Sigma rules, triage agent
	$(PY) bin/detect.py --wait

verify:  ## prove every demo step works (run this in the venue too)
	$(PY) bin/verify.py

demo:  ## the eight minutes, paused between steps
	$(PY) bin/demo.py

rehearse:  ## run the whole demo end to end without pausing
	$(PY) bin/demo.py --no-pause

rollup:  ## additionally create the slide-18 index rollup job
	$(PY) bin/bootstrap.py --profile $(PROFILE) --with-rollup

snapshot-repo:  ## register a local snapshot repo so the ISM cold state can run
	@curl -sS -X PUT "$${OPENSEARCH_URL:-http://localhost:9200}/_snapshot/s3-sec" \
	  -H 'Content-Type: application/json' \
	  -d '{"type":"fs","settings":{"location":"/usr/share/opensearch/snapshots","compress":true}}' \
	  | $(PY) -m json.tool

dashboards:  ## import the saved objects AND refresh their field lists
	$(PY) bin/dashboards.py

diagnose:  ## why is a panel empty / a step failing? read-only health report
	$(PY) bin/diagnose.py

logs:  ## tail the OpenSearch container
	docker compose logs -f opensearch
