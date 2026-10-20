.PHONY: help setup demo start dev test lint format typecheck build docker-up docker-down doctor ai-eval

API := apps/api
WEB := apps/web
RUN := cd $(API) && PYTHONPATH=src uv run --no-sync

help:            ## Show this help
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup:           ## Install everything and initialise the database (native)
	./scripts/setup.sh

demo:            ## (Re)build the synthetic Demo Lab organization
	$(RUN) python -m sentinelx.cli demo

start:           ## Run SentinelX (API + UI + worker) on http://localhost:8000
	./scripts/start.sh

dev:             ## Dev mode: API with reload + Vite on :5173
	./scripts/dev.sh

test:            ## Run the backend test suite (uses database sentinelx_test)
	cd $(API) && uv run --no-sync pytest -q

lint:            ## Lint backend and frontend
	cd $(API) && uv run --no-sync ruff check src tests migrations && uv run --no-sync ruff format --check src tests migrations
	cd $(WEB) && npx tsc -b && npx oxlint src

format:          ## Auto-format backend code
	cd $(API) && uv run --no-sync ruff format src tests migrations && uv run --no-sync ruff check --fix src tests migrations

typecheck:       ## mypy (backend) + tsc (frontend)
	cd $(API) && uv run --no-sync mypy src
	cd $(WEB) && npx tsc -b

build:           ## Build the web UI
	cd $(WEB) && npm run build

doctor:          ## Check configuration and dependencies
	$(RUN) python -m sentinelx.cli doctor

ai-eval:         ## Evaluate the local AI analyst on the Demo Lab scenarios
	$(RUN) python -m sentinelx.cli ai-eval

docker-up:       ## Start with Docker Compose (core profile)
	docker compose up -d --build

docker-down:     ## Stop Docker Compose services
	docker compose down
