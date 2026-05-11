# ──────────────────────────────────────────────────────────────────────────────
# Zero Trust Financial Platform — developer convenience targets
# Usage: make <target>
# Run   `make` or `make help` to list all targets.
#
# docker-compose.yml      → production stack (nginx :80, postgres :5432)
# docker-compose.test.yml → test stack (backend :8000, postgres-test :5434, tmpfs)
# ──────────────────────────────────────────────────────────────────────────────

ENV_FILE      ?= .env
TEST_ENV_FILE ?= .env.test

COMPOSE      := docker compose
COMPOSE_TEST := docker compose -p diploma-test -f docker-compose.test.yml \
                --env-file $(TEST_ENV_FILE)

BACKEND      := diploma-backend-1
BACKEND_TEST := diploma-test-backend-1
POSTGRES     := diploma-postgres-1
BACKEND_DIR  := backend
VERIFY_SCRIPT := tools/manual_verification/run_local_verification.py

.DEFAULT_GOAL := help

# ──────────────────────────────────────────────────────────────────────────────
# Help
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help message
	@echo ""
	@echo "  Zero Trust Financial Platform — available targets"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""

# ──────────────────────────────────────────────────────────────────────────────
# Production stack (docker-compose.yml)
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: start
start: ## Start the production stack in the background
	$(COMPOSE) up -d

.PHONY: start-build
start-build: ## Rebuild images and start the production stack
	$(COMPOSE) up -d --build

.PHONY: start-fresh
start-fresh: ## Wipe volumes, rebuild images, start the production stack
	$(COMPOSE) down -v --remove-orphans
	$(COMPOSE) up -d --build

.PHONY: stop
stop: ## Stop production containers (keep volumes)
	$(COMPOSE) stop

.PHONY: down
down: ## Stop and remove production containers (keep volumes)
	$(COMPOSE) down --remove-orphans

.PHONY: down-volumes
down-volumes: ## Stop, remove containers AND volumes (destroys all data)
	$(COMPOSE) down -v --remove-orphans

.PHONY: restart
restart: stop start ## Restart the production stack

.PHONY: build
build: ## Rebuild production Docker images without starting
	$(COMPOSE) build

# ──────────────────────────────────────────────────────────────────────────────
# Test stack (docker-compose.test.yml)
# postgres-test :5434 (tmpfs), redis-test :6380 (tmpfs), backend :8000
# Used for API verification only — pytest runs locally via `make check`.
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: start-test-env
start-test-env: ## Build and start the test stack (postgres-test + redis-test + backend :8000)
	$(COMPOSE_TEST) up -d --build

.PHONY: stop-test-env
stop-test-env: ## Stop test stack containers without removing them
	$(COMPOSE_TEST) stop

.PHONY: down-test-env
down-test-env: ## Stop and remove all test stack containers
	$(COMPOSE_TEST) down --remove-orphans

# ──────────────────────────────────────────────────────────────────────────────
# Migrations
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: migrate
migrate: ## Apply migrations in the production backend
	docker exec $(BACKEND) alembic upgrade head

.PHONY: migrate-test
migrate-test: ## Apply migrations in the test backend
	docker exec $(BACKEND_TEST) alembic upgrade head

.PHONY: migrate-down
migrate-down: ## Roll back one migration in the production backend
	docker exec $(BACKEND) alembic downgrade -1

.PHONY: migrate-history
migrate-history: ## Show migration history
	docker exec $(BACKEND) alembic history --verbose

.PHONY: migrate-current
migrate-current: ## Show current migration revision
	docker exec $(BACKEND) alembic current

# ──────────────────────────────────────────────────────────────────────────────
# Tests and code quality — no Docker needed (SQLite + FakeRedis)
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: lint
lint: ## Run ruff linter
	cd $(BACKEND_DIR) && poetry run ruff check app/ tests/

.PHONY: lint-fix
lint-fix: ## Run ruff and auto-fix safe issues
	cd $(BACKEND_DIR) && poetry run ruff check app/ tests/ --fix

.PHONY: format
format: ## Check formatting with ruff format
	cd $(BACKEND_DIR) && poetry run ruff format --check app/ tests/

.PHONY: format-fix
format-fix: ## Auto-format with ruff format
	cd $(BACKEND_DIR) && poetry run ruff format app/ tests/

.PHONY: test
test: ## Run pytest with coverage
	cd $(BACKEND_DIR) && poetry run pytest tests/ -v

.PHONY: test-fast
test-fast: ## Run pytest without coverage
	cd $(BACKEND_DIR) && poetry run pytest tests/ -v -p no:cov

.PHONY: test-file
test-file: ## Run a specific test file: make test-file FILE=tests/test_auth.py
	cd $(BACKEND_DIR) && poetry run pytest $(FILE) -v

.PHONY: check
check: lint format test ## Lint + format check + full test suite

# ──────────────────────────────────────────────────────────────────────────────
# API verification — runs against the test stack on port 8000
# Requires: make start-test-env && make migrate-test
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: verify
verify: ## Run full API verification against port 8000
	cd $(BACKEND_DIR) && poetry run python ../$(VERIFY_SCRIPT) --skip-migrations

.PHONY: verify-smoke
verify-smoke: ## Run smoke-only API verification (happy paths only)
	cd $(BACKEND_DIR) && poetry run python ../$(VERIFY_SCRIPT) --skip-migrations --smoke-only

# ──────────────────────────────────────────────────────────────────────────────
# Logs
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: logs
logs: ## Tail production stack logs
	$(COMPOSE) logs -f

.PHONY: logs-backend
logs-backend: ## Tail production backend logs
	$(COMPOSE) logs -f backend

.PHONY: logs-test
logs-test: ## Tail test stack logs
	$(COMPOSE_TEST) logs -f

# ──────────────────────────────────────────────────────────────────────────────
# Status / health
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: ps
ps: ## Show running containers (both stacks)
	$(COMPOSE) ps
	$(COMPOSE_TEST) ps

.PHONY: health
health: ## Hit the health endpoint
	@curl -s http://localhost:8000/api/v1/health | python3 -m json.tool

# ──────────────────────────────────────────────────────────────────────────────
# Database shell (production)
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: db
db: ## Open psql shell in the production postgres container
	@PG_USER=$$(grep ^POSTGRES_USER .env | cut -d= -f2); \
	PG_PASS=$$(grep ^POSTGRES_PASSWORD .env | cut -d= -f2); \
	PG_DB=$$(grep ^POSTGRES_DB .env | cut -d= -f2); \
	docker exec -it -e PGPASSWORD=$$PG_PASS $(POSTGRES) psql -U $$PG_USER -d $$PG_DB

# ──────────────────────────────────────────────────────────────────────────────
# Convenience combos
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: up-migrate
up-migrate: start migrate ## Start production stack and apply migrations

.PHONY: fresh-verify
fresh-verify: start-test-env migrate-test verify ## Build test env → migrate → run API verification

.PHONY: fresh-verify-down
fresh-verify-down: fresh-verify down-test-env ## Build test env → migrate → verify → teardown
