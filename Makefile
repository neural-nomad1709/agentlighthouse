# AgentLighthouse developer tasks. All Python runs through uv.
.DEFAULT_GOAL := help
.PHONY: help install sync test cov lint fmt keygen init check healthz run verify demo demo-memory demo-a2a release bump-version compose-config sbom sign pilot clean

IMAGE ?= agentlighthouse/al-core:0.2.1

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install sync: ## Install/sync the workspace (uv)
	uv sync

test: ## Run the test suite
	uv run pytest -q

cov: ## Run tests with coverage report
	uv run pytest -q --cov --cov-report=term-missing

lint: ## detect-secrets scan of our own repo (supply-chain hygiene)
	uv run detect-secrets scan --all-files > /dev/null && echo "no secrets detected"

keygen: ## Generate the mediator signing key (dev)
	uv run al keygen

init: ## Initialize a dev workspace (keys, .env, data)
	uv run al init --config configs/balanced.yaml

check: ## Validate the balanced config
	uv run al check --config configs/balanced.yaml

healthz: ## Boot the runtime and print health
	uv run al healthz --config configs/balanced.yaml

run: ## Run the control-plane API (/healthz)
	uv run al run --config configs/balanced.yaml

verify: ## Verify the local ledger with the standalone verifier
	uv run al-verify data/ledger.jsonl --pubkey keys/mediator_ed25519.pub

compose-config: ## Validate the docker compose topology
	docker compose config >/dev/null && echo "compose OK"

sbom: ## Generate the image SBOM (SPDX JSON) into dist/ (requires syft)
	mkdir -p dist
	syft "docker:$(IMAGE)" -o spdx-json > dist/al-core.spdx.json
	@echo "SBOM written to dist/al-core.spdx.json"

sign: ## RELEASE PACKAGING: build + SBOM + cosign sign/attest (requires registry push access)
	./scripts/release-image.sh "$(IMAGE)"

pilot: ## One-command pilot install (Linux/macOS; Windows: scripts/pilot-install.ps1)
	./scripts/pilot-install.sh

demo: ## RELEASE GATE: tool-response injection blocked on all 3 MCP transports
	uv run python examples/tool-response-injection/demo.py

demo-memory: ## Demo 2: memory poisoning blocked + rollback (ASI06), fully local
	uv run python examples/memory-poison/demo.py

demo-a2a: ## Demo 3: A2A card poisoning + session smuggling intercepted (ASI07)
	uv run python examples/a2a-lab/demo.py

release: ## Release gate: full suite + all three demos must pass
	uv run pytest -q
	$(MAKE) demo
	$(MAKE) demo-memory
	$(MAKE) demo-a2a

bump-version: ## Cut a release: sync versions, roll CHANGELOG, commit + tag (VERSION=X.Y.Z)
	./scripts/bump-version.sh "$(VERSION)"

clean: ## Remove caches and build artifacts (keeps keys/ and data/)
	rm -rf .pytest_cache htmlcov .coverage **/__pycache__ dist build
