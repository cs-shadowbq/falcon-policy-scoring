.PHONY: docs clean docs-serve install test test-coverage test-coverage-serve workflows run help requirements docker-build docker-test docker-push k8s-deploy k8s-delete run-daemon build man dist dist-clean airgap release bump-patch bump-minor bump-major version

help:
	@echo "Available Make Targets:"
	@echo "  clean                    Clean build artifacts"
	@echo "  docs                     Generate documentation"
	@echo "  docs-serve               Serve documentation on http://localhost:8088"
	@echo ""
	@echo "Testing Targets:"
	@echo "  test                     Run all tests (unit + integration, excludes E2E)"
	@echo "  test-unit                Run only unit tests"
	@echo "  test-integration         Run only integration tests"
	@echo "  test-e2e-record          Record E2E tests with real API (requires credentials)"
	@echo "  test-e2e-replay          Replay E2E tests from VCR cassettes (no credentials)"
	@echo "  test-failed              Re-run only previously failed tests"
	@echo "  test-coverage            Run tests with coverage report (excludes E2E)"
	@echo "  test-coverage-serve      Run coverage + serve report at http://localhost:8089"
	@echo "  clean-test               Clean test artifacts and cache"
	@echo ""
	@echo "Development Targets:"
	@echo "  workflows                Run similar GitHub workflows locally"
	@echo "  install                  Install all dependencies"
	@echo "  requirements             Generate requirements.txt files from pyproject.toml"
	@echo ""
	@echo "Distribution Targets:"
	@echo "  build                    Build wheel + sdist + man page (alias: dist + man)"
	@echo "  dist                     Build wheel and sdist into dist/<version>/"
	@echo "  man                      Generate man page (dist-templates/policy-audit.1)"
	@echo "  dist-clean               Clean all dist artifacts (or 'make dist-clean X.Y.Z' for one version)"
	@echo "  airgap                   Build airgap bundles (RHEL 9 x86_64)"
	@echo "  release                  Create GitHub release with all artifacts (via gh CLI)"
	@echo ""
	@echo "Version Bump Targets (edit version in pyproject.toml):"
	@echo "  version                  Show current version from pyproject.toml"
	@echo "  bump-patch               Bump patch version (X.Y.Z -> X.Y.Z+1)"
	@echo "  bump-minor               Bump minor version (X.Y.Z -> X.Y+1.0)"
	@echo "  bump-major               Bump major version (X.Y.Z -> X+1.0.0)"
	@echo ""
	@echo "Daemon Mode Targets:"
	@echo "  run-daemon               Run daemon locally"
	@echo "  docker-build             Build Docker image [TAG=version]"
	@echo "  docker-test              Test Docker image locally"
	@echo "  docker-push              Push to registry (requires REGISTRY=...) [TAG=version]"
	@echo "  k8s-deploy               Deploy to Kubernetes"
	@echo "  k8s-delete               Delete Kubernetes deployment"
	@echo ""
	@echo "Environment Variables:"
	@echo "  REGISTRY=registry.com    Docker registry (required for push)"
	@echo "  TAG=version              Docker image tag (default: latest)"
	@echo "  AIRGAP_PYTHON=39,311,312 Python versions for airgap bundles (default: 39,311,312)"
	@echo ""
	@echo "Examples:"
	@echo "  make dist                          Build wheel"
	@echo "  make airgap                        Build airgap bundles for Python 3.9 + 3.11"
	@echo "  make airgap AIRGAP_PYTHON=39       Build only Python 3.9 bundle"
	@echo "  make release                       Push dist + airgap to GitHub release"
	@echo "  make docker-build TAG=v1.0.0"
	@echo "  export REGISTRY=docker.io/myuser && make docker-push"
	@echo "  REGISTRY=ghcr.io/org TAG=dev make docker-push"
	@echo ""
	@echo "Advanced Deployment (use k8s-deploy.sh directly):"
	@echo "  ./k8s-deploy.sh check        Check K8s deployment status"
	@echo "  ./k8s-deploy.sh logs         Tail K8s logs"
	@echo "  ./k8s-deploy.sh port-forward Forward port 8088 locally"

# Default target
.DEFAULT_GOAL := help

docs:
	@echo "Generating documentation..."
	pip install -e ".[docs]"
	sphinx-apidoc -o docs/source src/falcon_policy_scoring
	cd docs && make html

clean: dist-clean clean-test
	@rm -rf data/*.json data/*.db data/*.sqlite && echo 'Cleaned database files in data/'
	@rm -rf logs/*.log && echo 'Cleaned log files in logs/'
	@rm -f results.json && echo 'Cleaned results.json'
	@echo 'Clean complete'


docs-serves:
	@echo "Serving documentation on localhost port 8088..."
	python3 -m http.server 8088 --directory docs/_build/html

# Testing targets
# Note: E2E tests are excluded by default and must be explicitly run
# E2E recording requires real CrowdStrike Falcon API credentials

test:
	@echo "Running all tests (unit + integration, excluding E2E)..."
	@pip install -e ".[test]" >/dev/null 2>&1
	pytest tests/ -m "not e2e" --tb=short -q

test-unit:
	@echo "Running unit tests only..."
	@pip install -e ".[test]" >/dev/null 2>&1
	pytest tests/ -m unit --tb=short -q

test-integration:
	@echo "Running integration tests only..."
	@pip install -e ".[test]" >/dev/null 2>&1
	pytest tests/ -m integration --tb=short -q

test-e2e-record:
	@echo "Recording E2E tests with real API (requires credentials)..."
	@echo "Note: Set FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, FALCON_BASE_URL"
	@pip install -e ".[test]" >/dev/null 2>&1
	pytest tests/test_e2e_smoke.py -m e2e --vcr-record=all --tb=short -v

test-e2e-replay:
	@echo "Replaying E2E tests from VCR cassettes (no credentials needed)..."
	@pip install -e ".[test]" >/dev/null 2>&1
	pytest tests/test_e2e_smoke.py -m e2e --vcr-record=none --tb=short -v

test-failed:
	@echo "Re-running only failed tests..."
	@pip install -e ".[test]" >/dev/null 2>&1
	pytest --lf --tb=short -v

test-coverage:
	@echo "Running tests with coverage (excluding E2E)..."
	@pip install -e ".[test]" >/dev/null 2>&1
	pytest tests/ -m "not e2e" --tb=short -q --cov=src/falcon_policy_scoring --cov-report=html --cov-report=term

test-coverage-serve:
	@$(MAKE) test-coverage
	@echo "Serving coverage report at http://localhost:8089 ..."
	python3 -m http.server 8089 --directory htmlcov

clean-test:
	@echo "Cleaning test artifacts..."
	@rm -rf .pytest_cache htmlcov .coverage
	@find tests -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "Test artifacts cleaned"

workflows:
	@echo "Running all GitHub workflows locally..."
	pip install -e ".[dev,test]"
	pip install pylint bandit
	@echo "Running Bandit scan..."
	bandit -r src -ll -ii -s B104
	@echo "Running Pylint..."
	pylint src/falcon_policy_scoring --disable=R0801,C0411,C0301,C0413,C0415,W0613


install:
	@echo "Installing dependencies..."
	pip install -e ".[dev,test,docs]"
	python -m pip install --upgrade pip

requirements:
	@echo "Generating requirements.txt files from pyproject.toml..."
	@echo "# Auto-generated from pyproject.toml - DO NOT EDIT MANUALLY" > requirements.txt
	@echo "# Use 'make requirements' to regenerate" >> requirements.txt
	@echo "" >> requirements.txt
	pip-compile --no-header --resolver=backtracking pyproject.toml -o requirements.txt 2>/dev/null || \
		(pip install pip-tools && pip-compile --no-header --resolver=backtracking pyproject.toml -o requirements.txt)
	@echo ""
	@echo "# Auto-generated from pyproject.toml - DO NOT EDIT MANUALLY" > requirements-dev.txt
	@echo "# Use 'make requirements' to regenerate" >> requirements-dev.txt
	@echo "" >> requirements-dev.txt
	pip-compile --no-header --resolver=backtracking --extra=dev pyproject.toml -o requirements-dev.txt
	@echo ""
	@echo "# Auto-generated from pyproject.toml - DO NOT EDIT MANUALLY" > requirements-test.txt
	@echo "# Use 'make requirements' to regenerate" >> requirements-test.txt
	@echo "" >> requirements-test.txt
	pip-compile --no-header --resolver=backtracking --extra=test pyproject.toml -o requirements-test.txt
	@echo ""
	@echo "# Auto-generated from pyproject.toml - DO NOT EDIT MANUALLY" > requirements-docs.txt
	@echo "# Use 'make requirements' to regenerate" >> requirements-docs.txt
	@echo "" >> requirements-docs.txt
	pip-compile --no-header --resolver=backtracking --extra=docs pyproject.toml -o requirements-docs.txt
	@echo "✓ Generated requirements.txt, requirements-dev.txt, requirements-test.txt, requirements-docs.txt"
	

# Daemon mode targets
# Environment variables:
#   REGISTRY - Docker registry URL (e.g., docker.io/username, ghcr.io/org)
#   TAG      - Docker image tag (default: latest)
# Examples:
#   make docker-build TAG=v1.0.0
#   export REGISTRY=docker.io/myuser && make docker-push
#   REGISTRY=ghcr.io/myorg TAG=dev make docker-push

TAG ?= latest
AIRGAP_PYTHON ?= 39,311,312

# Extract version from pyproject.toml. Build artifacts are written to a
# version-scoped subdirectory (dist/<version>/) so different versions never
# mingle and SHA256SUMS only ever covers a single release.
VERSION := $(shell python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])" 2>/dev/null || python3 -c "import tomli as tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])" 2>/dev/null || echo "0.0.0")
DIST_DIR := dist/$(VERSION)

# --- Version bump targets ---
# Bumps the version in pyproject.toml in place. Prints old -> new and a
# suggested tag/commit workflow. Does not commit or tag automatically.
define bump_version
	@python3 -c "import re,sys; part='$(1)'; p='pyproject.toml'; text=open(p,encoding='utf-8').read(); m=re.search(r'^version\s*=\s*\"(\d+)\.(\d+)\.(\d+)\"',text,re.M); sys.exit('ERROR: could not find version in pyproject.toml') if not m else None; mj,mn,pt=(int(x) for x in m.groups()); new={'patch':(mj,mn,pt+1),'minor':(mj,mn+1,0),'major':(mj+1,0,0)}[part]; old_v='%d.%d.%d'%(mj,mn,pt); new_v='%d.%d.%d'%new; open(p,'w',encoding='utf-8').write(text[:m.start(1)]+new_v+text[m.end(3):]); print('Bumped version: %s -> %s'%(old_v,new_v)); print('Next: git commit -am \"Release v%s\" && git tag v%s && git push --tags'%(new_v,new_v))"
endef

version:
	@echo "$(VERSION)"

bump-patch:
	$(call bump_version,patch)

bump-minor:
	$(call bump_version,minor)

bump-major:
	$(call bump_version,major)

# --- Distribution targets ---

# Generate the man page (policy-audit.1) from the argparse parser plus the
# hand-authored include (EXAMPLES/FILES/ENVIRONMENT/SUPPORT). The dynamic option
# surface comes from src/.../cli/cli_setup.py:build_parser() via argparse-manpage,
# so it never drifts from --help; only the prose in the include is maintained.
MAN_PAGE := dist-templates/policy-audit.1
MAN_INCLUDE := dist-templates/policy-audit.1.include

man:
	@echo "Generating man page (policy-audit.1) for v$(VERSION)..."
	@python3 -m pip install --quiet argparse-manpage
	@python3 -m pip install --quiet -e . >/dev/null 2>&1
	@argparse-manpage \
		--module falcon_policy_scoring.cli.cli_setup --function build_parser \
		--prog policy-audit --project-name "falcon-policy-scoring" \
		--version "$(VERSION)" \
		--description "fetch, grade, and analyze CrowdStrike Falcon security policies" \
		--author "CrowdStrike Community" \
		--url "https://github.com/cs-shadowbq/falcon-policy-scoring" \
		--manual-title "Falcon Policy Audit Manual" \
		--include $(MAN_INCLUDE) \
		--output $(MAN_PAGE)
	@echo "Wrote $(MAN_PAGE)"

# Convenience alias mirroring the common 'make build' convention: build the
# distributable artifacts (wheel + sdist) and the man page.
build: dist man

dist:
	@echo "Building wheel and sdist for v$(VERSION)..."
	@rm -rf $(DIST_DIR)
	python3 -m pip install --quiet build
	python3 -m build --outdir $(DIST_DIR)
	@echo ""
	@echo "Verifying wheel installs correctly..."
	@python3 -m pip install --quiet --force-reinstall $(DIST_DIR)/*.whl
	@policy-audit --version
	@echo ""
	@echo "Artifacts:"
	@ls -lh $(DIST_DIR)/

# Remove dist artifacts — all versions, or only the given version(s):
#   make dist-clean            # remove everything under dist/
#   make dist-clean 1.8.1      # remove only dist/1.8.1/
dist-clean:
	@if [ -n "$(DIST_CLEAN_VERSIONS)" ]; then \
		for v in $(DIST_CLEAN_VERSIONS); do \
			if [ -d "dist/$$v" ]; then \
				echo "Removing dist/$$v/"; \
				rm -rf "dist/$$v"; \
			else \
				echo "No such version dir: dist/$$v (skipping)"; \
			fi; \
		done; \
	else \
		echo "Removing ALL dist artifacts"; \
		rm -rf dist/ build/ src/*.egg-info; \
	fi

# Support "make dist-clean <version>" — the version is a second goal to Make.
# Capture it, and turn it into a no-op target so Make does not error out.
ifneq ($(filter dist-clean,$(MAKECMDGOALS)),)
DIST_CLEAN_VERSIONS := $(filter-out dist-clean,$(MAKECMDGOALS))
$(eval $(DIST_CLEAN_VERSIONS):;@:)
endif

airgap: build
	@echo ""
	@echo "Building airgap bundles for Python $(AIRGAP_PYTHON)..."
	@chmod +x scripts/build-airgap.sh
	scripts/build-airgap.sh --python $(AIRGAP_PYTHON)

release: dist airgap
	@echo ""
	@echo "=== Creating GitHub Release v$(VERSION) ==="
	@if ! command -v gh &>/dev/null || ! gh auth status &>/dev/null; then \
		echo ""; \
		echo "gh CLI is not available or not authenticated."; \
		echo "To publish this release manually:"; \
		echo ""; \
		echo "1. Tag the release:"; \
		echo ""; \
		echo "   git tag v$(VERSION)"; \
		echo "   git push origin v$(VERSION)"; \
		echo ""; \
		echo "2. Go to: https://github.com/cs-shadowbq/falcon-policy-scoring/releases/new"; \
		echo ""; \
		echo "3. Select tag: v$(VERSION)"; \
		echo "   Title: falcon-policy-scoring v$(VERSION)"; \
		echo "   Description: Click 'Generate release notes' for changelog"; \
		echo ""; \
		echo "4. Attach these files from $(DIST_DIR)/:"; \
		echo ""; \
		ls $(DIST_DIR)/*.whl $(DIST_DIR)/*.tar.gz $(DIST_DIR)/SHA256SUMS 2>/dev/null | sort -u | sed 's/^/   /'; \
		echo ""; \
		echo "5. Verify checksums match $(DIST_DIR)/SHA256SUMS after upload."; \
		echo ""; \
	else \
		echo ""; \
		echo "Release artifacts:"; \
		ls $(DIST_DIR)/*.whl $(DIST_DIR)/*.tar.gz $(DIST_DIR)/*-airgap-*.tar.gz $(DIST_DIR)/SHA256SUMS 2>/dev/null; \
		echo ""; \
		echo "Creating release..."; \
		gh release create "v$(VERSION)" \
			--title "falcon-policy-scoring v$(VERSION)" \
			--generate-notes \
			--notes-start-tag "$$(git tag --sort=-v:refname | sed -n '2p')" \
			$(DIST_DIR)/*.whl \
			$(DIST_DIR)/*.tar.gz \
			$(DIST_DIR)/*-airgap-*.tar.gz \
			$(DIST_DIR)/SHA256SUMS \
			$$(ls $(DIST_DIR)/SHA256SUMS.asc 2>/dev/null); \
		echo ""; \
		echo "Release published: https://github.com/cs-shadowbq/falcon-policy-scoring/releases/tag/v$(VERSION)"; \
	fi

run-daemon:
	python bin/policy-audit daemon --config config/config.yaml --output-dir ./output --verbose

docker-build:
	@echo "Building Docker image (falcon-policy-audit:$(TAG))..."
	@echo "Version from pyproject.toml: $(VERSION)"
	docker build --build-arg VERSION=$(VERSION) -t falcon-policy-audit:$(TAG) -f Dockerfile .
	@if [ "$(TAG)" != "latest" ]; then \
		docker tag falcon-policy-audit:$(TAG) falcon-policy-audit:latest; \
		echo "Also tagged as falcon-policy-audit:latest"; \
	fi

docker-test:
	@echo "Testing Docker image locally..."
	docker-compose up -d
	@sleep 10
	@echo "Testing health endpoint..."
	curl -f http://localhost:8088/health || (docker-compose logs && docker-compose down && exit 1)
	@echo "Health check passed!"
	docker-compose down

docker-push:
	@if [ -z "$(REGISTRY)" ]; then \
		echo "Error: REGISTRY not set."; \
		echo "Usage: make docker-push REGISTRY=your-registry.com [TAG=version]"; \
		echo "Or:    export REGISTRY=your-registry.com && make docker-push"; \
		exit 1; \
	fi
	@echo "Tagging and pushing to $(REGISTRY)/falcon-policy-audit:$(TAG)..."
	docker tag falcon-policy-audit:$(TAG) $(REGISTRY)/falcon-policy-audit:$(TAG)
	docker push $(REGISTRY)/falcon-policy-audit:$(TAG)
	@if [ "$(TAG)" != "latest" ]; then \
		echo "Also pushing latest tag..."; \
		docker tag falcon-policy-audit:$(TAG) $(REGISTRY)/falcon-policy-audit:latest; \
		docker push $(REGISTRY)/falcon-policy-audit:latest; \
	fi

k8s-deploy:
	@echo "Deploying to Kubernetes..."
	./k8s-deploy.sh deploy

k8s-delete:
	@echo "Deleting Kubernetes deployment..."
	./k8s-deploy.sh delete
