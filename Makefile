.PHONY: docs clean docs-serve install test test-coverage test-coverage-serve run help requirements docker-build docker-test docker-push k8s-deploy k8s-delete run-daemon

help:
	@echo "Available Make Targets:"
	@echo "  clean                    Clean build artifacts"
	@echo "  docs                     Generate documentation"
	@echo "  docs-serve               Serve documentation on http://localhost:8088"
	@echo "  test                     Run tests"
	@echo "  test-coverage            Run tests with coverage report"
	@echo "  test-coverage-serve      Run tests with coverage report http://localhost:8089"
	@echo "  install                  Install all dependencies"
	@echo "  requirements             Generate requirements.txt files from pyproject.toml"
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
	@echo ""
	@echo "Examples:"
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

clean:
	@rm -rf data/*.json data/*.db data/*.sqlite && echo 'Cleaned database files in data/'
	@rm -rf logs/*.log && echo 'Cleaned log files in logs/'
	@rm -f results.json && echo 'Cleaned results.json'
	@echo 'Clean complete'


docs-serves:
	@echo "Serving documentation on localhost port 8088..."
	python3 -m http.server 8088 --directory docs/_build/html

test:
	@echo "Running tests..."
	pip install -e ".[test]"
	pytest --tb=short --disable-warnings -q tests

test-coverage:
	@echo "Running tests with coverage..."
	pip install -e ".[test]"
	pytest --tb=short --disable-warnings -q tests --cov=src/falcon_policy_scoring --cov-report=html

test-coverage-serve:
	$(MAKE) test-coverage
	@echo "Serving coverage report at http://localhost:8089 ..."
	python3 -m http.server 8089 --directory htmlcov

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

# Extract version from pyproject.toml
VERSION := $(shell python -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])" 2>/dev/null || echo "0.0.0")

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
