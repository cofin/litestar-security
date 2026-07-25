SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

.DEFAULT_GOAL := help
.ONESHELL:
.EXPORT_ALL_VARIABLES:
MAKEFLAGS += --no-print-directory

.PHONY: help
help: ## Display this help text
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: install
install: ## Install all locked development dependencies
	uv sync --all-groups

.PHONY: fix
fix: ## Apply Ruff lint and formatting fixes
	uv run ruff check --fix --unsafe-fixes .
	uv run ruff format .

.PHONY: prek
prek: ## Run all repository hooks
	uv run prek run --all-files

.PHONY: lint
lint: prek ## Run formatting, linting, spelling, and repository policy checks

.PHONY: test
test: ## Run the test suite
	uv run pytest

.PHONY: coverage
coverage: ## Run the test suite with branch coverage
	uv run pytest --cov=litestar_security --cov-branch --cov-report=term-missing

.PHONY: mypy
mypy: ## Run mypy
	uv run mypy

.PHONY: pyright
pyright: ## Run pyright
	uv run pyright

.PHONY: type-check
type-check: mypy pyright ## Run all static type checks

.PHONY: slotscheck
slotscheck: ## Validate slotted classes
	uv run slotscheck src/litestar_security

.PHONY: docs
docs: ## Build the HTML documentation with warnings as errors
	uv run sphinx-build -W --keep-going -b html docs docs/_build/html

.PHONY: docs-linkcheck
docs-linkcheck: ## Validate documentation links
	uv run sphinx-build -W --keep-going -b linkcheck docs docs/_build/linkcheck

.PHONY: build
build: ## Build the wheel and source distribution
	uv build

.PHONY: check-all
check-all: lint test coverage type-check slotscheck docs docs-linkcheck build ## Run the complete validation suite
