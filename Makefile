SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

# =============================================================================
# Configuration and Environment Variables
# =============================================================================

.DEFAULT_GOAL:=help
.ONESHELL:
.EXPORT_ALL_VARIABLES:
MAKEFLAGS += --no-print-directory
PYTHON_VERSION ?= 3.10
UV_SYNC_ARGS ?= --all-groups

# Detect Rodete and configure index URLs for Python tools
ifneq ($(shell grep -s -q "rodete" /etc/os-release && echo "yes"),)
export PIP_INDEX_URL=https://pypi.org/simple
export UV_INDEX_URL=https://pypi.org/simple
endif

# -----------------------------------------------------------------------------
# Display Formatting and Colors
# -----------------------------------------------------------------------------
BLUE := $(shell printf "\033[1;34m")
GREEN := $(shell printf "\033[1;32m")
RED := $(shell printf "\033[1;31m")
YELLOW := $(shell printf "\033[1;33m")
NC := $(shell printf "\033[0m")
INFO := $(shell printf "$(BLUE)ℹ$(NC)")
OK := $(shell printf "$(GREEN)✓$(NC)")
WARN := $(shell printf "$(YELLOW)⚠$(NC)")
ERROR := $(shell printf "$(RED)✖$(NC)")

# =============================================================================
# Help and Documentation
# =============================================================================

.PHONY: help
help:                                               ## Display this help text for Makefile
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

# =============================================================================
# Installation and Environment Setup
# =============================================================================

.PHONY: setup-env
setup-env:                                          ## Configure local environment (e.g. Rodete)
	@./tools/scripts/setup-env.sh

.PHONY: install-uv
install-uv:                                         ## Install latest version of uv
	@echo "${INFO} Installing uv... ⚡"
	@curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1
	@echo "${OK} UV installed successfully 🎉"

.PHONY: install
install: destroy clean setup-env                    ## Install all locked development dependencies
	@echo "${INFO} Starting fresh installation... ⚡"
	@uv python pin $(PYTHON_VERSION) >/dev/null 2>&1
	@uv venv >/dev/null 2>&1
	@uv sync $(UV_SYNC_ARGS)
	@echo "${OK} Installation complete! 🎉"

.PHONY: destroy
destroy:                                            ## Destroy virtual environment and clean caches
	@echo "${INFO} Destroying virtual environment... 🗑️"
	@uvx prek clean >/dev/null 2>&1 || true
	@rm -rf .venv
	@echo "${OK} Virtual environment destroyed 🗑️"

# =============================================================================
# Dependency Management
# =============================================================================

.PHONY: upgrade
upgrade:                                            ## Upgrade all dependencies to latest stable versions
	@echo "${INFO} Updating all dependencies... 🔄"
	@uv lock --upgrade
	@echo "${OK} Dependencies updated 🔄"
	@uvx prek autoupdate --cooldown-days 7
	@echo "${OK} Updated prek hooks (7-day cooldown) 🔄"
	@uv lock >/dev/null 2>&1

.PHONY: lock
lock:                                               ## Rebuild lockfiles from scratch
	@echo "${INFO} Rebuilding lockfiles... 🔄"
	@uv lock --upgrade >/dev/null 2>&1
	@echo "${OK} Lockfiles updated 🔄"

# =============================================================================
# Build
# =============================================================================

.PHONY: build
build:                                              ## Build the wheel and source distribution
	@echo "${INFO} Building package... 📦"
	@uv build
	@echo "${OK} Package build complete 📦"

# =============================================================================
# Documentation
# =============================================================================

.PHONY: docs
docs:                                               ## Build the HTML documentation with warnings as errors
	@echo "${INFO} Building docs... 📚"
	@uv run sphinx-build -W --keep-going -b html docs docs/_build/html
	@echo "${OK} Docs build complete 📚"

.PHONY: docs-linkcheck
docs-linkcheck:                                     ## Validate documentation links
	@echo "${INFO} Checking docs links... 📚"
	@uv run sphinx-build -W --keep-going -b linkcheck docs docs/_build/linkcheck
	@echo "${OK} Docs linkcheck complete 📚"

# =============================================================================
# Testing and Quality Checks
# =============================================================================

.PHONY: test
test:                                               ## Run the test suite
	@echo "${INFO} Running test cases... 🧪"
	@uv run pytest
	@echo "${OK} Tests complete 🧪"

.PHONY: test-all
test-all: test                                      ## Run all tests

.PHONY: coverage
coverage:                                           ## Run the test suite with branch coverage
	@echo "${INFO} Running tests with coverage... 🧪"
	@uv run pytest --cov=litestar_security --cov-branch --cov-report=term-missing
	@echo "${OK} Coverage checks passed 📊"

# -----------------------------------------------------------------------------
# Type Checking
# -----------------------------------------------------------------------------

.PHONY: mypy
mypy:                                               ## Run mypy
	@echo "${INFO} Running mypy... 🔍"
	@uv run mypy
	@echo "${OK} Mypy checks passed ✨"

.PHONY: pyright
pyright:                                            ## Run pyright
	@echo "${INFO} Running pyright... 🔍"
	@uv run pyright
	@echo "${OK} Pyright checks passed ✨"

.PHONY: type-check
type-check: mypy pyright                            ## Run all static type checks

# -----------------------------------------------------------------------------
# Linting and Formatting
# -----------------------------------------------------------------------------

.PHONY: prek
prek:                                               ## Run prek hooks
	@echo "${INFO} Running prek checks... 🔍"
	@uvx prek run --show-diff-on-failure --color=always --all-files
	@echo "${OK} prek checks passed ✨"

.PHONY: zizmor
zizmor:                                             ## Run zizmor workflow security scanner
	@echo "${INFO} Running zizmor workflow security checks... 🛡️"
	@if [ -d ".github/workflows" ]; then \
		uvx zizmor .github/workflows; \
	else \
		echo "${WARN} No .github/workflows directory found"; \
	fi
	@echo "${OK} zizmor workflow checks passed ✨"

.PHONY: slotscheck
slotscheck:                                         ## Validate slotted classes
	@echo "${INFO} Running slots check... 🔍"
	@uv run slotscheck src/litestar_security/
	@echo "${OK} Slots check passed ✨"

.PHONY: fix
fix:                                                ## Fix linting issues
	@echo "${INFO} Fixing linting issues... 🔍"
	@uv run ruff check --fix --unsafe-fixes .
	@uv run ruff format .
	@echo "${OK} Linting issues fixed ✨"

.PHONY: lint
lint: prek type-check slotscheck zizmor              ## Run all linting checks

# =============================================================================
# Aggregate Verification
# =============================================================================

.PHONY: check-all
check-all: lint test-all coverage docs docs-linkcheck build ## Run the complete validation suite
