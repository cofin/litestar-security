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
UV_SYNC_ARGS ?= --all-groups --all-extras

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
# Cleaning and Maintenance
# =============================================================================

.PHONY: clean
clean:                                              ## Cleanup temporary build artifacts
	@echo "${INFO} Cleaning working directory... 🧹"
	@rm -rf .pytest_cache .ruff_cache .hypothesis build/ dist/ .eggs/ .coverage coverage.xml coverage.json htmlcov/ src/tests/.pytest_cache src/tests/**/.pytest_cache .mypy_cache >/dev/null 2>&1
	@find . -name '*.egg-info' -exec rm -rf {} + >/dev/null 2>&1
	@find . -type f -name '*.egg' -exec rm -f {} + >/dev/null 2>&1
	@find . -name '*.pyc' -exec rm -f {} + >/dev/null 2>&1
	@find . -name '*.pyo' -exec rm -f {} + >/dev/null 2>&1
	@find . -name '*~' -exec rm -f {} + >/dev/null 2>&1
	@find . -name '__pycache__' -exec rm -rf {} + >/dev/null 2>&1
	@find . -name '.ipynb_checkpoints' -exec rm -rf {} + >/dev/null 2>&1
	@echo "${OK} Working directory cleaned 🧹"

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
# Build and Release
# =============================================================================

.PHONY: build
build:                                              ## Build the wheel and source distribution
	@echo "${INFO} Building package... 📦"
	@uv build
	@echo "${OK} Package build complete 📦"

.PHONY: release
release:                                           ## Bump version and create release tag (bump=major|minor|patch)
	@echo "${INFO} Preparing for release... 📦"
	@make docs
	@make clean
	@make build
	@uv run bump-my-version bump $(bump)
	@uv lock --upgrade-package litestar-security >/dev/null 2>&1
	@echo "${OK} Release complete 🎉"

.PHONY: pre-release
pre-release:                                       ## Start a pre-release: make pre-release version=0.2.0-alpha.1
	@if [ -z "$(version)" ]; then \
		echo "${ERROR} Usage: make pre-release version=X.Y.Z-alpha.N"; \
		echo ""; \
		echo "Pre-release workflow:"; \
		echo "  1. Start alpha:     make pre-release version=0.2.0-alpha.1"; \
		echo "  2. Next alpha:      make pre-release version=0.2.0-alpha.2"; \
		echo "  3. Move to beta:    make pre-release version=0.2.0-beta.1"; \
		echo "  4. Move to rc:      make pre-release version=0.2.0-rc.1"; \
		echo "  5. Final release:   make release bump=pre (from rc) OR bump=patch/minor (from stable)"; \
		exit 1; \
	fi
	@echo "${INFO} Preparing pre-release $(version)... 🧪"
	@make clean
	@make build
	@uv run bump-my-version bump --new-version $(version) pre
	@uv lock --upgrade-package litestar-security >/dev/null 2>&1
	@echo "${OK} Pre-release $(version) complete 🧪"
	@echo ""
	@echo "${INFO} Next steps:"
	@echo "  1. Push: git push origin HEAD"
	@echo "  2. Create a GitHub pre-release: gh release create v$(version) --prerelease --title 'v$(version)'"
	@echo "  3. This will publish to PyPI with pre-release tags"


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
	@uv run pytest -m "not performance"
	@echo "${OK} Tests complete 🧪"

.PHONY: test-all
test-all: test                                      ## Run all tests

.PHONY: property
property:                                           ## Run deterministic property and fuzz regression tests
	@echo "${INFO} Running property tests... 🧪"
	@uv run pytest src/tests/property
	@echo "${OK} Property tests passed 🧪"

.PHONY: examples
examples:                                           ## Run the runnable example applications
	@echo "${INFO} Running example applications... 🧪"
	@uv run pytest src/tests/examples
	@echo "${OK} Example applications passed 🧪"

.PHONY: benchmark
benchmark:                                          ## Run deterministic local performance regression gates
	@echo "${INFO} Running performance regression gates... 📊"
	@uv run pytest -m performance
	@echo "${OK} Performance regression gates passed 📊"

.PHONY: performance
performance: benchmark                              ## Alias for deterministic performance regression gates

.PHONY: downstream-check
downstream-check:                                   ## Verify the installed wheel from an isolated downstream package
	@echo "${INFO} Checking downstream consumer compatibility... 📦"
	@uv run python tools/check_downstream_consumer.py
	@echo "${OK} Downstream consumer compatibility passed 📦"

.PHONY: release-smoke
release-smoke:                                      ## Verify release archives and installed wheels on every supported Python
	@echo "${INFO} Checking release archives and installed wheels... 📦"
	@uv run python tools/check_release.py
	@echo "${OK} Release archive and wheel checks passed 📦"

.PHONY: coverage
coverage:                                           ## Run the test suite with branch coverage
	@echo "${INFO} Running tests with coverage... 🧪"
	@uv run pytest -m "not performance" --cov=litestar_security --cov-branch --cov-report=term-missing
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
check-all: lint test-all property coverage docs docs-linkcheck downstream-check build ## Run all checks

.PHONY: release-check
release-check: property downstream-check examples benchmark check-all release-smoke ## Run every local 1.0 release gate
