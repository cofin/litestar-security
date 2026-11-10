---
type: Guide
title: "Tech Stack & Verification Toolchain"
description: "Verified Python runtime versions, core and optional dependencies, build backend, and static/runtime verification tools for litestar-security."
status: stable
tags: [tech-stack, python, litestar, uv, pytest, ruff, mypy, pyright]
generated:
  by: flow/0.26.0
  at: "2026-11-02T01:45:00Z"
verified:
  - by: agent:flow-setup
    at: "2026-11-10T22:45:00Z"
    commit: "398fd57"
sources:
  - id: pyproject-stack
    resource: "pyproject.toml"
    title: "Project dependencies, optional extras, and tool configurations"
  - id: makefile
    resource: "Makefile"
    title: "Developer workflow targets for install, lint, test, coverage, and release checks"
  - id: typing-facade
    resource: "src/litestar_security/typing.py"
    title: "Lazy optional-dependency flags and installation requirement helpers"
  - id: docs-conf
    resource: "docs/conf.py"
    title: "Sphinx theme and extension configuration"
---

# Tech Stack & Verification Toolchain

<!-- truth: start -->
- **Language & Build Backend**: Python `>=3.10` (`3.10`–`3.14` supported), managed with `uv` and built via `hatchling` (`src/litestar_security` wheel package).[^pyproject-stack]
- **Core Runtime Dependencies**:
  - `litestar>=2.24.0` (ASGI framework, routing, DI, OpenAPI 3.1, DTOs, channels/WebSockets, Click CLI plugin hook).[^pyproject-stack]
  - `httpx>=0.28.1` (async HTTP client for JWKS fetching, OAuth token exchange, and OIDC discovery with custom SSRF-pinned transport).[^pyproject-stack]
  - `PyJWT[crypto]>=2.13` (JWS/JWT verification and `cryptography` primitives for AES-GCM, RSA, EC, EdDSA, and HMAC).[^pyproject-stack]
  - Transitive core primitives used directly: `msgspec` (`WireStruct` and `MsgspecDTO`), `anyio` (`BlockingCallRunner`, task groups, memory object streams), and `click` (`litestar security` CLI group).[^pyproject-stack]
- **Optional Extras (`[project.optional-dependencies]` & `litestar_security.typing`)**:
  - `argon2`: `argon2-cffi>=25.1,<26` (`Argon2PasswordHasher`, gated by `ARGON2_INSTALLED` / `ensure_argon2`).[^pyproject-stack][^typing-facade]
  - `mfa`: `PyOTP>=2.10,<3` (`MFAService` and `MFALoginService`, gated by `PYOTP_INSTALLED` / `ensure_pyotp`).[^pyproject-stack][^typing-facade]
  - `passkeys`: `webauthn>=3,<4` (`PyWebAuthnVerifier`, gated by `WEBAUTHN_INSTALLED` / `ensure_webauthn`).[^pyproject-stack][^typing-facade]
  - `oauth`: `[]` (uses core `httpx` + `PyJWT[crypto]`).[^pyproject-stack]
- **Verification Toolchain**:
  - Static analysis: `ruff` (`select = ["ALL"]`, `line-length = 120`), `mypy` (`strict = true`), `pyright` (`typeCheckingMode = "strict"`, `pythonVersion = "3.10"`), `slotscheck`, `codespell`, `prek`, and `zizmor`.[^pyproject-stack][^makefile]
  - Testing & coverage: `pytest` (`anyio_mode = "auto"`, `pytest-xdist` `-n auto`, `pytest-benchmark`, `polyfactory`, `hypothesis`) and `pytest-cov` (`95%` overall threshold + `100%` branch coverage on `CORE_COVERAGE` modules).[^pyproject-stack][^makefile]
<!-- truth: end -->

## CLI Entrypoint & Documentation Stack

- **Litestar CLI Plugin**: Registered under `[project.entry-points."litestar.commands"]` as `security = "litestar_security._cli:security_group"`, providing `litestar security routes` (`--format table|json`, `--include-excluded`) and `litestar security --version`.[^pyproject-stack]
- **Documentation**: Sphinx (`sphinx>=7.1.2`) with `shibuya` theme, `sphinx-copybutton>=0.5.2`, `sphinx-design>=0.5.0`, and Sphinx `autodoc`, `autosectionlabel`, `napoleon`, and `viewcode` extensions (`make docs`, `make docs-linkcheck`).[^pyproject-stack][^makefile][^docs-conf]

## References

[^pyproject-stack]: `pyproject.toml` — Project dependencies, optional extras, and tool configurations
[^makefile]: `Makefile` — Developer workflow targets for install, lint, test, coverage, and release checks
[^typing-facade]: `src/litestar_security/typing.py` — Lazy optional-dependency flags and installation requirement helpers
[^docs-conf]: `docs/conf.py` — Sphinx theme and extension configuration
