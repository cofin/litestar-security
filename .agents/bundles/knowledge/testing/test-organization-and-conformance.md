---
type: Testing
title: "Test Organization, Store Conformance, & Coverage Gates"
description: "Unit vs integration test boundaries, fixture scoping, optional-extra-free store conformance, and 100% core branch coverage."
status: stable
tags: [testing, pytest, conformance, unit-tests, integration-tests, coverage]
generated:
  by: flow/0.26.0
  at: "2026-11-02T01:45:00Z"
verified:
  - by: agent:flow-setup
    at: "2026-11-10T22:45:00Z"
    commit: "398fd57"
sources:
  - id: testing-py
    resource: "src/litestar_security/testing.py::assert_security_backend_conformance"
    title: "InMemorySecurityBackend, FakeClock, StoreConformanceFactories, and conformance suites"
  - id: context-test
    resource: "src/tests/unit/test_context.py"
    title: "Subprocess isolation tests verifying accounts and testing kit without optional extras"
  - id: conftest-py
    resource: "src/tests/conftest.py"
    title: "Root pytest fixtures: clock, anyio_backend, and jwt_key_material"
  - id: unit-conftest-py
    resource: "src/tests/unit/conftest.py"
    title: "Unit-scoped fixtures for security_backend, derived stores, and test collaborators"
  - id: typing-helpers
    resource: "src/tests/helpers/typing.py"
    title: "Static typing assertion helpers for test modules"
  - id: makefile-cov
    resource: "Makefile"
    title: "CORE_COVERAGE 100% branch coverage gate and check-all target"
---

# Test Organization, Store Conformance, & Coverage Gates

<!-- truth: start -->
- **Unit vs. Integration Split (`src/tests/`)**:
  - `src/tests/unit/`: Tests pure logic, codecs, sealers, policy algebra, and service methods in memory. New unit tests must **never** instantiate `Litestar`, `TestClient`, or `AsyncTestClient` (pre-existing legacy instances in `test_dto.py` and `test_cli.py` are not to be imitated).
  - `src/tests/integration/`: Tests end-to-end ASGI pipelines, route compilation, OpenAPI schemas, middleware, CSRF/cookies, controllers, and WebSocket lifecycles via `Litestar` + `TestClient` / `AsyncTestClient`.
  - `src/tests/examples/`: Verifies runnable example modes (`test_local_modes.py`, `test_provider_modes.py`, `test_websocket_admin_modes.py`).
  - `src/tests/helpers/typing.py`: Houses static `assert_type` checks verified by `mypy` and `pyright`; keep typing-only check stubs out of unit and integration modules.[^conftest-py][^typing-helpers]
- **Fixture Scoping & `anyio_mode = "auto"`**: `src/tests/conftest.py` provides only `clock`, `anyio_backend`, and `jwt_key_material`. `src/tests/unit/conftest.py` provides `security_backend`, derived store fixtures, standalone `oidc_logout_store`, `rate_limiter`, `secret_protector`, `local_key_ring`, `password_hasher`, and `anonymous_principal`. `src/tests/integration/conftest.py` provides app and recording fixtures (`empty_security_config`, `public_profile_app`, `required_profile_app`, `oauth_provider`, `oauth_transport`, `revocation_source`). Single-module fixtures stay in the test file that uses them, and `pyproject.toml` sets `anyio_mode = "auto"` so async tests omit `@pytest.mark.anyio`.[^conftest-py][^unit-conftest-py]
- **Optional-Extra-Free Conformance Suite**: `litestar_security.testing` exports `StoreConformanceFactories` and `assert_security_backend_conformance` covering `AccountLookup`, `RegistrationStore`, `PasswordCredentialStore`, `LoginMethodStore`, `VerificationTokenStore`, `RecoveryTokenStore`, `SecurityEpochStore`, `SessionRegistry` (`NativeSessionStore`), `RefreshTokenFamilyStore`, `MFAStore`, `MFALoginChallengeStore`, `PasskeyStore`, `WebAuthnChallengeStore`, `StepUpStore`, `APIKeyStore`, `OAuthAccountStore`, `OAuthTransactionStore`, `OIDCSessionLogoutStore`, `OAuthTransactionProtector`, `SecretProtector`, and `WebSocketConnectTokenStore`, plus standalone `assert_rate_limiter_conformance` (`RateLimiter`). All reference stores and conformance runners execute without `argon2`, `pyotp`, `webauthn`, or `cbor2` installed.[^testing-py][^context-test]
- **Coverage Gates (`Makefile`)**: `make coverage` enforces `>=95%` overall branch+line coverage and `100%` branch coverage on `CORE_COVERAGE` (`authentication.py`, `guards.py`, `context.py`, `providers/jwt/*`, `providers/oauth/_transactions.py`, `accounts/_refresh.py`, `websocket/_connect_tokens.py`).[^makefile-cov]
<!-- truth: end -->

## Canonical Test Module Map

| Area | Unit Tests (`src/tests/unit/`) | Integration & Example Tests (`src/tests/{integration,examples}/`) |
| :--- | :--- | :--- |
| **Runtime & Policy** | `test_authentication_evaluator.py`, `test_authentication_registry.py`, `test_guards.py`, `test_context.py`, `test_config.py`, `test_docs.py`, `test_headers.py`, `test_dto.py`, `test_openapi.py`, `test_cli.py`, `test_extensibility.py`, `test_input_corpora.py`, `test_value_type_contracts.py` | `integration/test_plugin.py`, `integration/test_plugin_delegation.py`, `integration/test_openapi_document.py`, `integration/test_route_exclusion.py`, `integration/test_authentication_composition.py`, `integration/test_error_responses.py`, `integration/test_runtime.py`, `integration/test_wire_casing.py` |
| **Providers** | `test_providers/test_jwt/`, `test_providers/test_jwks/`, `test_providers/test_api_key/`, `test_providers/test_iap/`, `test_providers/test_oauth/` (including `test_resource_server.py`), `test_providers/test_oidc/` | `integration/test_oauth_routes.py`, `integration/test_resource_server.py`, `integration/test_authentication_composition.py`, `examples/test_provider_modes.py` |
| **Accounts** | `test_accounts/test_access_tokens.py`, `test_accounts/test_mfa.py`, `test_accounts/test_mfa_login.py`, `test_accounts/test_passkeys.py`, `test_accounts/test_passwords.py`, `test_accounts/test_profiles.py`, `test_accounts/test_rate_limits.py`, `test_accounts/test_records.py`, `test_accounts/test_recovery.py`, `test_accounts/test_refresh.py`, `test_accounts/test_refresh_receipts.py`, `test_accounts/test_sessions.py`, `test_accounts/test_step_up.py` | `integration/test_accounts/test_controllers/`, `examples/test_local_modes.py` |
| **WebSocket & Testing** | `test_websocket/test_bindings.py`, `test_websocket/test_config.py`, `test_websocket/test_connect_tokens.py`, `test_websocket/test_handshake.py`, `test_websocket/test_lifecycle.py`, `test_in_memory_backend.py`, `test_testing_kit.py`, `test_fixture_vocabulary.py`, `test_accounts/test_conformance.py` | `integration/test_runtime.py`, `integration/test_plugin.py`, `integration/test_route_exclusion.py`, `integration/test_fixture_vocabulary.py`, `examples/test_websocket_admin_modes.py` |

## References

[^testing-py]: `src/litestar_security/testing.py::assert_security_backend_conformance` — `InMemorySecurityBackend`, `FakeClock`, `StoreConformanceFactories`, and conformance suites
[^context-test]: `src/tests/unit/test_context.py` — Subprocess isolation tests verifying accounts and testing kit without optional extras
[^conftest-py]: `src/tests/conftest.py` — Root pytest fixtures: `clock`, `anyio_backend`, and `jwt_key_material`
[^unit-conftest-py]: `src/tests/unit/conftest.py` — Unit-scoped fixtures for `security_backend`, derived stores, and test collaborators
[^typing-helpers]: `src/tests/helpers/typing.py` — Static typing assertion helpers for test modules
[^makefile-cov]: `Makefile` — `CORE_COVERAGE` 100% branch coverage gate and `check-all` target
