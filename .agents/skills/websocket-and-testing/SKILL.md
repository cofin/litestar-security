---
name: websocket-and-testing
description: Use when editing WebSocketSecurityConfig, connect tokens, supervise_websocket_lifetime, testing.py, InMemorySecurityBackend, or src/tests/. Not for OAuth or local account services.
---

# WebSocket Security, Conformance Test Kit, & Test Boundaries

<!-- truth: start -->
- **Canonical Origin & Startup Enforcement**: `WebSocketSecurityConfig.allowed_origins` validates canonical HTTP(S) origins in `__post_init__`. `RouteCompiler.receive_route` fails startup if a `WebSocketRoute` policy includes a `session_capable` mechanism while `allowed_origins` is empty (and forbids `csrf_required` on WebSocket routes). `extract_websocket_handshake` enforces a single canonical `Origin` in `allowed_origins` when `uses_cookie_credentials=True` and validates any `Origin` header present on header-authenticated handshakes (`4403`, `origin_denied`).
- **One-Time Connect Tokens & Query Rules**: `extract_websocket_handshake` extracts only a single non-empty `config.connect_token_query_parameter` (`"connect_token"` default), rejecting invalid percent-encoding, duplicates, blanks, and `RESERVED_QUERY_PARAMETERS` (`access_token`, `authorization`, `bearer`, `jwt`, `token`) with close code `4401`. `WebSocketConnectAuthorization` binds `(connect_token_id, digest, subject_id, security_epoch, route_name, origin, restrictions, policy_fingerprint, issued_at, expires_at)` with TTL bounded by `maximum_connect_token_ttl` (`<= 2m`), atomic consume-once, revalidation of `current_security_epoch`/`route_name`/`origin`/`policy_fingerprint`, and `_merge_connect_token` `restrictions` narrowing.
- **Lifetime Supervision & Close Codes**: `supervise_websocket_lifetime` and `WebSocketCloseCoordinator` close active sockets once on expiry (`4401`, `credential_expired`), `WebSocketRevocationSource.wait(binding)` (`4401`, `credential_revoked`), `AuthorizationSnapshotRefresher` / guard denial (`4403`, `authorization_denied`), or revocation/refresh/epoch outages (`1013`, `verification_unavailable`).
- **Test-Kit Isolation (`R5`) & Un-Gated Exports**: Runtime modules never import `litestar_security.testing` (enforced by Ruff `TID251`, `ban-relative-imports = "all"`, and `tools/check_import_boundaries.py`: `assert 'litestar_security.testing' not in sys.modules` and `assert not hasattr(litestar_security, 'InMemorySecurityBackend')`). `src/litestar_security/__init__.py.__getattr__` resolves only `_OAUTH_EXPORTS`, while `testing.py` exports all 15 `StoreConformanceFactories` suites, `assert_rate_limiter_conformance`, and test doubles directly without optional extras installed.
- **Test Tiers & Fixtures**: Keep new tests in `src/tests/unit/` free of `Litestar`, `TestClient`, and `AsyncTestClient` (pre-existing legacy instances in `test_dto.py` and `test_cli.py` are not to be imitated); keep ASGI/WebSocket tests in `src/tests/integration/` and `src/tests/examples/`, and static `assert_type` checks in `src/tests/helpers/typing.py`.
<!-- truth: end -->

Domain skill for `src/litestar_security/websocket/`, `src/litestar_security/testing.py`, `src/litestar_security/_openapi.py`, `src/tests/`, and `tools/check_*.py`.

## Canonical Modules & Seams

- **WebSocket Transport & Connect Tokens (`websocket/`)**: `WebSocketSecurityConfig`, `WebSocketCloseCodes` (`_config.py`); `WebSocketHandshake`, `WebSocketBinding`, `WebSocketRevocationSource`, `AuthorizationSnapshotRefresher` (`_bindings.py`); `extract_websocket_handshake` (`_handshake.py`); `RESERVED_QUERY_PARAMETERS`, `canonical_origin` (`_internal.py`); `WebSocketConnectAuthorization`, `IssuedWebSocketConnectToken`, `WebSocketConnectTokenStore`, `InMemoryWebSocketConnectTokenStore`, `WebSocketConnectTokenService`, `WebSocketConnectTokenIssuer`, `issue_websocket_connect_token`, `WebSocketConnectTokenUnavailableError` (`_connect_tokens.py`); `WebSocketCloseCoordinator`, `close_websocket`, `supervise_websocket_lifetime`, `websocket_policy_fingerprint` (`_lifecycle.py`); plus `RouteCompiler` (`_openapi.py`) and `SecurityMiddleware._handle_websocket` (`authentication.py`).
- **Shipped Test Kit (`testing.py`)**: `InMemorySecurityBackend`, `FakeClock`, `FakeOAuthProvider`, `FakeOAuthHTTPTransport`, `InMemoryWebSocketRevocationSource`, `InMemoryOIDCSessionLogoutStore`, `StoreConformanceFactories`, `assert_security_backend_conformance` (15 store/protector factories), and standalone `assert_rate_limiter_conformance` (`RateLimiter`). Note `InMemorySecurityBackend.oidc_session_logout` initializes empty mappings so seeded logout tests use standalone `oidc_logout_store` / `collaborators.build_security_environment()`, and `StoreRateLimiter` lives in `litestar_security.accounts` outside `InMemorySecurityBackend.__slots__` and `StoreConformanceFactories`.
- **Fixtures & Boundary Verifiers**: `src/tests/conftest.py` (`clock`, `anyio_backend`, `jwt_key_material`), `src/tests/unit/conftest.py` (`security_backend`, derived stores, `oidc_logout_store`, `rate_limiter`, `secret_protector`, `local_key_ring`, `password_hasher`, `anonymous_principal`), `src/tests/integration/conftest.py`, `src/tests/helpers/typing.py`, `tools/check_import_boundaries.py`, and `tools/check_downstream_consumer.py`.

## Verification Commands

```bash
uv run pytest src/tests/unit/test_websocket/ src/tests/unit/test_in_memory_backend.py src/tests/unit/test_testing_kit.py src/tests/unit/test_context.py src/tests/unit/test_fixture_vocabulary.py src/tests/unit/test_accounts/test_conformance.py -q
uv run pytest src/tests/integration/test_runtime.py src/tests/integration/test_fixture_vocabulary.py src/tests/examples/test_websocket_admin_modes.py -q
uv run python tools/check_import_boundaries.py
uv run slotscheck src/litestar_security/
```

## References

- [Implementation Checklist](./references/checklist.md)
- [False-Positive Suppressions](./references/false-positive-suppressions.md)
- [Test Organization & Store Conformance](../../bundles/knowledge/testing/test-organization-and-conformance.md)
- [ADR-001: Protocol Store Ports Without Runtime Adapters](../../bundles/knowledge/decisions/adr-001-protocol-ports-without-runtime-adapters.md)
