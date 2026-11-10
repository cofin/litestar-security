---
name: review-websocket-and-testing
description: Use when reviewing changes to WebSocketSecurityConfig, connect tokens, supervise_websocket_lifetime, testing.py, or src/tests/. Not for OAuth or local account service reviews.
---

# Review Skill: WebSocket Security, Conformance Test Kit, & Test Suite

<!-- truth: start -->
- **WebSocket Handshake & Origin Rules (`WST-01`, `WST-02`)**: Verify `RouteCompiler.receive_route` blocks `session_capable` WebSocket routes when `allowed_origins` is empty, `extract_websocket_handshake` validates a single canonical `Origin` for cookie credentials (and any present `Origin` on header credentials, closing with `4403` `origin_denied`), `RESERVED_QUERY_PARAMETERS` are unconditionally rejected (`4401`), and `WebSocketConnectAuthorization` binds `(connect_token_id, digest, subject_id, security_epoch, route_name, origin, restrictions, policy_fingerprint, issued_at, expires_at)` with atomic consume-once and epoch/route/origin/policy revalidation.
- **Lifetime Supervision & Outage Mapping (`WST-03`)**: Verify `supervise_websocket_lifetime` and `WebSocketCloseCoordinator` emit one terminal close on expiry (`4401`, `credential_expired`), `WebSocketRevocationSource` signals (`4401`, `credential_revoked`), `AuthorizationSnapshotRefresher` / guard denial (`4403`, `authorization_denied`), or revocation/refresh/epoch outages (`1013`, `verification_unavailable`).
- **Import Boundary & Un-Gated Conformance (`WST-04`, `WST-05`)**: Verify runtime modules never import `litestar_security.testing` (`R5`, Ruff `TID251` + `tools/check_import_boundaries.py`), `StoreConformanceFactories` / `assert_security_backend_conformance` (15 suites) plus standalone `assert_rate_limiter_conformance` match store `Protocol` ports, and `testing.py` works without optional extras (`argon2`, `pyotp`, `webauthn`, `cbor2`).
- **Test Boundaries & `CORE_COVERAGE` (`WST-06`..`WST-08`)**: Reject new `Litestar`/`TestClient`/`AsyncTestClient` calls in `src/tests/unit/` (pre-existing legacy instances in `test_dto.py` and `test_cli.py` are known exceptions not to imitate), verify `FakeClock` determinism and narrow fixture scoping (`src/tests/conftest.py` vs subpackage `conftest.py` vs module-local), and require `100%` branch coverage on `websocket/_connect_tokens.py`.
<!-- truth: end -->

Review capability skill for auditing changes in `src/litestar_security/websocket/`, `src/litestar_security/testing.py`, `src/litestar_security/_openapi.py`, `src/tests/`, and `tools/check_*.py`.

## Review Protocol

1. **Inspect Modified WebSocket & Test Files**: Read the changed files in `src/litestar_security/websocket/`, `src/litestar_security/testing.py`, and `src/tests/`.
2. **Audit Against Checklist (`WST-01`..`WST-08`)**: Check every invariant in [references/checklist.md](./references/checklist.md).
3. **Filter False Positives (`FP-WST-01`..`FP-WST-05`)**: Consult [references/false-positive-suppressions.md](./references/false-positive-suppressions.md) before reporting findings.
4. **Verify Coverage & Boundary Gates**:
   - Confirm `src/litestar_security/websocket/_connect_tokens.py` retains `100%` branch coverage (`CORE_COVERAGE`).
   - Confirm new tests in `src/tests/unit/` contain zero `Litestar`, `TestClient`, or `AsyncTestClient` instantiations.
5. **Run Verification Commands**:
   ```bash
   uv run pytest src/tests/unit/test_websocket/ src/tests/unit/test_in_memory_backend.py src/tests/unit/test_testing_kit.py src/tests/unit/test_context.py src/tests/unit/test_fixture_vocabulary.py src/tests/unit/test_accounts/test_conformance.py src/tests/integration/test_runtime.py src/tests/integration/test_fixture_vocabulary.py src/tests/examples/test_websocket_admin_modes.py -q
   uv run python tools/check_import_boundaries.py
   uv run slotscheck src/litestar_security/
   ```

## Required Finding Format

Report only verified findings anchored to `path/to/file.py:line` with violated check ID (`WST-XX`), concrete failure scenario, and minimal fix.

## References

- [Review Checklist (`WST-01`..`WST-08`)](./references/checklist.md)
- [False-Positive Suppressions (`FP-WST-01`..`FP-WST-05`)](./references/false-positive-suppressions.md)
- [Test Organization & Store Conformance](../../bundles/knowledge/testing/test-organization-and-conformance.md)
- [ADR-001: Protocol Store Ports Without Runtime Adapters](../../bundles/knowledge/decisions/adr-001-protocol-ports-without-runtime-adapters.md)
