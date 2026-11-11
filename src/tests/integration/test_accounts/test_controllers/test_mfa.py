"""HTTP integration coverage for generated MFA, passkey, and step-up controllers."""

from collections.abc import Callable
from datetime import datetime, timezone
from secrets import token_hex
from types import SimpleNamespace
from typing import Any, cast

import pytest
from litestar import Litestar
from litestar.config.csrf import CSRFConfig
from litestar.connection import ASGIConnection
from litestar.middleware.csrf import generate_csrf_token
from litestar.openapi.spec import SecurityScheme
from litestar.routes import HTTPRoute
from litestar.testing import TestClient

from litestar_security import SecurityConfig, SecurityPlugin, accounts
from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    CredentialExtraction,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
    VerificationUnavailable,
)
from litestar_security.context import AuthenticationEvidence, Principal
from tests.fixtures.accounts import AsyncOutcome

_ISSUED_AT = datetime(2026, 7, 27, tzinfo=timezone.utc)
_EXPIRES_AT = datetime(2026, 7, 27, 0, 5, tzinfo=timezone.utc)


def test_route_builder_requires_and_selects_enabled_features() -> None:
    """Verify build_mfa_routes enforces factor presence, cache headers, and transport route selection."""
    with pytest.raises(ValueError, match="At least one"):
        accounts.build_mfa_routes(step_up=cast("Any", object()), epochs=cast("Any", object()))

    mfa_router = accounts.build_mfa_routes(
        step_up=cast("Any", object()), epochs=cast("Any", object()), mfa=cast("Any", object())
    )
    passkey_token_router = accounts.build_mfa_routes(
        step_up=cast("Any", object()), epochs=cast("Any", object()), passkeys=cast("Any", object()), token_capable=True
    )
    passkey_session_router = accounts.build_mfa_routes(
        step_up=cast("Any", object()),
        epochs=cast("Any", object()),
        passkeys=cast("Any", object()),
        session_capable=True,
    )
    hybrid_router = accounts.build_mfa_routes(
        step_up=cast("Any", object()),
        epochs=cast("Any", object()),
        passkeys=cast("Any", object()),
        session_capable=True,
        token_capable=True,
    )

    assert mfa_router.path == passkey_token_router.path == passkey_session_router.path == hybrid_router.path == "/auth"
    assert mfa_router.cache_control is not None
    assert mfa_router.cache_control.no_store is True
    assert {(header.name, header.value) for header in mfa_router.response_headers} == {("Pragma", "no-cache")}
    assert len(hybrid_router.routes) > len(passkey_token_router.routes) > len(mfa_router.routes)
    assert "/auth/passkeys/authentication/verify" in _router_paths(passkey_session_router)
    assert {
        "/auth/passkeys/authentication/session/verify",
        "/auth/passkeys/authentication/tokens/verify",
    } <= _router_paths(hybrid_router)


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("POST", "/auth/step-up/totp-enroll", {"method": "password", "credential": "pw"}),
        ("POST", "/auth/mfa/totp/enroll", {"label": "User", "step_up_grant": "grant"}),
        ("GET", "/auth/passkeys", None),
    ],
    ids=["step-up", "totp-enroll", "passkeys-list"],
)
def test_protected_mfa_and_passkey_routes_require_authentication(
    method: str, path: str, payload: dict[str, str] | None
) -> None:
    """Verify anonymous and malformed-header requests are rejected with HTTP 401."""
    app, _ = _mfa_http_app(_MFAHarness())

    with TestClient(app) as client:
        anonymous = client.request(method, path, json=payload)
        malformed = client.request(method, path, headers={"x-auth": "invalid"}, json=payload)

    assert anonymous.status_code == 401
    assert malformed.status_code == 401


@pytest.mark.parametrize(
    "purpose", ["totp-enroll", "totp-remove", "recovery-codes", "passkey-register", "passkey-remove"]
)
def test_step_up_purposes_accept_strong_factors(purpose: str) -> None:
    """Verify all five allowlisted purposes issue grants for password and passkey factors."""
    harness = _MFAHarness()
    app, _ = _mfa_http_app(harness)
    headers = {"x-auth": "valid", "authorization": "Bearer transport"}

    with TestClient(app) as client:
        password_resp = client.post(
            f"/auth/step-up/{purpose}", headers=headers, json={"method": "password", "credential": "pw"}
        )
        passkey_resp = client.post(
            f"/auth/step-up/{purpose}", headers=headers, json={"method": "passkey", "credential": "{}"}
        )

    assert password_resp.status_code == 200
    assert password_resp.headers["cache-control"] == "no-store"
    assert password_resp.headers["pragma"] == "no-cache"
    assert password_resp.json()["grant"] == "step-up-grant"
    assert password_resp.json()["purpose"] == purpose
    assert passkey_resp.status_code == 200
    assert passkey_resp.json()["purpose"] == purpose


@pytest.mark.parametrize(
    ("purpose", "factor_method", "include_passkeys", "include_local_auth"),
    [
        ("settings", "password", True, True),
        ("totp-enroll", "totp", True, True),
        ("passkey-remove", "recovery-code", True, True),
        ("recovery-codes", "unsupported", True, True),
        ("totp-enroll", "password", True, False),
        ("totp-enroll", "passkey", False, True),
    ],
    ids=[
        "unlisted-purpose",
        "weak-totp",
        "weak-recovery-code",
        "unknown-method",
        "missing-local-auth",
        "missing-passkeys",
    ],
)
def test_step_up_purposes_are_deny_by_default_and_require_configured_strong_factors(
    purpose: str, factor_method: str, *, include_passkeys: bool, include_local_auth: bool
) -> None:
    """Verify unlisted purposes, weak methods, and disabled factor services return sanitized 401 responses."""
    harness = _MFAHarness(enable_passkeys=include_passkeys, enable_local_auth=include_local_auth)
    app, _ = _mfa_http_app(harness)

    with TestClient(app) as client:
        response = client.post(
            f"/auth/step-up/{purpose}",
            headers={"x-auth": "valid", "authorization": "Bearer transport"},
            json={"method": factor_method, "credential": "proof"},
        )

    assert response.status_code == 401
    assert response.json() == {"status_code": 401, "detail": "Authentication required."}


@pytest.mark.parametrize(
    ("factor_method", "expected_operation", "key_mode", "expected_key"),
    [
        ("password", "local.password.verify", "named", "edge-client"),
        ("passkey", "local.passkey.assert", "none", None),
        ("password", "local.password.verify", "error", None),
    ],
    ids=["named-client-key", "no-client-key", "raising-client-key-fallback"],
)
def test_rate_limit_records_client_key_and_degrades_on_callback_failure(
    factor_method: str, expected_operation: str, key_mode: str, expected_key: str | None
) -> None:
    """Verify rate_limits records client_key and degrades raising client_key callbacks to None."""
    rate_limits = _RecordingRateLimits(outcome=None)
    callback = _client_key_callback(key_mode)
    app, _ = _mfa_http_app(_MFAHarness(), rate_limits=rate_limits, client_key=callback)

    with TestClient(app) as client:
        allowed = client.post(
            "/auth/step-up/totp-enroll",
            headers={"x-auth": "valid", "authorization": "Bearer transport"},
            json={"method": factor_method, "credential": "{}"},
        )
        rate_limits.outcome = accounts.RateLimited(3)
        limited_with_hint = client.post(
            "/auth/step-up/totp-enroll",
            headers={"x-auth": "valid", "authorization": "Bearer transport"},
            json={"method": factor_method, "credential": "{}"},
        )
        rate_limits.outcome = accounts.RateLimited()
        limited_without_hint = client.post(
            "/auth/step-up/totp-enroll",
            headers={"x-auth": "valid", "authorization": "Bearer transport"},
            json={"method": factor_method, "credential": "{}"},
        )

    assert allowed.status_code == 200
    assert limited_with_hint.status_code == 429
    assert limited_with_hint.json() == {"status_code": 429, "detail": "Too many requests."}
    assert limited_with_hint.headers["retry-after"] == "3"
    assert limited_without_hint.status_code == 429
    assert limited_without_hint.headers.get("retry-after") is None
    assert rate_limits.calls == [(expected_operation, expected_key, "account-1")] * 3


@pytest.mark.parametrize(
    ("method", "path", "payload", "authenticated"),
    [
        ("POST", "/auth/mfa/totp/enroll", {"label": "User", "step_up_grant": "grant"}, True),
        ("POST", "/auth/mfa/totp/verify", {"enrollment_id": "e1", "code": "123456"}, True),
        ("POST", "/auth/mfa/totp/m1/remove", {"step_up_grant": "grant"}, True),
        ("POST", "/auth/mfa/recovery-codes", {"step_up_grant": "grant"}, True),
        ("POST", "/auth/passkeys/registration/options", {"user_name": "User", "step_up_grant": "grant"}, True),
        ("POST", "/auth/passkeys/registration/verify", {"account_id": "account-1", "response": "{}"}, True),
        ("POST", "/auth/passkeys/authentication/options", {"account_id": "account-1"}, False),
        ("POST", "/auth/passkeys/Y3JlZGVudGlhbA/remove", {"step_up_grant": "grant"}, True),
        ("POST", "/auth/passkeys/authentication/verify", {"account_id": "account-1", "response": "{}"}, False),
    ],
)
def test_rate_limit_outcomes_apply_across_all_mfa_and_passkey_mutations(
    method: str, path: str, payload: dict[str, str], *, authenticated: bool
) -> None:
    """Verify every rate-limited MFA and passkey route maps RateLimited and VerificationUnavailable cleanly."""
    rate_limits = _RecordingRateLimits(outcome=accounts.RateLimited(5))
    app, _ = _mfa_http_app(_MFAHarness(), rate_limits=rate_limits, token_capable=True)
    headers = {"x-auth": "valid", "authorization": "Bearer transport"} if authenticated else {}

    with TestClient(app) as client:
        limited = client.request(method, path, headers=headers, json=payload)
        rate_limits.outcome = VerificationUnavailable()
        unavailable = client.request(method, path, headers=headers, json=payload)

    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "5"
    assert unavailable.status_code == 503
    assert unavailable.json() == {"status_code": 503, "detail": "Authentication service is unavailable."}


@pytest.mark.parametrize(
    ("extra_headers", "expected_binding"),
    [
        ({"authorization": "Bearer transport", "cookie": "session=ignored"}, b"Bearer transport"),
        ({"cookie": "session=value"}, b"session=value"),
        ({}, b""),
    ],
    ids=["authorization-precedence", "cookie-fallback", "empty-binding"],
)
def test_transport_binding_extraction_precedence_over_http(
    extra_headers: dict[str, str], expected_binding: bytes
) -> None:
    """Verify Authorization takes precedence over Cookie and absent transport yields empty bytes."""
    harness = _MFAHarness()
    app, _ = _mfa_http_app(harness)
    headers = {"x-auth": "valid", **extra_headers}

    with TestClient(app) as client:
        issued = client.post(
            "/auth/step-up/passkey-register", headers=headers, json={"method": "passkey", "credential": "{}"}
        )
        options = client.post(
            "/auth/passkeys/registration/options",
            headers=headers,
            json={"user_name": "User", "step_up_grant": "step-up-grant"},
        )
        verified = client.post(
            "/auth/passkeys/registration/verify", headers=headers, json={"account_id": "account-1", "response": "{}"}
        )

    assert issued.status_code == 200
    assert options.status_code == 200
    assert verified.status_code == 201
    assert harness.bindings == [
        ("passkeys.verify_authentication", expected_binding),
        ("step_up.issue", expected_binding),
        ("step_up.consume", expected_binding),
        ("passkeys.begin_registration", expected_binding),
        ("passkeys.verify_registration", expected_binding),
    ]


def test_empty_transport_binding_rejected_by_step_up_service_returns_unauthorized() -> None:
    """Verify routes fail closed with 401 when step_up rejects an empty transport binding."""
    harness = _MFAHarness()
    harness.reject_empty_binding = True
    app, _ = _mfa_http_app(harness)

    with TestClient(app) as client:
        issued = client.post(
            "/auth/step-up/totp-enroll", headers={"x-auth": "valid"}, json={"method": "password", "credential": "pw"}
        )
        consumed = client.post(
            "/auth/mfa/totp/enroll", headers={"x-auth": "valid"}, json={"label": "User", "step_up_grant": "grant"}
        )

    assert issued.status_code == 401
    assert consumed.status_code == 401


@pytest.mark.parametrize(
    "bad_epoch", [False, -1, OSError("epoch backend offline")], ids=["bool-epoch", "negative-epoch", "oserror-epoch"]
)
def test_epoch_failures_sanitize_to_service_unavailable(bad_epoch: object) -> None:
    """Verify invalid or raising security epochs map to sanitized 503 responses on issue and consume."""
    harness = _MFAHarness()
    harness.epochs.current_epoch = AsyncOutcome(bad_epoch, bad_epoch)
    app, _ = _mfa_http_app(harness)
    headers = {"x-auth": "valid", "authorization": "Bearer transport"}

    with TestClient(app) as client:
        issued = client.post(
            "/auth/step-up/totp-enroll", headers=headers, json={"method": "password", "credential": "pw"}
        )
        consumed = client.post(
            "/auth/mfa/totp/enroll", headers=headers, json={"label": "User", "step_up_grant": "grant"}
        )

    assert issued.status_code == 503
    assert issued.json() == {"status_code": 503, "detail": "Authentication service is unavailable."}
    assert "offline" not in issued.text
    assert consumed.status_code == 503
    assert consumed.json() == {"status_code": 503, "detail": "Authentication service is unavailable."}


def test_step_up_factor_and_issuance_outcomes_sanitize_errors() -> None:
    """Verify password, passkey, and grant issuance failures map to sanitized 401 and 503 responses."""
    harness = _MFAHarness()
    harness.password_outcomes = AsyncOutcome(
        InvalidCredentials(), VerificationUnavailable(), _password_proof(), _password_proof()
    )
    harness.passkey_auth_outcomes = AsyncOutcome(InvalidCredentials(), VerificationUnavailable())
    harness.step_up_issue_outcomes = AsyncOutcome(InvalidCredentials(), VerificationUnavailable())
    app, _ = _mfa_http_app(harness)
    headers = {"x-auth": "valid", "authorization": "Bearer transport"}

    with TestClient(app) as client:
        pw_invalid = client.post(
            "/auth/step-up/totp-enroll", headers=headers, json={"method": "password", "credential": "bad"}
        )
        pw_unavailable = client.post(
            "/auth/step-up/totp-enroll", headers=headers, json={"method": "password", "credential": "pw"}
        )
        pk_invalid = client.post(
            "/auth/step-up/passkey-remove", headers=headers, json={"method": "passkey", "credential": "{}"}
        )
        pk_unavailable = client.post(
            "/auth/step-up/passkey-remove", headers=headers, json={"method": "passkey", "credential": "{}"}
        )
        issue_invalid = client.post(
            "/auth/step-up/recovery-codes", headers=headers, json={"method": "password", "credential": "pw"}
        )
        issue_unavailable = client.post(
            "/auth/step-up/recovery-codes", headers=headers, json={"method": "password", "credential": "pw"}
        )

    assert (pw_invalid.status_code, pw_unavailable.status_code) == (401, 503)
    assert (pk_invalid.status_code, pk_unavailable.status_code) == (401, 503)
    assert (issue_invalid.status_code, issue_unavailable.status_code) == (401, 503)


def test_mfa_totp_and_recovery_endpoints_project_typed_outcomes_and_errors() -> None:
    """Verify TOTP enroll, verify, and recovery-code replacement project grants and sanitize failures."""
    harness = _MFAHarness()
    harness.step_up_consume_outcomes = AsyncOutcome(
        _factor_evidence(),
        InvalidCredentials(),
        _factor_evidence(),
        _factor_evidence(),
        InvalidCredentials(),
        _factor_evidence(),
        _factor_evidence(),
    )
    harness.totp_enroll_outcomes = AsyncOutcome(_provisioning_grant(), VerificationUnavailable())
    harness.totp_activate_outcomes = AsyncOutcome(
        accounts.RecoveryCodeGrant(codes=("rc_v1_00000000000000000000000000000000",)),
        InvalidCredentials(),
        VerificationUnavailable(),
    )
    harness.recovery_replace_outcomes = AsyncOutcome(
        accounts.RecoveryCodeGrant(codes=("rc_v1_11111111111111111111111111111111",)),
        InvalidCredentials(),
        VerificationUnavailable(),
    )
    app, _ = _mfa_http_app(harness)
    headers = {"x-auth": "valid", "authorization": "Bearer transport"}

    with TestClient(app) as client:
        enrolled = client.post(
            "/auth/mfa/totp/enroll", headers=headers, json={"label": "User", "step_up_grant": "grant"}
        )
        enroll_denied = client.post(
            "/auth/mfa/totp/enroll", headers=headers, json={"label": "User", "step_up_grant": "bad"}
        )
        enroll_unavailable = client.post(
            "/auth/mfa/totp/enroll", headers=headers, json={"label": "User", "step_up_grant": "grant"}
        )
        verified = client.post("/auth/mfa/totp/verify", headers=headers, json={"enrollment_id": "e1", "code": "123456"})
        verify_invalid = client.post(
            "/auth/mfa/totp/verify", headers=headers, json={"enrollment_id": "e1", "code": "000000"}
        )
        verify_unavailable = client.post(
            "/auth/mfa/totp/verify", headers=headers, json={"enrollment_id": "e1", "code": "123456"}
        )
        replaced = client.post("/auth/mfa/recovery-codes", headers=headers, json={"step_up_grant": "grant"})
        replace_step_up_denied = client.post("/auth/mfa/recovery-codes", headers=headers, json={"step_up_grant": "bad"})
        replace_invalid = client.post("/auth/mfa/recovery-codes", headers=headers, json={"step_up_grant": "grant"})
        replace_unavailable = client.post("/auth/mfa/recovery-codes", headers=headers, json={"step_up_grant": "grant"})

    assert enrolled.status_code == 201
    assert enrolled.json()["enrollment_id"] == "enrollment-1"
    assert (enroll_denied.status_code, enroll_unavailable.status_code) == (401, 503)
    assert verified.status_code == 200
    assert verified.json() == {"codes": ["rc_v1_00000000000000000000000000000000"]}
    assert (verify_invalid.status_code, verify_unavailable.status_code) == (401, 503)
    assert replaced.status_code == 200
    assert replaced.json() == {"codes": ["rc_v1_11111111111111111111111111111111"]}
    assert (replace_step_up_denied.status_code, replace_invalid.status_code, replace_unavailable.status_code) == (
        401,
        401,
        503,
    )


@pytest.mark.parametrize("path", ["/auth/mfa/totp/m1/remove", "/auth/passkeys/Y3JlZGVudGlhbA/remove"])
@pytest.mark.parametrize(
    ("outcome", "expected_status", "expected_body"),
    [
        (
            accounts.RevokeLoginMethodOutcome(accounts.RevokeLoginMethodStatus.REVOKED),
            200,
            {"detail": "Login method removed."},
        ),
        (
            accounts.RevokeLoginMethodOutcome(accounts.RevokeLoginMethodStatus.FINAL_METHOD),
            409,
            {"detail": "At least one viable login method is required."},
        ),
        (
            accounts.RevokeLoginMethodOutcome(accounts.RevokeLoginMethodStatus.NOT_FOUND),
            400,
            {"detail": "The request is invalid."},
        ),
        (VerificationUnavailable(), 503, {"status_code": 503, "detail": "Authentication service is unavailable."}),
    ],
    ids=["revoked", "final-method", "not-found", "unavailable"],
)
def test_removal_outcomes_keep_their_http_classification(
    path: str, outcome: object, expected_status: int, expected_body: dict[str, object]
) -> None:
    """Verify TOTP and passkey removal endpoints map REVOKED, FINAL_METHOD, NOT_FOUND, and unavailable outcomes."""
    harness = _MFAHarness()
    harness.totp_remove_outcomes = AsyncOutcome(outcome)
    harness.passkey_remove_outcomes = AsyncOutcome(outcome)
    app, _ = _mfa_http_app(harness)

    with TestClient(app) as client:
        response = client.post(
            path, headers={"x-auth": "valid", "authorization": "Bearer transport"}, json={"step_up_grant": "grant"}
        )

    assert response.status_code == expected_status
    assert response.json() == expected_body


def test_passkey_ceremony_inventory_and_removal_validation_over_http() -> None:
    """Verify passkey options, registration, safe listing, step-up denial, and malformed base64 removal."""
    harness = _MFAHarness()
    harness.step_up_consume_outcomes = AsyncOutcome(
        InvalidCredentials(), _factor_evidence(), InvalidCredentials(), _factor_evidence(), InvalidCredentials()
    )
    harness.reg_options_outcomes = AsyncOutcome(VerificationUnavailable())
    harness.reg_verify_outcomes = AsyncOutcome(
        SimpleNamespace(credential_id=b"credential"), InvalidCredentials(), VerificationUnavailable()
    )
    harness.auth_options_outcomes = AsyncOutcome(_webauthn_options(), VerificationUnavailable())
    harness.list_outcomes = AsyncOutcome((_passkey_metadata(),), VerificationUnavailable())
    app, _ = _mfa_http_app(harness)
    headers = {"x-auth": "valid", "authorization": "Bearer transport"}

    with TestClient(app) as client:
        reg_step_up_denied = client.post(
            "/auth/passkeys/registration/options", headers=headers, json={"user_name": "User", "step_up_grant": "bad"}
        )
        reg_options_503 = client.post(
            "/auth/passkeys/registration/options", headers=headers, json={"user_name": "User", "step_up_grant": "ok"}
        )
        reg_ok = client.post(
            "/auth/passkeys/registration/verify", headers=headers, json={"account_id": "account-1", "response": "{}"}
        )
        reg_mismatch = client.post(
            "/auth/passkeys/registration/verify", headers=headers, json={"account_id": "other", "response": "{}"}
        )
        reg_invalid = client.post(
            "/auth/passkeys/registration/verify", headers=headers, json={"account_id": "account-1", "response": "{}"}
        )
        reg_unavailable = client.post(
            "/auth/passkeys/registration/verify", headers=headers, json={"account_id": "account-1", "response": "{}"}
        )
        auth_opts = client.post("/auth/passkeys/authentication/options", json={"account_id": "account-1"})
        auth_opts_503 = client.post("/auth/passkeys/authentication/options", json={"account_id": "account-1"})
        listed = client.get("/auth/passkeys", headers=headers)
        listed_503 = client.get("/auth/passkeys", headers=headers)
        totp_remove_denied = client.post("/auth/mfa/totp/m1/remove", headers=headers, json={"step_up_grant": "bad"})
        bad_b64 = client.post("/auth/passkeys/a/remove", headers=headers, json={"step_up_grant": "grant"})
        pk_remove_denied = client.post(
            "/auth/passkeys/Y3JlZGVudGlhbA/remove", headers=headers, json={"step_up_grant": "bad"}
        )

    assert (reg_step_up_denied.status_code, reg_options_503.status_code) == (401, 503)
    assert reg_ok.status_code == 201
    assert reg_ok.json() == {"detail": "Passkey registered."}
    assert (reg_mismatch.status_code, reg_invalid.status_code, reg_unavailable.status_code) == (401, 401, 503)
    assert auth_opts.status_code == 200
    assert isinstance(auth_opts.json()["binding"], str)
    assert auth_opts.json()["binding"] != ""
    assert auth_opts_503.status_code == 503
    assert listed.status_code == 200
    assert listed.json()[0]["credential_id"] == "Y3JlZGVudGlhbA"
    assert "public_key" not in listed.text
    assert listed_503.status_code == 503
    assert (totp_remove_denied.status_code, bad_b64.status_code, pk_remove_denied.status_code) == (401, 400, 401)
    assert bad_b64.json() == {"detail": "The request is invalid."}


@pytest.mark.parametrize(
    ("session_capable", "token_capable"), [(True, False), (False, True)], ids=["session-only", "tokens-only"]
)
def test_passkey_single_transport_authentication_verify_enforces_csrf_and_transport(
    *, session_capable: bool, token_capable: bool
) -> None:
    """Verify single-transport passkey verification requires CSRF only when session-capable."""
    harness = _MFAHarness()
    app, csrf_key = _mfa_http_app(harness, session_capable=session_capable, token_capable=token_capable)
    requested_transport = "session" if session_capable else "tokens"
    payload = {
        "account_id": "account-1",
        "response": "{}",
        "binding": "ceremony-binding",
        "transport": requested_transport,
    }

    with TestClient(app) as client:
        without_csrf = client.post("/auth/passkeys/authentication/verify", json=payload)
        if session_capable:
            assert without_csrf.status_code == 403
            csrf_headers = _seed_csrf(client, csrf_key)
            verified = client.post("/auth/passkeys/authentication/verify", headers=csrf_headers, json=payload)
        else:
            verified = without_csrf

    assert verified.status_code == 200
    assert verified.json() == {"account_id": "account-1", "display_name": None}
    assert harness.transports == [requested_transport]


def test_passkey_hybrid_authentication_verify_splits_csrf_and_fixes_transport() -> None:
    """Verify hybrid passkey authentication fixes transport by route and enforces CSRF on session verify."""
    harness = _MFAHarness()
    app, csrf_key = _mfa_http_app(harness, session_capable=True, token_capable=True)
    token_payload = {"account_id": "account-1", "response": "{}", "binding": "b1", "transport": "session"}
    session_payload = {"account_id": "account-1", "response": "{}", "binding": "b2", "transport": "tokens"}

    with TestClient(app) as client:
        single_route = client.post("/auth/passkeys/authentication/verify", json=token_payload)
        token_ok = client.post("/auth/passkeys/authentication/tokens/verify", json=token_payload)
        session_blocked = client.post("/auth/passkeys/authentication/session/verify", json=session_payload)
        csrf_headers = _seed_csrf(client, csrf_key)
        session_ok = client.post(
            "/auth/passkeys/authentication/session/verify", headers=csrf_headers, json=session_payload
        )

    assert single_route.status_code == 404
    assert token_ok.status_code == 200
    assert session_blocked.status_code == 403
    assert session_ok.status_code == 200
    assert harness.transports == ["tokens", "session"]


def test_passkey_authentication_verify_sanitizes_missing_binding_and_login_failures() -> None:
    """Verify passkey authentication rejects missing bindings and sanitizes factor or login failures."""
    harness = _MFAHarness()
    harness.passkey_auth_outcomes = AsyncOutcome(
        InvalidCredentials(), VerificationUnavailable(), _factor_evidence(), _factor_evidence()
    )
    harness.passkey_login_outcomes = AsyncOutcome(InvalidCredentials(), VerificationUnavailable())
    app, _ = _mfa_http_app(harness, token_capable=True)

    with TestClient(app) as client:
        missing_binding = client.post(
            "/auth/passkeys/authentication/verify", json={"account_id": "account-1", "response": "{}"}
        )
        factor_invalid = client.post(
            "/auth/passkeys/authentication/verify", json={"account_id": "account-1", "response": "{}", "binding": "b1"}
        )
        factor_unavailable = client.post(
            "/auth/passkeys/authentication/verify", json={"account_id": "account-1", "response": "{}", "binding": "b1"}
        )
        login_invalid = client.post(
            "/auth/passkeys/authentication/verify", json={"account_id": "account-1", "response": "{}", "binding": "b1"}
        )
        login_unavailable = client.post(
            "/auth/passkeys/authentication/verify", json={"account_id": "account-1", "response": "{}", "binding": "b1"}
        )

    assert missing_binding.status_code == 401
    assert (factor_invalid.status_code, factor_unavailable.status_code) == (401, 503)
    assert (login_invalid.status_code, login_unavailable.status_code) == (401, 503)


class _HeaderSlot:
    def __init__(self, name: str = "header", header: str = "x-auth") -> None:
        self.name = name
        self.header = header

    def extract(self, connection: ASGIConnection[Any, Any, Any, Any]) -> CredentialExtraction[str]:
        value = connection.headers.get(self.header)
        if value is None:
            return NoCredentials()
        if value != "valid":
            return InvalidCredentials()
        return PresentedCredential("account-1")


class _HeaderAuthenticator:
    participates_by_default = True

    def __init__(self, name: str = "header", slot: str = "header") -> None:
        self.name = name
        self.slot = slot

    async def authenticate(self, credential: str, connection: ASGIConnection[Any, Any, Any, Any]) -> Authenticated[str]:
        del connection
        return Authenticated(
            claims=credential,
            evidence=AuthenticationEvidence(mechanism=self.name, slot=self.slot, authenticated_at=_ISSUED_AT),
        )


class _AccountResolver:
    async def resolve(self, claims: str) -> Principal[object]:
        return Principal(id=claims)


class _RecordingRateLimits:
    def __init__(self, outcome: object = None) -> None:
        self.outcome = outcome
        self.calls: list[tuple[str, str | None, str | None]] = []

    async def check(self, operation: str, *, client_key: str | None = None, identifier: str | None = None) -> object:
        self.calls.append((operation, client_key, identifier))
        return self.outcome


class _MFAHarness:
    def __init__(self, *, enable_passkeys: bool = True, enable_local_auth: bool = True) -> None:
        self.enable_passkeys = enable_passkeys
        self.enable_local_auth = enable_local_auth
        self.reject_empty_binding = False
        self.bindings: list[tuple[str, bytes]] = []
        self.transports: list[str | None] = []
        self.epochs = SimpleNamespace(current_epoch=self._default_epoch)
        self.password_outcomes: AsyncOutcome | None = None
        self.passkey_auth_outcomes: AsyncOutcome | None = None
        self.passkey_login_outcomes: AsyncOutcome | None = None
        self.step_up_issue_outcomes: AsyncOutcome | None = None
        self.step_up_consume_outcomes: AsyncOutcome | None = None
        self.totp_enroll_outcomes: AsyncOutcome | None = None
        self.totp_activate_outcomes: AsyncOutcome | None = None
        self.totp_remove_outcomes: AsyncOutcome | None = None
        self.recovery_replace_outcomes: AsyncOutcome | None = None
        self.reg_options_outcomes: AsyncOutcome | None = None
        self.reg_verify_outcomes: AsyncOutcome | None = None
        self.auth_options_outcomes: AsyncOutcome | None = None
        self.list_outcomes: AsyncOutcome | None = None
        self.passkey_remove_outcomes: AsyncOutcome | None = None
        self.step_up = SimpleNamespace(issue=self.issue_step_up, consume=self.consume_step_up)
        self.mfa = SimpleNamespace(
            begin_totp_enrollment=self.begin_totp_enrollment,
            activate_totp_with_recovery_codes=self.activate_totp_with_recovery_codes,
            remove_totp_method=self.remove_totp_method,
            generate_recovery_codes=self.generate_recovery_codes,
        )
        self.passkeys = (
            SimpleNamespace(
                verify_authentication=self.verify_authentication,
                begin_registration=self.begin_registration,
                verify_registration=self.verify_registration,
                begin_authentication=self.begin_authentication,
                list_credentials=self.list_credentials,
                remove_credential=self.remove_credential,
            )
            if enable_passkeys
            else None
        )
        self.local_auth = (
            SimpleNamespace(
                password_reauthentication=SimpleNamespace(verify=self.verify_password), passkey_login=self.passkey_login
            )
            if enable_local_auth
            else None
        )

    async def issue_step_up(self, **kwargs: Any) -> object:
        binding = cast("bytes", kwargs["transport_binding"])
        purpose = cast("str", kwargs["purpose"])
        self.bindings.append(("step_up.issue", binding))
        if self.reject_empty_binding and not binding:
            return InvalidCredentials()
        if self.step_up_issue_outcomes is not None:
            return await self.step_up_issue_outcomes()
        return accounts.StepUpCredential(
            token="step-up-grant",  # noqa: S106
            purpose=purpose,
            expires_at=_EXPIRES_AT,
        )

    async def consume_step_up(self, _grant: str, **kwargs: Any) -> object:
        binding = cast("bytes", kwargs["transport_binding"])
        self.bindings.append(("step_up.consume", binding))
        if self.reject_empty_binding and not binding:
            return InvalidCredentials()
        if self.step_up_consume_outcomes is not None:
            return await self.step_up_consume_outcomes()
        return _factor_evidence()

    async def verify_password(self, account_id: str, password: str) -> object:
        del account_id, password
        if self.password_outcomes is not None:
            return await self.password_outcomes()
        return _password_proof()

    async def passkey_login(
        self, request: object, account_id: str, *, transport: str | None, evidence: object
    ) -> object:
        del request, evidence
        self.transports.append(transport)
        if self.passkey_login_outcomes is not None:
            return await self.passkey_login_outcomes()
        return accounts.LocalAccount(account_id=account_id)

    async def begin_totp_enrollment(self, account_id: str, *, label: str) -> object:
        del account_id, label
        if self.totp_enroll_outcomes is not None:
            return await self.totp_enroll_outcomes()
        return _provisioning_grant()

    async def activate_totp_with_recovery_codes(self, account_id: str, enrollment_id: str, code: str) -> object:
        del account_id, enrollment_id, code
        if self.totp_activate_outcomes is not None:
            return await self.totp_activate_outcomes()
        return accounts.RecoveryCodeGrant(codes=("rc_v1_00000000000000000000000000000000",))

    async def remove_totp_method(self, account_id: str, method_id: str) -> object:
        del account_id, method_id
        if self.totp_remove_outcomes is not None:
            return await self.totp_remove_outcomes()
        return accounts.RevokeLoginMethodOutcome(accounts.RevokeLoginMethodStatus.REVOKED)

    async def generate_recovery_codes(self, account_id: str) -> object:
        del account_id
        if self.recovery_replace_outcomes is not None:
            return await self.recovery_replace_outcomes()
        return accounts.RecoveryCodeGrant(codes=("rc_v1_00000000000000000000000000000000",))

    async def verify_authentication(self, account_id: str, *, binding: bytes, response: str) -> object:
        del account_id, response
        self.bindings.append(("passkeys.verify_authentication", binding))
        if self.passkey_auth_outcomes is not None:
            return await self.passkey_auth_outcomes()
        return _factor_evidence()

    async def begin_registration(self, account_id: str, *, user_name: str, binding: bytes) -> object:
        del account_id, user_name
        self.bindings.append(("passkeys.begin_registration", binding))
        if self.reg_options_outcomes is not None:
            return await self.reg_options_outcomes()
        return _webauthn_options()

    async def verify_registration(self, account_id: str, *, binding: bytes, response: str) -> object:
        del account_id, response
        self.bindings.append(("passkeys.verify_registration", binding))
        if self.reg_verify_outcomes is not None:
            return await self.reg_verify_outcomes()
        return SimpleNamespace(credential_id=b"credential")

    async def begin_authentication(self, account_id: str, *, binding: bytes) -> object:
        del account_id
        self.bindings.append(("passkeys.begin_authentication", binding))
        if self.auth_options_outcomes is not None:
            return await self.auth_options_outcomes()
        return _webauthn_options()

    async def list_credentials(self, account_id: str) -> object:
        del account_id
        if self.list_outcomes is not None:
            return await self.list_outcomes()
        return (_passkey_metadata(),)

    async def remove_credential(self, account_id: str, credential_id: bytes) -> object:
        del account_id
        assert credential_id == b"credential"
        if self.passkey_remove_outcomes is not None:
            return await self.passkey_remove_outcomes()
        return accounts.RevokeLoginMethodOutcome(accounts.RevokeLoginMethodStatus.REVOKED)

    @staticmethod
    async def _default_epoch(_account_id: str) -> int:
        return 1


def _password_proof() -> accounts.PasswordReauthenticationProof:
    return accounts.PasswordReauthenticationProof(
        account_id="account-1", security_epoch=1, authenticated_at=_ISSUED_AT, expires_at=_EXPIRES_AT
    )


def _factor_evidence() -> AuthenticationEvidence:
    return AuthenticationEvidence(
        mechanism="totp", slot="mfa", authenticated_at=_ISSUED_AT, methods=frozenset({"totp"})
    )


def _provisioning_grant() -> accounts.TOTPProvisioningGrant:
    return accounts.TOTPProvisioningGrant(
        enrollment_id="enrollment-1",
        method_id="method-1",
        provisioning_uri="otpauth://totp/Example?secret=SECRET",
        expires_at=_EXPIRES_AT,
    )


def _webauthn_options() -> accounts.WebAuthnOptions:
    return accounts.WebAuthnOptions(challenge="challenge", json='{"challenge":"challenge"}', expires_at=_EXPIRES_AT)


def _passkey_metadata() -> accounts.PasskeyMetadata:
    return accounts.PasskeyMetadata(
        credential_id="Y3JlZGVudGlhbA",
        display_name="Laptop",
        backup_eligible=True,
        backup_state=False,
        suspect=False,
        created_at=_ISSUED_AT,
        last_used_at=None,
    )


def _client_key_callback(mode: str) -> Callable[[ASGIConnection[Any, Any, Any, Any]], str | None] | None:
    if mode == "none":
        return None
    if mode == "named":
        return lambda _request: "edge-client"

    def _fail(_request: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        raise RuntimeError

    return _fail


def _router_paths(router: Any) -> set[str]:
    return {route.path for route in router.routes if isinstance(route, HTTPRoute)}


def _seed_csrf(client: TestClient[Litestar], csrf_key: str) -> dict[str, str]:
    value = generate_csrf_token(csrf_key)
    client.cookies.set("csrftoken", value)
    return {"x-csrftoken": value}


def _mfa_http_app(
    harness: _MFAHarness,
    *,
    rate_limits: _RecordingRateLimits | None = None,
    client_key: Callable[[ASGIConnection[Any, Any, Any, Any]], str | None] | None = None,
    session_capable: bool = False,
    token_capable: bool = False,
) -> tuple[Litestar, str]:
    csrf_key = token_hex()
    router = accounts.build_mfa_routes(
        step_up=cast("Any", harness.step_up),
        epochs=cast("Any", harness.epochs),
        mfa=cast("Any", harness.mfa),
        passkeys=cast("Any", harness.passkeys),
        rate_limits=cast("Any", rate_limits),
        client_key=client_key,
        local_auth=cast("Any", harness.local_auth),
        session_capable=session_capable,
        token_capable=token_capable,
    )
    security = SecurityConfig(
        slots=(_HeaderSlot(),),
        mechanisms=(
            AuthenticationMechanism(
                authenticator=_HeaderAuthenticator(),
                resolver=_AccountResolver(),
                scheme_name="HeaderAuth",
                security_scheme=SecurityScheme(type="apiKey", name="x-auth", security_scheme_in="header"),
                session_capable=False,
            ),
        ),
    )
    app = Litestar(
        route_handlers=[router],
        csrf_config=CSRFConfig(secret=csrf_key) if session_capable else None,
        openapi_config=None,
        plugins=[SecurityPlugin(security)],
    )
    return app, csrf_key
