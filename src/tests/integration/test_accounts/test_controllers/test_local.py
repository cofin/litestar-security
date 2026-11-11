"""HTTP integration coverage for the generated local-auth controller graph."""

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
from litestar.testing import TestClient

from litestar_security import SecurityConfig, SecurityPlugin, accounts
from litestar_security._docs import RouteDocs
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

_ISSUED_AT = datetime(2026, 7, 26, tzinfo=timezone.utc)
_EXPIRES_AT = datetime(2026, 7, 27, tzinfo=timezone.utc)
_SESSION_ID = "A" * 43


def test_local_route_schemas_redact_every_secret_they_carry() -> None:
    """Verify every secret-bearing local route schema redacts credentials in repr()."""
    secret = "s3cr3t-value"  # noqa: S105
    identifier = "user@example.com"
    schemas = (
        accounts.LocalCredentials(identifier=identifier, password=secret),
        accounts.LocalRegistration(identifier=identifier, password=secret, display_name="User"),
        accounts.LocalInvitationRegistration(identifier=identifier, password=secret, invitation_token=secret),
        accounts.LocalToken(token=secret),
        accounts.LocalPasswordReset(token=secret, password=secret),
        accounts.LocalPasswordChange(current_password=secret, password=secret, compromise=True),
    )

    rendered = {type(schema).__name__: repr(schema) for schema in schemas}
    assert {name: value for name, value in rendered.items() if secret in value} == {}
    assert all(name in value for name, value in rendered.items())
    assert identifier in repr(schemas[0])
    assert "compromise=True" in repr(schemas[-1])


@pytest.mark.parametrize(
    ("mode", "registration", "expected_names"),
    [
        (
            accounts.LocalAuthMode.SESSION,
            accounts.RegistrationMode.PUBLIC,
            {"local.session.login", "local.session.logout", "local.registration"},
        ),
        (
            accounts.LocalAuthMode.TOKENS,
            accounts.RegistrationMode.INVITE_ONLY,
            {"local.token.login", "local.token.refresh", "local.registration"},
        ),
        (
            accounts.LocalAuthMode.HYBRID,
            accounts.RegistrationMode.DISABLED,
            {"local.session.login", "local.token.login", "local.session.password.change"},
        ),
    ],
)
def test_route_graph_follows_transport_and_registration_policy(
    mode: accounts.LocalAuthMode, registration: accounts.RegistrationMode, expected_names: set[str]
) -> None:
    """Verify build_local_auth_routes mounts only controllers enabled by mode and registration policy."""
    config = SimpleNamespace(
        mode=mode,
        registration=SimpleNamespace(mode=registration),
        local_auth_service=object(),
        mfa_login=None,
        route_prefix="/auth",
        docs=RouteDocs(),
    )

    router = accounts.build_local_auth_routes(cast("Any", config))
    names = {handler.name for route in router.routes for handler in route.route_handlers if handler.name is not None}

    assert expected_names <= names
    assert router.path == "/auth"
    assert router.cache_control is not None
    assert router.cache_control.no_store is True
    assert {(header.name, header.value) for header in router.response_headers} == {("Pragma", "no-cache")}


def test_session_login_and_recovery_project_typed_outcomes_over_http() -> None:
    """Verify session login enforces CSRF and maps outcomes alongside password recovery."""
    service = SimpleNamespace(
        session_login=AsyncOutcome(accounts.LocalAccount("account-1"), InvalidCredentials(), VerificationUnavailable()),
        recovery=SimpleNamespace(request=AsyncOutcome(accounts.LifecycleAccepted(), accounts.RateLimited(7))),
        client_key_for=lambda _request: "1.2.3.4",
    )
    app, csrf_key = _local_http_app(service, mode=accounts.LocalAuthMode.SESSION)
    credentials = {"identifier": "user@example.com", "password": "secret"}

    with TestClient(app) as client:
        missing_csrf = client.post("/auth/login", json=credentials)
        csrf_headers = _seed_csrf(client, csrf_key)
        signed_in = client.post("/auth/login", headers=csrf_headers, json=credentials)
        rejected = client.post("/auth/login", headers=csrf_headers, json=credentials)
        unavailable = client.post("/auth/login", headers=csrf_headers, json=credentials)
        accepted = client.post("/auth/password/recovery", json={"identifier": "user@example.com"})
        limited = client.post("/auth/password/recovery", json={"identifier": "user@example.com"})

    assert missing_csrf.status_code == 403
    assert signed_in.status_code == 200
    assert signed_in.headers["cache-control"] == "no-store"
    assert signed_in.headers["pragma"] == "no-cache"
    assert signed_in.json() == {"account_id": "account-1", "display_name": None}
    assert rejected.status_code == 401
    assert rejected.json() == {"status_code": 401, "detail": "Authentication required."}
    assert unavailable.status_code == 503
    assert accepted.status_code == 202
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "7"


def test_session_logout_list_and_revoke_enforce_csrf_and_sanitize_errors() -> None:
    """Verify session logout, inventory, and revocation over HTTP with CSRF and null-service branches."""
    summary = accounts.SessionSummary(
        session_id=_SESSION_ID,
        current=True,
        created_at=_ISSUED_AT,
        last_seen_at=_ISSUED_AT,
        expires_at=_EXPIRES_AT,
        display_metadata={"device": "laptop"},
    )
    current_calls = iter([None, SimpleNamespace(session_id=_SESSION_ID), None])
    session_routes = SimpleNamespace(
        logout=AsyncOutcome(bool(1), VerificationUnavailable()),
        revoke_session=AsyncOutcome(bool(1), VerificationUnavailable()),
        list_sessions=AsyncOutcome((), (summary,), OSError()),
        current_authentication=lambda _request: next(current_calls),
    )
    service = SimpleNamespace(session_auth=session_routes, client_key_for=lambda _request: "1.2.3.4")
    app, csrf_key = _local_http_app(service, mode=accounts.LocalAuthMode.SESSION)

    with TestClient(app) as client:
        assert client.post("/auth/logout", headers={"x-auth-session": "valid"}).status_code == 403
        assert client.delete("/auth/sessions/session", headers={"x-auth-session": "valid"}).status_code == 403
        csrf_headers = _seed_csrf(client, csrf_key)
        auth_headers = {"x-auth-session": "valid", **csrf_headers}
        assert client.post("/auth/logout", headers=csrf_headers).status_code == 401
        assert client.get("/auth/sessions").status_code == 401
        anon_revoke = client.delete("/auth/sessions/session", headers=csrf_headers)
        logout_ok = client.post("/auth/logout", headers=auth_headers)
        logout_503 = client.post("/auth/logout", headers=auth_headers)
        list_empty = client.get("/auth/sessions", headers={"x-auth-session": "valid"})
        list_item = client.get("/auth/sessions", headers={"x-auth-session": "valid"})
        list_503 = client.get("/auth/sessions", headers={"x-auth-session": "valid"})
        revoke_ok = client.delete("/auth/sessions/session", headers=auth_headers)
        revoke_503 = client.delete("/auth/sessions/session", headers=auth_headers)
        service.session_auth = None
        logout_null = client.post("/auth/logout", headers=auth_headers)
        list_null = client.get("/auth/sessions", headers={"x-auth-session": "valid"})
        revoke_null = client.delete("/auth/sessions/session", headers=auth_headers)

    assert (anon_revoke.status_code, anon_revoke.json()["detail"]) == (401, "Authentication required")
    assert (logout_ok.status_code, logout_503.status_code, logout_null.status_code) == (200, 503, 503)
    assert list_empty.json() == {"sessions": []}
    assert list_item.json()["sessions"][0]["session_id"] == _SESSION_ID
    assert (list_503.status_code, list_null.status_code, revoke_ok.status_code, revoke_503.status_code) == (
        503,
        401,
        200,
        503,
    )
    assert (revoke_null.status_code, revoke_null.json()["detail"]) == (401, "Authentication required.")


def test_token_login_refresh_and_revoke_routes_over_http() -> None:
    """Verify token issuance, Idempotency-Key rotation, and local-bearer revocation over HTTP."""
    refresh_value = accounts.RefreshTokenCodec(pepper=b"p" * 32).issue().refresh_token
    token_pair = accounts.TokenPair(
        access_token="e30.e30.YQ",  # noqa: S106
        refresh_token=refresh_value,
        expires_in=600,
    )
    observed_keys: list[str | None] = []

    async def rotate(presented: str, *, idempotency_key: str | None = None, client_key: str | None = None) -> object:
        assert presented == refresh_value
        assert client_key == "1.2.3.4"
        observed_keys.append(idempotency_key)
        return token_pair if idempotency_key is not None else InvalidCredentials()

    refresh_service = SimpleNamespace(
        rotate=rotate, revoke_for_account=AsyncOutcome(bool(1), VerificationUnavailable())
    )
    service = SimpleNamespace(
        token_login=AsyncOutcome(token_pair, InvalidCredentials()),
        session_auth=None,
        refresh_tokens=refresh_service,
        client_key_for=lambda _request: "1.2.3.4",
    )
    app, _ = _local_http_app(service, mode=accounts.LocalAuthMode.TOKENS)
    bearer = {"authorization": "Bearer valid"}

    with TestClient(app) as client:
        login_ok = client.post("/auth/token", json={"identifier": "user@example.com", "password": "secret"})
        login_401 = client.post("/auth/token", json={"identifier": "user@example.com", "password": "bad"})
        rotated = client.post(
            "/auth/token/refresh", headers={"Idempotency-Key": "AAAAAAAAAAAAAAAAAAAAAA"}, json={"token": refresh_value}
        )
        refresh_400 = client.post("/auth/token/refresh", json={"token": refresh_value})
        revoke_ok = client.post("/auth/token/revoke", headers=bearer, json={"token": refresh_value})
        revoke_503 = client.post("/auth/token/revoke", headers=bearer, json={"token": refresh_value})
        revoke_anon = client.post("/auth/token/revoke", json={"token": refresh_value})
        service.refresh_tokens = None
        refresh_503 = client.post("/auth/token/refresh", json={"token": refresh_value})
        revoke_null = client.post("/auth/token/revoke", headers=bearer, json={"token": refresh_value})

    assert (login_ok.status_code, login_401.status_code) == (200, 401)
    assert login_401.json() == {"status_code": 401, "detail": "Authentication required."}
    assert rotated.status_code == 200
    assert observed_keys == ["AAAAAAAAAAAAAAAAAAAAAA", None]
    assert (refresh_400.status_code, refresh_400.json()["detail"]) == (400, "The request is invalid.")
    assert (refresh_503.status_code, refresh_503.json()["detail"]) == (503, "Authentication service is unavailable.")
    assert (revoke_ok.status_code, revoke_503.status_code, revoke_anon.status_code, revoke_null.status_code) == (
        200,
        503,
        401,
        401,
    )


@pytest.mark.parametrize(
    ("mode", "path", "payload"),
    [
        (accounts.LocalAuthMode.TOKENS, "/auth/token/revoke", {"token": "opaque-refresh"}),
        (
            accounts.LocalAuthMode.TOKENS,
            "/auth/password/change",
            {"current_password": "old", "password": "new-password"},
        ),
        (
            accounts.LocalAuthMode.HYBRID,
            "/auth/token/password/change",
            {"current_password": "old", "password": "new-password"},
        ),
    ],
    ids=["token-revoke", "token-only-password-change", "hybrid-token-password-change"],
)
def test_local_bearer_guard_rejects_non_local_bearer_slots_over_http(
    mode: accounts.LocalAuthMode, path: str, payload: dict[str, str]
) -> None:
    """Verify require_local_bearer rejects authenticated bearer evidence from non-local slots."""
    service = SimpleNamespace(
        refresh_tokens=SimpleNamespace(revoke_for_account=AsyncOutcome(bool(1))),
        change_token_password=AsyncOutcome(accounts.PasswordChangeOutcome(accounts.PasswordChangeStatus.CHANGED, 2)),
        session_auth=None,
        client_key_for=lambda _request: "1.2.3.4",
    )
    external_app, _ = _local_http_app(service, mode=mode, bearer_slot="external")
    local_app, _ = _local_http_app(service, mode=mode, bearer_slot="local")

    with TestClient(external_app) as client:
        denied = client.post(path, headers={"authorization": "Bearer valid"}, json=payload)
    with TestClient(local_app) as client:
        allowed = client.post(path, headers={"authorization": "Bearer valid"}, json=payload)

    assert denied.status_code == 401
    assert denied.json() == {"status_code": 401, "detail": "Authentication required"}
    assert allowed.status_code == 200


def test_lifecycle_reset_and_verification_routes_project_outcomes_over_http() -> None:
    """Verify password reset and account verification endpoints return 200/202 and sanitize failures."""
    purpose_token = accounts.RefreshTokenCodec(pepper=b"p" * 32).issue().refresh_token
    service = SimpleNamespace(
        recovery=SimpleNamespace(
            request=AsyncOutcome(accounts.LifecycleAccepted()),
            reset=AsyncOutcome(
                accounts.PasswordResetOutcome(accounts.PasswordResetStatus.RESET, "account-1", 2),
                accounts.PasswordResetOutcome(accounts.PasswordResetStatus.INVALID),
            ),
        ),
        verification=SimpleNamespace(
            resend=AsyncOutcome(accounts.LifecycleAccepted(), VerificationUnavailable()),
            consume=AsyncOutcome(
                accounts.VerificationOutcome(accounts.VerificationStatus.CONSUMED, "account-1", 1),
                accounts.VerificationOutcome(accounts.VerificationStatus.INVALID),
            ),
        ),
        client_key_for=lambda _request: "1.2.3.4",
    )
    app, _ = _local_http_app(service, mode=accounts.LocalAuthMode.TOKENS)

    with TestClient(app) as client:
        reset_ok = client.post("/auth/password/reset", json={"token": purpose_token, "password": "new-password"})
        reset_400 = client.post("/auth/password/reset", json={"token": purpose_token, "password": "new-password"})
        resend_202 = client.post("/auth/verification", json={"identifier": "user@example.com"})
        resend_503 = client.post("/auth/verification", json={"identifier": "user@example.com"})
        confirm_ok = client.post("/auth/verification/confirm", json={"token": purpose_token})
        confirm_400 = client.post("/auth/verification/confirm", json={"token": purpose_token})

    assert reset_ok.status_code == 200
    assert reset_ok.json() == {"detail": "Password reset complete."}
    assert (reset_400.status_code, reset_400.json()["detail"]) == (400, "The request is invalid.")
    assert (resend_202.status_code, resend_503.status_code) == (202, 503)
    assert confirm_ok.status_code == 200
    assert confirm_ok.json() == {"detail": "Account verified."}
    assert (confirm_400.status_code, confirm_400.json()["detail"]) == (400, "The request is invalid.")


@pytest.mark.parametrize(
    ("registration_mode", "payload", "rejection"),
    [
        (
            accounts.RegistrationMode.PUBLIC,
            {"identifier": "user@example.com", "password": "password"},
            accounts.LifecycleRejected(),
        ),
        (
            accounts.RegistrationMode.INVITE_ONLY,
            {"identifier": "user@example.com", "password": "password", "invitation_token": "invite-secret"},
            accounts.InvalidInvitation(),
        ),
    ],
    ids=["public", "invite-only"],
)
def test_registration_controllers_project_public_and_invitation_outcomes(
    registration_mode: accounts.RegistrationMode, payload: dict[str, str], rejection: object
) -> None:
    """Verify public and invite-only registration accept valid requests and return 400 on rejection."""
    service = SimpleNamespace(
        registration=SimpleNamespace(register=AsyncOutcome(accounts.LifecycleAccepted(), rejection)),
        client_key_for=lambda _request: "1.2.3.4",
    )
    app, _ = _local_http_app(service, mode=accounts.LocalAuthMode.TOKENS, registration_mode=registration_mode)

    with TestClient(app) as client:
        accepted = client.post("/auth/register", json=payload)
        rejected = client.post("/auth/register", json=payload)
        service.registration = None
        missing_service = client.post("/auth/register", json=payload)

    assert accepted.status_code == 202
    assert (rejected.status_code, rejected.json()["detail"]) == (400, "The request is invalid.")
    assert (missing_service.status_code, missing_service.json()["detail"]) == (400, "The request is invalid.")


def test_session_and_token_password_change_controllers_enforce_auth_and_csrf() -> None:
    """Verify session, hybrid-bearer, and token-only password change endpoints over HTTP."""
    service = SimpleNamespace(
        change_session_password=AsyncOutcome(
            accounts.PasswordChangeOutcome(accounts.PasswordChangeStatus.CHANGED, 2), InvalidCredentials()
        ),
        change_token_password=AsyncOutcome(
            accounts.PasswordChangeOutcome(accounts.PasswordChangeStatus.CHANGED, 2),
            accounts.LifecycleRejected(),
            accounts.LifecycleRejected(),
        ),
        client_key_for=lambda _request: "1.2.3.4",
    )
    hybrid_app, csrf_key = _local_http_app(service, mode=accounts.LocalAuthMode.HYBRID)
    token_only_app, _ = _local_http_app(service, mode=accounts.LocalAuthMode.TOKENS)
    payload = {"current_password": "old", "password": "new-password"}

    with TestClient(hybrid_app) as client:
        session_no_csrf = client.post("/auth/password/change", headers={"x-auth-session": "valid"}, json=payload)
        csrf_headers = _seed_csrf(client, csrf_key)
        session_anon = client.post("/auth/password/change", headers=csrf_headers, json=payload)
        session_headers = {"x-auth-session": "valid", **csrf_headers}
        session_ok = client.post("/auth/password/change", headers=session_headers, json=payload)
        session_400 = client.post("/auth/password/change", headers=session_headers, json=payload)
        token_anon = client.post("/auth/token/password/change", json=payload)
        token_ok = client.post("/auth/token/password/change", headers={"authorization": "Bearer valid"}, json=payload)
        token_400 = client.post("/auth/token/password/change", headers={"authorization": "Bearer valid"}, json=payload)

    with TestClient(token_only_app) as client:
        only_anon = client.post("/auth/password/change", json=payload)
        only_400 = client.post("/auth/password/change", headers={"authorization": "Bearer valid"}, json=payload)

    assert (session_no_csrf.status_code, session_anon.status_code) == (403, 401)
    assert session_ok.status_code == 200
    assert session_ok.json() == {"detail": "Password changed."}
    assert (session_400.status_code, session_400.json()["detail"]) == (400, "The request is invalid.")
    assert (token_anon.status_code, token_ok.status_code, token_400.status_code) == (401, 200, 400)
    assert (only_anon.status_code, only_400.status_code) == (401, 400)


@pytest.mark.parametrize("retry_after", [None, 42], ids=["without-retry-after", "with-retry-after"])
def test_rate_limited_local_route_preserves_optional_retry_hint(retry_after: int | None) -> None:
    """Verify RateLimited outcomes preserve or omit the HTTP Retry-After header."""
    service = SimpleNamespace(
        recovery=SimpleNamespace(request=AsyncOutcome(accounts.RateLimited(retry_after=retry_after))),
        client_key_for=lambda _request: "1.2.3.4",
    )
    app, _ = _local_http_app(service, mode=accounts.LocalAuthMode.TOKENS)

    with TestClient(app) as client:
        response = client.post("/auth/password/recovery", json={"identifier": "user@example.com"})

    assert response.status_code == 429
    assert response.json() == {"status_code": 429, "detail": "Too many requests."}
    assert response.headers.get("retry-after") == (None if retry_after is None else str(retry_after))


class _HeaderSlot:
    def __init__(self, name: str, header: str, expected: str = "valid") -> None:
        self.name = name
        self.header = header
        self.expected = expected

    def extract(self, connection: ASGIConnection[Any, Any, Any, Any]) -> CredentialExtraction[str]:
        value = connection.headers.get(self.header)
        if value is None:
            return NoCredentials()
        if value != self.expected:
            return InvalidCredentials()
        return PresentedCredential("account-1")


class _HeaderAuthenticator:
    participates_by_default = True

    def __init__(self, name: str, slot: str) -> None:
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


def _seed_csrf(client: TestClient[Litestar], csrf_key: str) -> dict[str, str]:
    value = generate_csrf_token(csrf_key)
    client.cookies.set("csrftoken", value)
    return {"x-csrftoken": value}


def _local_http_app(
    service: object,
    *,
    mode: accounts.LocalAuthMode = accounts.LocalAuthMode.HYBRID,
    registration_mode: accounts.RegistrationMode = accounts.RegistrationMode.DISABLED,
    bearer_slot: str = "local",
) -> tuple[Litestar, str]:
    csrf_key = token_hex()
    session_enabled = mode in {accounts.LocalAuthMode.SESSION, accounts.LocalAuthMode.HYBRID}
    tokens_enabled = mode in {accounts.LocalAuthMode.TOKENS, accounts.LocalAuthMode.HYBRID}
    slots: list[_HeaderSlot] = []
    mechanisms: list[AuthenticationMechanism[Any, Any, Any]] = []
    if session_enabled:
        slots.append(_HeaderSlot("session", "x-auth-session"))
        mechanisms.append(
            AuthenticationMechanism(
                authenticator=_HeaderAuthenticator("session", "session"),
                resolver=_AccountResolver(),
                scheme_name="SessionCookie",
                security_scheme=SecurityScheme(type="apiKey", name="x-auth-session", security_scheme_in="header"),
                session_capable=True,
            )
        )
    if tokens_enabled:
        slots.append(_HeaderSlot(bearer_slot, "authorization", "Bearer valid"))
        mechanisms.append(
            AuthenticationMechanism(
                authenticator=_HeaderAuthenticator("bearer", bearer_slot),
                resolver=_AccountResolver(),
                scheme_name="BearerAuth",
                security_scheme=SecurityScheme(type="http", scheme="bearer"),
                session_capable=False,
            )
        )
    config = SimpleNamespace(
        mode=mode,
        registration=SimpleNamespace(mode=registration_mode),
        local_auth_service=service,
        mfa_login=None,
        route_prefix="/auth",
        docs=RouteDocs(),
    )
    app = Litestar(
        route_handlers=[accounts.build_local_auth_routes(cast("Any", config))],
        csrf_config=CSRFConfig(secret=csrf_key) if session_enabled else None,
        openapi_config=None,
        plugins=[SecurityPlugin(SecurityConfig(slots=tuple(slots), mechanisms=tuple(mechanisms)))],
    )
    return app, csrf_key
