"""Integration coverage for the generated local-auth controller graph."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, cast

import pytest
from litestar.exceptions import (
    ClientException,
    NotAuthorizedException,
    ServiceUnavailableException,
    TooManyRequestsException,
)

import litestar_security.accounts.controllers._local as local_controllers
from litestar_security import accounts
from litestar_security._docs import RouteDocs
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.context import AuthenticationEvidence, NullSessionHandle, Principal, SecurityContext
from tests.fixtures.accounts import AsyncOutcome


def test_local_route_schemas_redact_every_secret_they_carry() -> None:
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
    for schema in schemas:
        rendered = repr(schema)
        assert secret not in rendered, type(schema).__name__
        assert type(schema).__name__ in rendered
    assert identifier in repr(schemas[0])
    assert "compromise=True" in repr(schemas[-1])


async def _raised(awaitable: Any, exception_type: type[Exception]) -> Exception:
    with pytest.raises(exception_type) as exc_info:
        await awaitable
    return exc_info.value


async def _assert_http_exception(
    awaitable: Any, exception_type: type[Exception], *, status_code: int, detail: str
) -> Exception:
    error = await _raised(awaitable, exception_type)
    assert error.status_code == status_code
    assert error.detail == detail
    return error


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
    config = SimpleNamespace(
        mode=mode,
        registration=SimpleNamespace(mode=registration),
        local_auth_service=object(),
        mfa_login=None,
        route_prefix="/auth",
        docs=RouteDocs(),
    )

    router = local_controllers.build_local_auth_routes(cast("Any", config))
    names = {handler.name for route in router.routes for handler in route.route_handlers if handler.name is not None}

    assert expected_names <= names
    assert router.path == "/auth"
    assert router.cache_control.no_store is True
    assert {(header.name, header.value) for header in router.response_headers} == {("Pragma", "no-cache")}


async def test_generated_login_and_lifecycle_handlers_project_typed_outcomes() -> None:
    credentials = accounts.LocalCredentials(
        identifier="user@example.com",
        password="secret",  # noqa: S106 - request DTO fixture
    )
    identifier = accounts.LocalIdentifier(identifier="user@example.com")
    service = SimpleNamespace(
        session_login=AsyncOutcome(accounts.LocalAccount("account-1"), InvalidCredentials()),
        recovery=SimpleNamespace(request=AsyncOutcome(accounts.LifecycleAccepted(), accounts.RateLimited(7))),
        verification=SimpleNamespace(resend=AsyncOutcome(accounts.LifecycleAccepted())),
        client_key_for=lambda _request: "1.2.3.4",
    )
    request = cast("Any", SimpleNamespace())
    login = cast("Any", local_controllers._LocalSessionController.login.fn)  # noqa: SLF001
    recovery = cast("Any", local_controllers._LocalLifecycleController.recovery.fn)  # noqa: SLF001

    response = await login(None, credentials, request, service)
    assert response.status_code == 200
    assert response.content.account_id == "account-1"
    error = await _raised(login(None, credentials, request, service), ClientException)
    assert cast("ClientException", error).detail == "The request is invalid."
    assert (await recovery(None, identifier, request, service)).status_code == 202
    error = await _raised(recovery(None, identifier, request, service), TooManyRequestsException)
    assert cast("TooManyRequestsException", error).headers["Retry-After"] == "7"


async def test_generated_session_and_token_handlers_cover_success_and_safe_failures() -> None:
    token = accounts.RefreshTokenCodec(pepper=b"p" * 32).issue().refresh_token
    token_pair = accounts.TokenPair(access_token="e30.e30.YQ", refresh_token=token, expires_in=600)  # noqa: S106
    principal, anonymous = Principal(id="account-1"), Principal.anonymous()
    credentials = accounts.LocalCredentials(
        identifier="user@example.com",
        password="secret",  # noqa: S106 - request DTO fixture
    )
    token_request = accounts.LocalToken(token=token)
    session_routes = SimpleNamespace(
        logout=AsyncOutcome(bool(1), VerificationUnavailable()),
        revoke_session=AsyncOutcome(bool(1), VerificationUnavailable()),
        list_sessions=AsyncOutcome((), OSError()),
        current_authentication=lambda _request: None,
    )
    services = SimpleNamespace(
        session_login=AsyncOutcome(accounts.LocalAccount("account-1")),
        token_login=AsyncOutcome(token_pair, InvalidCredentials()),
        session_auth=session_routes,
        refresh_tokens=SimpleNamespace(
            rotate=AsyncOutcome(token_pair, InvalidCredentials()),
            revoke_for_account=AsyncOutcome(bool(1), VerificationUnavailable()),
        ),
        client_key_for=lambda _request: "1.2.3.4",
    )
    request = cast("Any", SimpleNamespace())

    logout = cast("Any", local_controllers._LocalSessionController.logout.fn)  # noqa: SLF001
    assert (await logout(None, request, services)).status_code == 200
    await _assert_http_exception(
        logout(None, request, services),
        ServiceUnavailableException,
        status_code=503,
        detail="Authentication service is unavailable.",
    )
    services.session_auth = None
    await _assert_http_exception(
        logout(None, request, services),
        ServiceUnavailableException,
        status_code=503,
        detail="Authentication service is unavailable.",
    )
    services.session_auth = session_routes

    list_sessions = cast("Any", local_controllers._LocalSessionController.list_sessions.fn)  # noqa: SLF001
    assert (await list_sessions(None, request, principal, services)).status_code == 200
    await _assert_http_exception(
        list_sessions(None, request, principal, services),
        ServiceUnavailableException,
        status_code=503,
        detail="Authentication service is unavailable.",
    )
    await _assert_http_exception(
        list_sessions(None, request, anonymous, services),
        NotAuthorizedException,
        status_code=401,
        detail="Authentication required.",
    )
    revoke_session = cast("Any", local_controllers._LocalSessionController.revoke_session.fn)  # noqa: SLF001
    assert (await revoke_session(None, "session", request, principal, services)).status_code == 200
    await _assert_http_exception(
        revoke_session(None, "session", request, principal, services),
        ServiceUnavailableException,
        status_code=503,
        detail="Authentication service is unavailable.",
    )
    services.session_auth = None
    await _assert_http_exception(
        revoke_session(None, "session", request, principal, services),
        NotAuthorizedException,
        status_code=401,
        detail="Authentication required.",
    )
    services.session_auth = session_routes

    login = cast("Any", local_controllers._LocalTokenController.login.fn)  # noqa: SLF001
    assert (await login(None, credentials, request, services)).status_code == 200
    await _assert_http_exception(
        login(None, credentials, request, services), ClientException, status_code=400, detail="The request is invalid."
    )
    refresh = cast("Any", local_controllers._LocalTokenController.refresh.fn)  # noqa: SLF001
    assert (await refresh(None, token_request, request, services, "AAAAAAAAAAAAAAAAAAAAAA")).status_code == 200
    await _assert_http_exception(
        refresh(None, token_request, request, services, None),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )
    refresh_tokens = services.refresh_tokens
    services.refresh_tokens = None
    await _assert_http_exception(
        refresh(None, token_request, request, services, None),
        ServiceUnavailableException,
        status_code=503,
        detail="Authentication service is unavailable.",
    )
    services.refresh_tokens = refresh_tokens
    revoke = cast("Any", local_controllers._LocalTokenController.revoke.fn)  # noqa: SLF001
    assert (await revoke(None, token_request, principal, services)).status_code == 200
    await _assert_http_exception(
        revoke(None, token_request, principal, services),
        ServiceUnavailableException,
        status_code=503,
        detail="Authentication service is unavailable.",
    )
    await _assert_http_exception(
        revoke(None, token_request, anonymous, services),
        NotAuthorizedException,
        status_code=401,
        detail="Authentication required.",
    )


async def test_generated_registration_reset_and_password_handlers_cover_projection_matrix() -> None:
    token = accounts.RefreshTokenCodec(pepper=b"p" * 32).issue().refresh_token
    request = cast("Any", SimpleNamespace())
    principal, anonymous = Principal(id="account-1"), Principal.anonymous()
    token_request = accounts.LocalToken(token=token)
    password_request = accounts.LocalPasswordChange(
        current_password="old",  # noqa: S106 - request DTO fixture
        password="new-password",  # noqa: S106 - request DTO fixture
    )
    services = SimpleNamespace(
        recovery=SimpleNamespace(
            request=AsyncOutcome(accounts.LifecycleAccepted()),
            reset=AsyncOutcome(
                accounts.PasswordResetOutcome(accounts.PasswordResetStatus.RESET, "account-1", 2),
                accounts.PasswordResetOutcome(accounts.PasswordResetStatus.INVALID),
            ),
        ),
        verification=SimpleNamespace(
            resend=AsyncOutcome(accounts.LifecycleAccepted()),
            consume=AsyncOutcome(
                accounts.VerificationOutcome(accounts.VerificationStatus.CONSUMED, "account-1", 1),
                accounts.VerificationOutcome(accounts.VerificationStatus.INVALID),
            ),
        ),
        registration=SimpleNamespace(register=AsyncOutcome(accounts.LifecycleAccepted(), accounts.InvalidInvitation())),
        change_session_password=AsyncOutcome(
            accounts.PasswordChangeOutcome(accounts.PasswordChangeStatus.CHANGED, 2), InvalidCredentials()
        ),
        change_token_password=AsyncOutcome(
            accounts.PasswordChangeOutcome(accounts.PasswordChangeStatus.CHANGED, 2), accounts.LifecycleRejected()
        ),
        client_key_for=lambda _request: "1.2.3.4",
    )
    lifecycle = local_controllers._LocalLifecycleController  # noqa: SLF001
    identifier = accounts.LocalIdentifier(identifier="user@example.com")
    assert (await cast("Any", lifecycle.recovery.fn)(None, identifier, request, services)).status_code == 202
    reset = cast("Any", lifecycle.reset.fn)
    reset_request = accounts.LocalPasswordReset(token=token, password="new-password")  # noqa: S106
    assert (await reset(None, reset_request, request, services)).status_code == 200
    await _assert_http_exception(
        reset(None, reset_request, request, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )
    assert (await cast("Any", lifecycle.verification.fn)(None, identifier, request, services)).status_code == 202
    confirm = cast("Any", lifecycle.confirm_verification.fn)
    assert (await confirm(None, token_request, request, services)).status_code == 200
    await _assert_http_exception(
        confirm(None, token_request, request, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )

    register = cast("Any", local_controllers._LocalRegistrationController.register.fn)  # noqa: SLF001
    registration = accounts.LocalRegistration(identifier="user@example.com", password="password")  # noqa: S106
    assert (await register(None, registration, request, services)).status_code == 202
    await _assert_http_exception(
        register(None, registration, request, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )
    services.registration = None
    await _assert_http_exception(
        register(None, registration, request, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )
    services.registration = SimpleNamespace(
        register=AsyncOutcome(accounts.LifecycleAccepted(), accounts.InvalidInvitation())
    )
    invitation = accounts.LocalInvitationRegistration(
        identifier="user@example.com",
        password="password",  # noqa: S106 - request DTO fixture
        invitation_token="invite-secret",  # noqa: S106
    )
    invite = cast("Any", local_controllers._LocalInvitationRegistrationController.register.fn)  # noqa: SLF001
    assert (await invite(None, invitation, request, services)).status_code == 202
    await _assert_http_exception(
        invite(None, invitation, request, services), ClientException, status_code=400, detail="The request is invalid."
    )
    services.registration = None
    await _assert_http_exception(
        invite(None, invitation, request, services), ClientException, status_code=400, detail="The request is invalid."
    )

    session_change = cast("Any", local_controllers._LocalSessionPasswordController.change.fn)  # noqa: SLF001
    assert (await session_change(None, password_request, request, principal, services)).status_code == 200
    await _assert_http_exception(
        session_change(None, password_request, request, principal, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )
    await _assert_http_exception(
        session_change(None, password_request, request, anonymous, services),
        NotAuthorizedException,
        status_code=401,
        detail="Authentication required.",
    )
    token_change = cast("Any", local_controllers._LocalTokenPasswordController.change.fn)  # noqa: SLF001
    assert (await token_change(None, password_request, principal, services)).status_code == 200
    await _assert_http_exception(
        token_change(None, password_request, anonymous, services),
        NotAuthorizedException,
        status_code=401,
        detail="Authentication required.",
    )
    token_only = cast("Any", local_controllers._LocalTokenOnlyPasswordController.change.fn)  # noqa: SLF001
    await _assert_http_exception(
        token_only(None, password_request, principal, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )
    await _assert_http_exception(
        token_only(None, password_request, anonymous, services),
        NotAuthorizedException,
        status_code=401,
        detail="Authentication required.",
    )


def test_local_bearer_guard_uses_authentication_evidence() -> None:
    now = datetime(2026, 7, 26, tzinfo=timezone.utc)
    authenticated = SecurityContext(
        session=NullSessionHandle(), evidence=(AuthenticationEvidence("bearer", "local", now),)
    )
    local_controllers.require_local_bearer(cast("Any", SimpleNamespace(auth=authenticated)), cast("Any", None))
    with pytest.raises(NotAuthorizedException, match="Authentication required"):
        local_controllers.require_local_bearer(
            cast("Any", SimpleNamespace(auth=SecurityContext(session=NullSessionHandle()))), cast("Any", None)
        )


@pytest.mark.parametrize("retry_after", [None, 42])
def test_route_error_preserves_optional_retry_hint(retry_after: int | None) -> None:
    with pytest.raises(TooManyRequestsException) as exc_info:
        local_controllers._route_error(accounts.RateLimited(retry_after=retry_after))  # noqa: SLF001

    assert exc_info.value.status_code == 429
    assert exc_info.value.detail == "Too many requests."
    assert (exc_info.value.headers or {}).get("Retry-After") == (None if retry_after is None else str(retry_after))
