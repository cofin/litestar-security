"""Unit tests for generated local-auth, MFA, passkey, and step-up route builders and helpers."""

from collections.abc import Mapping
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, cast

import pytest
from litestar.exceptions import (
    ClientException,
    HTTPException,
    NotAuthorizedException,
    ServiceUnavailableException,
    TooManyRequestsException,
)

import litestar_security.accounts as accounts_module
import litestar_security.accounts.controllers._local as local_controllers
import litestar_security.accounts.controllers._mfa as mfa_controllers
from litestar_security import (
    AuthenticationEvidence,
    InvalidCredentials,
    NullSessionHandle,
    Principal,
    RouteDocs,
    SecurityContext,
    VerificationUnavailable,
)
from litestar_security._internal import GENERATED_ROUTE_OPT_KEY

_NOW = datetime(2026, 3, 21, 12, 0, tzinfo=timezone.utc)
_LIFECYCLE_ROUTE_NAMES = frozenset({
    "local.password.recovery",
    "local.password.reset",
    "local.verification.resend",
    "local.verification.confirm",
})
_SESSION_ROUTE_NAMES = frozenset({
    "local.session.login",
    "local.session.logout",
    "local.session.list",
    "local.session.revoke",
    "local.session.password.change",
})
_TOKEN_ROUTE_NAMES = frozenset({
    "local.token.login",
    "local.token.refresh",
    "local.token.revoke",
    "local.token.password.change",
})
_MFA_ROUTE_NAMES = frozenset({"mfa.totp.enroll", "mfa.totp.verify", "mfa.totp.remove", "mfa.recovery_codes.replace"})
_PASSKEY_CORE_ROUTE_NAMES = frozenset({
    "passkey.registration.options",
    "passkey.registration.verify",
    "passkey.authentication.options",
    "passkey.list",
    "passkey.remove",
})


@pytest.mark.parametrize(
    ("mode", "registration", "has_mfa_login", "expected_names", "absent_names"),
    [
        (
            accounts_module.LocalAuthMode.SESSION,
            accounts_module.RegistrationMode.PUBLIC,
            False,
            set(_LIFECYCLE_ROUTE_NAMES | _SESSION_ROUTE_NAMES | {"local.registration"}),
            set(_TOKEN_ROUTE_NAMES | {"local.session.login.mfa", "local.token.login.mfa"}),
        ),
        (
            accounts_module.LocalAuthMode.TOKENS,
            accounts_module.RegistrationMode.INVITE_ONLY,
            True,
            set(_LIFECYCLE_ROUTE_NAMES | _TOKEN_ROUTE_NAMES | {"local.token.login.mfa", "local.registration"}),
            set(_SESSION_ROUTE_NAMES | {"local.session.login.mfa"}),
        ),
        (
            accounts_module.LocalAuthMode.HYBRID,
            accounts_module.RegistrationMode.DISABLED,
            True,
            set(
                _LIFECYCLE_ROUTE_NAMES
                | _SESSION_ROUTE_NAMES
                | _TOKEN_ROUTE_NAMES
                | {"local.session.login.mfa", "local.token.login.mfa"}
            ),
            {"local.registration"},
        ),
        (
            accounts_module.LocalAuthMode.HYBRID,
            accounts_module.RegistrationMode.DISABLED,
            False,
            set(_LIFECYCLE_ROUTE_NAMES | _SESSION_ROUTE_NAMES | _TOKEN_ROUTE_NAMES),
            {"local.registration", "local.session.login.mfa", "local.token.login.mfa"},
        ),
    ],
)
def test_build_local_auth_routes_selects_handlers_and_headers(
    mode: accounts_module.LocalAuthMode,
    registration: accounts_module.RegistrationMode,
    expected_names: set[str],
    absent_names: set[str],
    *,
    has_mfa_login: bool,
) -> None:
    service = SimpleNamespace()
    config = SimpleNamespace(
        local_auth_service=service,
        mfa_login=object() if has_mfa_login else None,
        mode=mode,
        registration=SimpleNamespace(mode=registration),
        route_prefix="/auth",
        docs=RouteDocs(),
    )

    router = local_controllers.build_local_auth_routes(cast("Any", config))

    _assert_generated_router_invariants(router, path="/auth")
    provider = router.dependencies["local_auth_service"]
    assert provider.sync_to_thread is False
    assert provider.use_cache is False
    assert cast("Any", provider.dependency)() is service

    handlers = _router_handlers_by_name(router)
    assert set(handlers) == expected_names
    assert set(handlers).isdisjoint(absent_names)
    if mode is accounts_module.LocalAuthMode.TOKENS:
        assert handlers["local.token.password.change"][0] == "/auth/password/change"
    elif mode is accounts_module.LocalAuthMode.HYBRID:
        assert handlers["local.session.password.change"][0] == "/auth/password/change"
        assert handlers["local.token.password.change"][0] == "/auth/token/password/change"
    if registration is accounts_module.RegistrationMode.PUBLIC:
        assert handlers["local.registration"][1].summary == "Register"
    elif registration is accounts_module.RegistrationMode.INVITE_ONLY:
        assert handlers["local.registration"][1].summary == "Register with an invitation"


def test_build_mfa_routes_requires_at_least_one_factor_service() -> None:
    with pytest.raises(ValueError, match="At least one MFA or passkey service must be enabled"):
        mfa_controllers.build_mfa_routes(step_up=cast("Any", object()), epochs=cast("Any", object()))


@pytest.mark.parametrize(
    ("has_mfa", "has_passkeys", "session_capable", "token_capable", "expected_names"),
    [
        (True, False, False, False, {"security.step_up", *_MFA_ROUTE_NAMES}),
        (
            False,
            True,
            True,
            False,
            {"security.step_up", *_PASSKEY_CORE_ROUTE_NAMES, "passkey.authentication.session.verify"},
        ),
        (
            False,
            True,
            False,
            True,
            {"security.step_up", *_PASSKEY_CORE_ROUTE_NAMES, "passkey.authentication.tokens.verify"},
        ),
        (
            True,
            True,
            True,
            True,
            {
                "security.step_up",
                *_MFA_ROUTE_NAMES,
                *_PASSKEY_CORE_ROUTE_NAMES,
                "passkey.authentication.hybrid.session.verify",
                "passkey.authentication.hybrid.tokens.verify",
            },
        ),
    ],
)
def test_build_mfa_routes_selects_factor_and_transport_handlers(
    expected_names: set[str], *, has_mfa: bool, has_passkeys: bool, session_capable: bool, token_capable: bool
) -> None:
    step_up = object()
    epochs = object()
    mfa_stub = object() if has_mfa else None
    passkeys_stub = object() if has_passkeys else None

    router = mfa_controllers.build_mfa_routes(
        step_up=cast("Any", step_up),
        epochs=cast("Any", epochs),
        mfa=cast("Any", mfa_stub),
        passkeys=cast("Any", passkeys_stub),
        session_capable=session_capable,
        token_capable=token_capable,
        route_prefix="/factors",
    )

    _assert_generated_router_invariants(router, path="/factors")
    provider = router.dependencies["mfa_service"]
    assert provider.sync_to_thread is False
    assert provider.use_cache is False
    feature = cast("Any", provider.dependency)()
    assert feature.step_up is step_up
    assert feature.epochs is epochs
    assert feature.mfa is mfa_stub
    assert feature.passkeys is passkeys_stub
    assert set(_router_handlers_by_name(router)) == expected_names


@pytest.mark.parametrize(
    ("outcome", "credentials", "exception_type", "status_code", "detail", "retry_after"),
    [
        (accounts_module.RateLimited(retry_after=9), False, TooManyRequestsException, 429, "Too many requests.", "9"),
        (accounts_module.RateLimited(), False, TooManyRequestsException, 429, "Too many requests.", None),
        (
            VerificationUnavailable(),
            False,
            ServiceUnavailableException,
            503,
            "Authentication service is unavailable.",
            None,
        ),
        (InvalidCredentials(), True, NotAuthorizedException, 401, "Authentication required.", None),
        (InvalidCredentials(), False, ClientException, 400, "The request is invalid.", None),
        (accounts_module.LifecycleRejected(), False, ClientException, 400, "The request is invalid.", None),
    ],
)
def test_route_error_projects_status_detail_and_retry_hint(  # noqa: PLR0913
    outcome: object,
    exception_type: type[HTTPException],
    status_code: int,
    detail: str,
    retry_after: str | None,
    *,
    credentials: bool,
) -> None:
    with pytest.raises(exception_type) as exc_info:
        local_controllers.route_error(outcome, credentials=credentials)
    assert exc_info.value.status_code == status_code
    assert exc_info.value.detail == detail
    headers = exc_info.value.headers or {}
    assert headers.get("Retry-After") == retry_after


@pytest.mark.parametrize(
    ("principal", "expected"), [(Principal(id="account-1"), "account-1"), (Principal.anonymous(), None)]
)
def test_principal_id_projects_only_authenticated_principals(
    principal: Principal[object], expected: str | None
) -> None:
    assert local_controllers.principal_id(principal) == expected


def test_require_local_bearer_accepts_only_local_slot_evidence() -> None:
    connection = SimpleNamespace(
        auth=SecurityContext(
            session=NullSessionHandle(),
            evidence=(AuthenticationEvidence(mechanism="jwt", slot="local", authenticated_at=_NOW),),
        )
    )
    local_controllers.require_local_bearer(cast("Any", connection), cast("Any", object()))


@pytest.mark.parametrize(
    "auth_context",
    [
        None,
        object(),
        SecurityContext(session=NullSessionHandle()),
        SecurityContext(
            session=NullSessionHandle(),
            evidence=(AuthenticationEvidence(mechanism="jwt", slot="external", authenticated_at=_NOW),),
        ),
    ],
)
def test_require_local_bearer_rejects_missing_or_foreign_evidence(auth_context: object) -> None:
    connection = SimpleNamespace(auth=auth_context)
    with pytest.raises(NotAuthorizedException) as exc_info:
        local_controllers.require_local_bearer(cast("Any", connection), cast("Any", object()))
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Authentication required"


@pytest.mark.parametrize(("binding", "expected_binding"), [(None, None), ("bind-1", "bind-1")])
def test_passkey_options_response_projects_options_and_unavailable_failure(
    binding: str | None, expected_binding: str | None
) -> None:
    options = accounts_module.WebAuthnOptions(
        challenge="challenge-1", json='{"challenge":"challenge-1"}', expires_at=_NOW
    )
    response = mfa_controllers._PasskeyController._options_response(  # noqa: SLF001
        options, binding=binding
    )
    assert response.status_code == 200
    assert response.content == accounts_module.PasskeyOptions(
        options='{"challenge":"challenge-1"}', expires_at=_NOW, binding=expected_binding
    )

    with pytest.raises(ServiceUnavailableException) as exc_info:
        mfa_controllers._PasskeyController._options_response(  # noqa: SLF001
            VerificationUnavailable(), binding=binding
        )
    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Authentication service is unavailable."


@pytest.mark.parametrize(
    ("status", "expected_status", "expected_detail"),
    [
        (accounts_module.RevokeLoginMethodStatus.REVOKED, 200, "Login method removed."),
        (accounts_module.RevokeLoginMethodStatus.FINAL_METHOD, 409, "At least one viable login method is required."),
        (accounts_module.RevokeLoginMethodStatus.NOT_FOUND, 400, "The request is invalid."),
    ],
)
def test_passkey_removal_response_projects_status_codes(
    status: accounts_module.RevokeLoginMethodStatus, expected_status: int, expected_detail: str
) -> None:
    response = mfa_controllers.removal_response(accounts_module.RevokeLoginMethodOutcome(status=status))
    assert response.status_code == expected_status
    assert response.content == accounts_module.OperationMessage(detail=expected_detail)


def test_passkey_removal_response_raises_when_service_unavailable() -> None:
    with pytest.raises(ServiceUnavailableException) as exc_info:
        mfa_controllers.removal_response(VerificationUnavailable())
    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Authentication service is unavailable."


def _router_handlers_by_name(router: Any) -> dict[str, tuple[str, Any]]:
    return {
        handler.name: (route.path, handler)
        for route in router.routes
        for handler in cast("tuple[Any, ...]", getattr(route, "route_handlers", ()))
        if getattr(handler, "http_methods", None) != {"OPTIONS"}
    }


def _router_headers(router: Any) -> dict[str, Any]:
    headers = router.response_headers or ()
    if isinstance(headers, Mapping):
        return {key: getattr(value, "value", value) for key, value in headers.items()}
    return {header.name: header.value for header in headers}


def _assert_generated_router_invariants(router: Any, *, path: str) -> None:
    assert router.path == path
    assert router.cache_control is not None
    assert router.cache_control.no_store is True
    assert _router_headers(router) == {"Pragma": "no-cache"}
    assert router.opt[GENERATED_ROUTE_OPT_KEY] is True
