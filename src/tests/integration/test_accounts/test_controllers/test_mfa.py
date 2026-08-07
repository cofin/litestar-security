"""Integration coverage for generated MFA, passkey, and step-up controllers."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

import pytest
from litestar.exceptions import NotAuthorizedException, ServiceUnavailableException, TooManyRequestsException

import litestar_security.accounts.controllers._mfa as mfa_controllers
from litestar_security import accounts
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.context import Principal
from tests.fixtures.accounts import AsyncOutcome


def test_route_builder_requires_and_selects_enabled_features() -> None:
    with pytest.raises(ValueError, match="At least one"):
        mfa_controllers.build_mfa_routes(step_up=cast("Any", object()), epochs=cast("Any", object()))

    mfa_router = mfa_controllers.build_mfa_routes(
        step_up=cast("Any", object()), epochs=cast("Any", object()), mfa=cast("Any", object())
    )
    passkey_only_router = mfa_controllers.build_mfa_routes(
        step_up=cast("Any", object()), epochs=cast("Any", object()), passkeys=cast("Any", object())
    )
    passkey_router = mfa_controllers.build_mfa_routes(
        step_up=cast("Any", object()),
        epochs=cast("Any", object()),
        passkeys=cast("Any", object()),
        session_capable=True,
        token_capable=True,
    )

    assert mfa_router.path == passkey_router.path == "/auth"
    assert passkey_only_router.path == "/auth"
    assert {(header.name, header.value) for header in mfa_router.response_headers} == {("Pragma", "no-cache")}
    assert len(passkey_router.routes) > len(mfa_router.routes)


def test_step_up_purposes_are_deny_by_default_and_require_strong_factors() -> None:
    purpose_methods = mfa_controllers._PURPOSE_METHODS  # noqa: SLF001

    assert set(purpose_methods) == {
        "totp-enroll",
        "totp-remove",
        "recovery-codes",
        "passkey-register",
        "passkey-remove",
    }
    assert set(purpose_methods.values()) == {frozenset({"password", "passkey"})}


@pytest.mark.parametrize(
    ("outcome", "exception_type", "status_code", "detail", "retry_after"),
    [
        (accounts.RateLimited(3), TooManyRequestsException, 429, "Too many requests.", "3"),
        (accounts.RateLimited(), TooManyRequestsException, 429, "Too many requests.", None),
        (VerificationUnavailable(), ServiceUnavailableException, 503, "Authentication service is unavailable.", None),
        (InvalidCredentials(), NotAuthorizedException, 401, "Authentication required.", None),
    ],
)
def test_mfa_route_errors_are_sanitized(
    outcome: object, exception_type: type[Exception], status_code: int, detail: str, retry_after: str | None
) -> None:
    with pytest.raises(exception_type) as exc_info:
        mfa_controllers._error(outcome)  # noqa: SLF001

    assert getattr(exc_info.value, "status_code", None) == status_code
    assert getattr(exc_info.value, "detail", None) == detail
    assert (getattr(exc_info.value, "headers", None) or {}).get("Retry-After") == retry_after


async def test_mfa_helpers_handle_transport_epoch_and_limiter_failures() -> None:
    request = cast("Any", SimpleNamespace(headers={"authorization": "Bearer transport"}))
    epochs = SimpleNamespace(current_epoch=AsyncOutcome(1, cast("object", bool(0)), OSError()))
    service = mfa_controllers._MFAFeatureService(  # noqa: SLF001
        mfa=None,
        passkeys=None,
        step_up=cast("Any", object()),
        epochs=cast("Any", epochs),
        rate_limits=None,
        client_key=None,
        local_auth=None,
    )

    assert mfa_controllers._principal_id(Principal.anonymous()) is None  # noqa: SLF001
    assert mfa_controllers._transport_binding(request) == b"Bearer transport"  # noqa: SLF001
    assert await mfa_controllers._current_epoch(service, "account-1") == 1  # noqa: SLF001
    assert isinstance(await mfa_controllers._current_epoch(service, "account-1"), VerificationUnavailable)  # noqa: SLF001
    assert isinstance(await mfa_controllers._current_epoch(service, "account-1"), VerificationUnavailable)  # noqa: SLF001

    limiter = SimpleNamespace(check=AsyncOutcome(accounts.RateLimited(), accounts.RateLimited()))
    limited = replace(service, rate_limits=cast("Any", limiter), client_key=cast("Any", lambda _request: "client"))
    assert isinstance(
        await mfa_controllers._check_rate_limit(limited, request, "operation", "account-1"),  # noqa: SLF001
        accounts.RateLimited,
    )
    limited = replace(limited, client_key=cast("Any", lambda _request: 1 / 0))
    assert isinstance(
        await mfa_controllers._check_rate_limit(limited, request, "operation", "account-1"),  # noqa: SLF001
        accounts.RateLimited,
    )
    assert isinstance(
        await mfa_controllers._StepUpController._verify_factor(  # noqa: SLF001
            "account-1", cast("Any", SimpleNamespace(method="unsupported", credential={})), request, limited
        ),
        InvalidCredentials,
    )


async def test_step_up_consumption_and_response_helpers_fail_closed() -> None:
    request = cast("Any", SimpleNamespace(headers={"cookie": "session=value"}))
    epochs = SimpleNamespace(current_epoch=AsyncOutcome(OSError()))
    service = mfa_controllers._MFAFeatureService(  # noqa: SLF001
        mfa=None,
        passkeys=None,
        step_up=cast("Any", object()),
        epochs=cast("Any", epochs),
        rate_limits=None,
        client_key=None,
        local_auth=None,
    )

    assert mfa_controllers._transport_binding(request) == b"session=value"  # noqa: SLF001
    assert mfa_controllers._transport_binding(cast("Any", SimpleNamespace(headers={}))) == b""  # noqa: SLF001
    assert isinstance(
        await mfa_controllers._consume_step_up(  # noqa: SLF001
            mfa_service=service, request=request, account_id="account-1", purpose="settings", grant="grant"
        ),
        VerificationUnavailable,
    )
    for response_factory in (mfa_controllers._options_response, mfa_controllers._removal_response):  # noqa: SLF001
        with pytest.raises(ServiceUnavailableException) as exc_info:
            response_factory(VerificationUnavailable())
        assert exc_info.value.status_code == 503
        assert exc_info.value.detail == "Authentication service is unavailable."


@pytest.mark.parametrize(
    ("status", "expected"),
    [(accounts.RevokeLoginMethodStatus.FINAL_METHOD, 409), (accounts.RevokeLoginMethodStatus.NOT_FOUND, 400)],
)
def test_removal_outcomes_keep_their_http_classification(
    status: accounts.RevokeLoginMethodStatus, expected: int
) -> None:
    outcome = accounts.RevokeLoginMethodOutcome(status)
    assert mfa_controllers._removal_response(outcome).status_code == expected  # noqa: SLF001
