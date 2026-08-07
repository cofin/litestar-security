from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from litestar_security.providers.oauth import (
    GitHubOAuthProvider,
    OAuthOperation,
    OAuthProviderError,
    OAuthTransaction,
    OAuthTransactionStart,
    ProviderIdentity,
    ProviderTokenSet,
    SecretStr,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from typing import Any

    Handler = Callable[[httpx.Request], httpx.Response] | Callable[[httpx.Request], Coroutine[Any, Any, httpx.Response]]


NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)


def transaction(*, scopes: frozenset[str] = frozenset({"read:user", "user:email"})) -> OAuthTransaction:
    return OAuthTransaction(
        state_digest=b"s" * 32,
        binding_digest=b"b" * 32,
        operation=OAuthOperation.LOGIN,
        provider="github",
        expected_issuer="https://github.com",
        redirect_uri="https://app.example.com/auth/oauth/github/callback",
        return_to="/",
        requested_scopes=scopes,
        pkce_verifier=SecretStr("v" * 43),
        nonce=None,
        expires_at=NOW + timedelta(minutes=10),
    )


def start() -> OAuthTransactionStart:
    return OAuthTransactionStart(
        state=SecretStr("state"),
        browser_binding=SecretStr("binding"),
        pkce_challenge="challenge",
        nonce=None,
        transaction=transaction(),
    )


def tokens(*, scopes: frozenset[str] = frozenset({"read:user", "user:email"})) -> ProviderTokenSet:
    return ProviderTokenSet(
        access_token=SecretStr("access-token"),
        token_type="Bearer",  # noqa: S106 - standardized OAuth token type, not a credential
        scopes=scopes,
        expires_at=NOW + timedelta(hours=1),
    )


def provider(handler: Handler) -> GitHubOAuthProvider:
    return GitHubOAuthProvider(
        client_id="client-id", client_secret=SecretStr("client-secret"), transport=httpx.MockTransport(handler)
    )


def test_github_authorization_uses_code_pkce_and_fixed_endpoints() -> None:
    github = provider(lambda request: httpx.Response(500, request=request))

    url = github.build_authorization_url(start())
    query = parse_qs(urlsplit(url).query)

    assert url.startswith("https://github.com/login/oauth/authorize?")
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == ["challenge"]
    assert query["scope"] == ["read:user user:email"]


async def test_github_refetches_profile_and_verified_email_each_login() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/user":
            return httpx.Response(200, json={"id": 123456, "login": "octocat", "name": "The Octocat"})
        if request.url.path == "/user/emails":
            return httpx.Response(
                200,
                json=[
                    {"email": "unverified@example.com", "verified": False, "primary": False},
                    {"email": "octocat@example.com", "verified": True, "primary": True},
                ],
            )
        raise AssertionError(request.url)

    github = provider(handler)

    first = await github.resolve_identity(tokens(), transaction=transaction(), now=NOW)
    second = await github.resolve_identity(tokens(), transaction=transaction(), now=NOW)

    assert first == second
    assert first.provider == "github"
    assert first.issuer == "https://github.com"
    assert first.subject == "123456"
    assert first.subject != first.email
    assert first.display_name == "The Octocat"
    assert first.email == "octocat@example.com"
    assert first.email_verified is True
    assert calls == ["/user", "/user/emails", "/user", "/user/emails"]


async def test_github_never_uses_unverified_email() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return httpx.Response(200, json={"id": 7, "login": "user", "email": "public@example.com"})
        return httpx.Response(200, json=[{"email": "unverified@example.com", "verified": False, "primary": True}])

    identity = await provider(handler).resolve_identity(tokens(), transaction=transaction(), now=NOW)

    assert identity.subject == "7"
    assert identity.email is None
    assert identity.email_verified is False


async def test_github_rejects_missing_required_scope() -> None:
    github = provider(lambda request: httpx.Response(500, request=request))

    with pytest.raises(OAuthProviderError):
        await github.resolve_identity(tokens(scopes=frozenset({"read:user"})), transaction=transaction(), now=NOW)


@pytest.mark.parametrize("status_code", [401, 403, 429, 500])
async def test_github_collapses_api_and_rate_limit_errors(status_code: int) -> None:
    github = provider(
        lambda request: httpx.Response(
            status_code, headers={"retry-after": "60"}, json={"message": "secret"}, request=request
        )
    )

    with pytest.raises(OAuthProviderError, match="OAuth provider request failed") as captured:
        await github.resolve_identity(tokens(), transaction=transaction(), now=NOW)

    assert captured.value.retry_after == (60 if status_code in {403, 429} else None)
    assert "secret" not in repr(captured.value)


async def test_github_revocation_uses_application_endpoint_and_basic_auth() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204, request=request)

    github = provider(handler)

    await github.revoke(SecretStr("access-token"), token_type_hint="access_token")  # noqa: S106 - OAuth token kind

    request = seen[0]
    assert request.method == "DELETE"
    assert request.url == "https://api.github.com/applications/client-id/token"
    assert request.headers["authorization"].startswith("Basic ")
    assert request.read() == b'{"access_token":"access-token"}'


async def test_github_delegates_code_exchange_refresh_and_close() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "access_token": "new-access",
                "refresh_token": "new-refresh",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "read:user user:email",
            },
            request=request,
        )

    github = provider(handler)

    exchanged = await github.exchange_code(code=SecretStr("code"), transaction=transaction(), now=NOW)
    refreshed = await github.refresh(SecretStr("refresh"), now=NOW)
    await github.aclose()

    assert exchanged.access_token.get_secret_value() == "new-access"
    assert refreshed.refresh_token is not None
    assert github.oauth.closed


async def test_github_rejects_invalid_or_failed_revocation() -> None:
    github = provider(lambda request: httpx.Response(500, request=request))

    with pytest.raises(OAuthProviderError):
        await github.revoke(SecretStr("access"), token_type_hint="refresh_token")  # noqa: S106 - OAuth token kind
    with pytest.raises(OAuthProviderError):
        await github.revoke(SecretStr("access"), token_type_hint=None)


async def test_github_sanitizes_revocation_transport_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        detail = "secret"
        raise httpx.ConnectError(detail, request=request)

    with pytest.raises(OAuthProviderError, match="OAuth provider request failed"):
        await provider(handler).revoke(SecretStr("access"), token_type_hint=None)


@pytest.mark.parametrize(
    "profile",
    [
        {},
        {"id": True, "login": "user"},
        {"id": 0, "login": "user"},
        {"id": 1, "login": ""},
        {"id": 1, "login": "user", "name": 1},
    ],
)
async def test_github_rejects_malformed_profile(profile: dict[str, object]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return httpx.Response(200, json=profile)
        return httpx.Response(200, json=[])

    with pytest.raises(OAuthProviderError):
        await provider(handler).resolve_identity(tokens(), transaction=transaction(), now=NOW)


@pytest.mark.parametrize(
    "emails",
    [
        {},
        [{"email": 1, "verified": True, "primary": True}],
        [{"email": "a@example.com", "verified": "true", "primary": True}],
        [{"email": "a@example.com", "verified": True, "primary": "true"}],
    ],
)
async def test_github_rejects_malformed_email_response(emails: object) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return httpx.Response(200, json={"id": 1, "login": "user"})
        return httpx.Response(200, json=emails)

    with pytest.raises(OAuthProviderError):
        await provider(handler).resolve_identity(tokens(), transaction=transaction(), now=NOW)


@pytest.mark.parametrize(("content_type", "body"), [("text/plain", b"{}"), ("application/json", b"{")])
async def test_github_rejects_invalid_api_documents(content_type: str, body: bytes) -> None:
    github = provider(
        lambda request: httpx.Response(200, headers={"content-type": content_type}, content=body, request=request)
    )

    with pytest.raises(OAuthProviderError):
        await github.resolve_identity(tokens(), transaction=transaction(), now=NOW)


@pytest.mark.parametrize(
    ("profile", "emails"), [([], []), ({"id": 1, "login": "user"}, {}), ({"id": 1, "login": "user"}, [1])]
)
async def test_github_rejects_wrong_api_shapes(profile: object, emails: object) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=profile if request.url.path == "/user" else emails, request=request)

    with pytest.raises(OAuthProviderError):
        await provider(handler).resolve_identity(tokens(), transaction=transaction(), now=NOW)


async def test_github_sanitizes_profile_transport_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        detail = "secret"
        raise httpx.ConnectError(detail, request=request)

    with pytest.raises(OAuthProviderError, match="OAuth provider request failed"):
        await provider(handler).resolve_identity(tokens(), transaction=transaction(), now=NOW)


@pytest.mark.parametrize("retry_after", [None, "invalid", "0", "86401"])
async def test_github_ignores_invalid_retry_after(retry_after: str | None) -> None:
    headers = {} if retry_after is None else {"retry-after": retry_after}
    github = provider(lambda request: httpx.Response(429, headers=headers, request=request))

    with pytest.raises(OAuthProviderError) as captured:
        await github.resolve_identity(tokens(), transaction=transaction(), now=NOW)

    assert captured.value.retry_after is None


def test_provider_identity_deep_freezes_raw_github_values() -> None:
    identity = ProviderIdentity(
        provider="github",
        issuer="https://github.com",
        subject="1",
        display_name="user",
        email=None,
        email_verified=False,
        raw_claims={"nested": {"items": [1, 2]}},
    )

    assert identity.raw_claims["nested"] == {"items": (1, 2)}

    with pytest.raises(ValueError, match="Provider identity is invalid"):
        ProviderIdentity(
            provider="github",
            issuer="https://github.com",
            subject="1",
            display_name="user",
            email=None,
            email_verified=False,
            raw_claims={"nested": {1: "invalid"}},
        )
