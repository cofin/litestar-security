"""Generic OAuth provider and hardened HTTP boundary contracts."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.providers.oauth import (
    OAuthClientAuth,
    OAuthEndpointConfig,
    OAuthHTTPPolicy,
    OAuthOperation,
    OAuthProvider,
    OAuthProviderClient,
    OAuthProviderError,
    OAuthTransaction,
    OAuthTransactionStart,
    ProviderGrant,
    ProviderIdentity,
    ProviderTokenSet,
    SecretStr,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    Handler = Callable[[httpx.Request], httpx.Response] | Callable[[httpx.Request], Coroutine[Any, Any, httpx.Response]]


_NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)
_AUTHORIZATION_ENDPOINT = "https://issuer.example/oauth/authorize"
_TOKEN_ENDPOINT = "https://issuer.example/oauth/token"  # noqa: S105 - endpoint path, not a credential
_REVOCATION_ENDPOINT = "https://issuer.example/oauth/revoke"
_CLIENT_SECRET = SecretStr("client-secret")


def _transaction(*, scopes: frozenset[str] = frozenset({"openid", "profile"})) -> OAuthTransaction:
    return OAuthTransaction(
        state_digest=b"s" * 32,
        binding_digest=b"b" * 32,
        operation=OAuthOperation.LOGIN,
        provider="example",
        expected_issuer="https://issuer.example",
        redirect_uri="https://app.example/auth/example/callback",
        return_to="/",
        requested_scopes=scopes,
        pkce_verifier=SecretStr("v" * 43),
        nonce=SecretStr("n" * 43),
        account_id=None,
        session_binding=None,
        expires_at=_NOW + timedelta(minutes=10),
    )


def _start() -> OAuthTransactionStart:
    return OAuthTransactionStart(
        state=SecretStr("s" * 43),
        browser_binding=SecretStr("b" * 43),
        pkce_challenge="challenge",
        nonce=SecretStr("n" * 43),
        transaction=_transaction(),
    )


def _config(
    *,
    client_auth: OAuthClientAuth = OAuthClientAuth.CLIENT_SECRET_BASIC,
    client_secret: SecretStr | None = _CLIENT_SECRET,
) -> OAuthEndpointConfig:
    return OAuthEndpointConfig(
        name="example",
        client_id="client-id",
        client_secret=client_secret,
        client_auth=client_auth,
        authorization_endpoint=_AUTHORIZATION_ENDPOINT,
        token_endpoint=_TOKEN_ENDPOINT,
        revocation_endpoint=_REVOCATION_ENDPOINT,
        allowed_scopes=frozenset({"openid", "profile", "email"}),
        required_scopes=frozenset({"openid"}),
        extra_authorization_parameters={"prompt": "consent"},
    )


def _json_response(request: httpx.Request, payload: dict[str, object], *, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code, headers={"content-type": "application/json"}, content=json.dumps(payload).encode(), request=request
    )


def _client(
    handler: Handler, *, config: OAuthEndpointConfig | None = None, policy: OAuthHTTPPolicy | None = None
) -> OAuthProviderClient:
    return OAuthProviderClient(
        config or _config(), policy=policy or OAuthHTTPPolicy(), transport=httpx.MockTransport(handler)
    )


def test_provider_protocol_uses_redacted_typed_contracts() -> None:
    class Provider:
        name = "example"

        async def build_authorization_url(self, start: OAuthTransactionStart) -> str:
            del start
            return _AUTHORIZATION_ENDPOINT

        async def exchange_code(self, *, code: SecretStr, transaction: OAuthTransaction) -> ProviderTokenSet:
            del code, transaction
            return _tokens()

        async def resolve_identity(self, tokens: ProviderTokenSet) -> ProviderIdentity:
            del tokens
            return _identity()

        async def refresh(self, refresh_token: SecretStr) -> ProviderTokenSet:
            del refresh_token
            return _tokens()

        async def revoke(self, token: SecretStr, *, token_type_hint: str | None) -> None:
            del token, token_type_hint

    assert isinstance(Provider(), OAuthProvider)
    assert "client-secret" not in repr(_config())
    assert "access-token" not in repr(_tokens())


def test_authorization_url_is_code_pkce_and_transaction_bound() -> None:
    client = _client(lambda request: httpx.Response(500, request=request))

    url = client.build_authorization_url(_start())
    split = urlsplit(url)
    query = parse_qs(split.query)

    assert f"{split.scheme}://{split.netloc}{split.path}" == _AUTHORIZATION_ENDPOINT
    assert query == {
        "client_id": ["client-id"],
        "code_challenge": ["challenge"],
        "code_challenge_method": ["S256"],
        "nonce": ["n" * 43],
        "prompt": ["consent"],
        "redirect_uri": ["https://app.example/auth/example/callback"],
        "response_type": ["code"],
        "scope": ["openid profile"],
        "state": ["s" * 43],
    }


def test_authorization_url_without_oidc_nonce_omits_nonce() -> None:
    client = _client(lambda request: httpx.Response(500, request=request))
    start = replace(_start(), nonce=None, transaction=replace(_transaction(), nonce=None))

    query = parse_qs(urlsplit(client.build_authorization_url(start)).query)

    assert "nonce" not in query


@pytest.mark.parametrize(
    "transaction",
    [
        replace(_transaction(), provider="other"),
        replace(_transaction(), requested_scopes=frozenset({"admin"})),
        replace(_transaction(), requested_scopes=frozenset({"profile"})),
    ],
)
def test_authorization_url_rejects_provider_or_scope_mismatch(transaction: OAuthTransaction) -> None:
    client = _client(lambda request: httpx.Response(500, request=request))
    start = replace(_start(), transaction=transaction)

    with pytest.raises(OAuthProviderError, match="failed"):
        client.build_authorization_url(start)


@pytest.mark.anyio
async def test_exchange_uses_basic_auth_exact_redirect_and_pkce() -> None:
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json_response(
            request,
            {
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "id_token": "id-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid profile",
            },
        )

    async with _client(handler) as client:
        tokens = await client.exchange_code(code=SecretStr("authorization-code"), transaction=_transaction(), now=_NOW)

    request = seen[0]
    form = parse_qs(request.content.decode())
    assert request.url == _TOKEN_ENDPOINT
    assert request.headers["authorization"].startswith("Basic ")
    assert form == {
        "code": ["authorization-code"],
        "code_verifier": ["v" * 43],
        "grant_type": ["authorization_code"],
        "redirect_uri": ["https://app.example/auth/example/callback"],
    }
    assert tokens.access_token.get_secret_value() == "access-token"
    assert tokens.refresh_token is not None
    assert tokens.refresh_token.get_secret_value() == "refresh-token"
    assert tokens.id_token is not None
    assert tokens.scopes == frozenset({"openid", "profile"})
    assert tokens.expires_at == _NOW + timedelta(hours=1)
    assert client.closed is True


@pytest.mark.anyio
async def test_exchange_accepts_form_response_and_omitted_unchanged_scope() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/x-www-form-urlencoded"},
            content=b"access_token=access-token&token_type=bearer&expires_in=60",
            request=request,
        )

    async with _client(handler) as client:
        tokens = await client.exchange_code(code=SecretStr("authorization-code"), transaction=_transaction(), now=_NOW)

    assert tokens.scopes == frozenset({"openid", "profile"})


@pytest.mark.anyio
async def test_post_client_auth_and_refresh_rotation() -> None:
    seen: list[dict[str, list[str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(parse_qs(request.content.decode()))
        return _json_response(
            request,
            {
                "access_token": "new-access",
                "refresh_token": "new-refresh",
                "token_type": "Bearer",
                "expires_in": 120,
                "scope": "openid email",
            },
        )

    async with _client(handler, config=_config(client_auth=OAuthClientAuth.CLIENT_SECRET_POST)) as client:
        tokens = await client.refresh(SecretStr("old-refresh"), now=_NOW)

    assert seen == [
        {
            "client_id": ["client-id"],
            "client_secret": ["client-secret"],
            "grant_type": ["refresh_token"],
            "refresh_token": ["old-refresh"],
        }
    ]
    assert tokens.access_token.get_secret_value() == "new-access"
    assert tokens.refresh_token is not None
    assert tokens.refresh_token.get_secret_value() == "new-refresh"


@pytest.mark.anyio
async def test_public_client_sends_client_id_without_secret() -> None:
    seen: list[dict[str, list[str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(parse_qs(request.content.decode()))
        return _json_response(
            request, {"access_token": "access", "token_type": "Bearer", "expires_in": 60, "scope": "openid"}
        )

    async with _client(handler, config=_config(client_auth=OAuthClientAuth.NONE, client_secret=None)) as client:
        await client.refresh(SecretStr("refresh"), now=_NOW)

    assert seen[0]["client_id"] == ["client-id"]
    assert "client_secret" not in seen[0]


@pytest.mark.anyio
async def test_revoke_uses_fixed_endpoint_and_hint() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, request=request)

    async with _client(handler) as client:
        await client.revoke(
            SecretStr("refresh-token"),
            token_type_hint="refresh_token",  # noqa: S106 - standardized OAuth token type hint
        )

    form = parse_qs(seen[0].content.decode())
    assert seen[0].url == _REVOCATION_ENDPOINT
    assert form["token"] == ["refresh-token"]
    assert form["token_type_hint"] == ["refresh_token"]


@pytest.mark.anyio
async def test_revoke_without_hint_and_provider_failures_are_sanitized() -> None:
    requests: list[httpx.Request] = []

    def success(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, request=request)

    async with _client(success) as client:
        await client.revoke(SecretStr("access-token"), token_type_hint=None)
    assert "token_type_hint" not in parse_qs(requests[0].content.decode())

    def rejected(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, content=b"provider detail", request=request)

    async with _client(rejected) as client:
        with pytest.raises(OAuthProviderError, match="failed"):
            await client.revoke(SecretStr("token"), token_type_hint=None)

    def unavailable(request: httpx.Request) -> httpx.Response:
        del request
        message = "transport detail"
        raise RuntimeError(message)

    async with _client(unavailable) as client:
        with pytest.raises(OAuthProviderError, match="failed") as exc_info:
            await client.revoke(SecretStr("token"), token_type_hint=None)
    assert "transport detail" not in repr(exc_info.value)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("config", "token", "hint"),
    [
        (replace(_config(), revocation_endpoint=None), SecretStr("token"), None),
        (_config(), cast("Any", "token"), None),
        (_config(), SecretStr("token"), "invalid"),
    ],
)
async def test_revoke_rejects_unsupported_or_malformed_input(
    config: OAuthEndpointConfig, token: Any, hint: str | None
) -> None:
    async with _client(lambda request: httpx.Response(200, request=request), config=config) as client:
        with pytest.raises(OAuthProviderError, match="failed"):
            await client.revoke(token, token_type_hint=hint)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "case",
    [
        "redirect",
        "status",
        "content-type",
        "json",
        "json-list",
        "duplicate",
        "form-duplicate",
        "token-type",
        "expiry",
        "expiry-type",
        "scope",
        "scope-type",
        "scope-duplicate",
        "missing-access",
        "bad-refresh",
    ],
)
async def test_exchange_maps_malformed_or_rejected_responses_to_one_secret_free_error(  # noqa: C901 - matrix branches
    case: str,
) -> None:
    def response(  # noqa: PLR0911 - explicit response-shape matrix keeps each malformed case visible
        request: httpx.Request,
    ) -> httpx.Response:
        if case == "redirect":
            return httpx.Response(302, headers={"location": "https://evil.example"}, request=request)
        if case == "status":
            return httpx.Response(500, content=b"provider secret detail", request=request)
        if case == "content-type":
            return httpx.Response(200, headers={"content-type": "text/html"}, content=b"<secret>", request=request)
        if case == "json":
            return httpx.Response(200, headers={"content-type": "application/json"}, content=b"{", request=request)
        if case == "json-list":
            return httpx.Response(200, headers={"content-type": "application/json"}, content=b"[]", request=request)
        if case == "duplicate":
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=b'{"access_token":"one","access_token":"two"}',
                request=request,
            )
        if case == "form-duplicate":
            return httpx.Response(
                200,
                headers={"content-type": "application/x-www-form-urlencoded"},
                content=b"access_token=one&access_token=two&token_type=Bearer&expires_in=60",
                request=request,
            )
        payload: dict[str, object] = {
            "access_token": "access",
            "token_type": "mac" if case == "token-type" else "Bearer",
            "expires_in": "invalid" if case == "expiry-type" else 0 if case == "expiry" else 60,
            "scope": (
                1
                if case == "scope-type"
                else "openid openid"
                if case == "scope-duplicate"
                else "profile"
                if case == "scope"
                else "openid"
            ),
        }
        if case == "missing-access":
            payload.pop("access_token")
        if case == "bad-refresh":
            payload["refresh_token"] = 1
        return _json_response(request, payload)

    async with _client(response) as client:
        with pytest.raises(OAuthProviderError, match="failed") as exc_info:
            await client.exchange_code(code=SecretStr("authorization-code"), transaction=_transaction(), now=_NOW)

    assert "provider secret detail" not in repr(exc_info.value)
    assert "access-token" not in repr(exc_info.value)


@pytest.mark.anyio
async def test_response_body_is_bounded_while_streaming() -> None:
    body = json.dumps({"access_token": "x" * 500, "token_type": "Bearer", "expires_in": 60, "scope": "openid"}).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json", "content-length": str(len(body))},
            content=body,
            request=request,
        )

    policy = OAuthHTTPPolicy(maximum_response_bytes=128)
    async with _client(handler, policy=policy) as client:
        with pytest.raises(OAuthProviderError, match="failed"):
            await client.exchange_code(code=SecretStr("code"), transaction=_transaction(), now=_NOW)


@pytest.mark.anyio
@pytest.mark.parametrize("case", ["invalid-length", "stream"])
async def test_response_stream_rejects_invalid_length_and_incremental_overflow(case: str) -> None:
    body = json.dumps({"access_token": "x" * 500, "token_type": "Bearer", "expires_in": 60, "scope": "openid"}).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        headers = {"content-type": "application/json"}
        if case == "invalid-length":
            headers["content-length"] = "invalid"
            return httpx.Response(200, headers=headers, content=body, request=request)
        return httpx.Response(200, headers=headers, stream=httpx.ByteStream(body), request=request)

    async with _client(handler, policy=OAuthHTTPPolicy(maximum_response_bytes=128)) as client:
        with pytest.raises(OAuthProviderError, match="failed"):
            await client.exchange_code(code=SecretStr("code"), transaction=_transaction(), now=_NOW)


@pytest.mark.anyio
async def test_network_failure_is_generic_and_cancellation_propagates() -> None:
    def network_failure(request: httpx.Request) -> httpx.Response:
        message = "network detail"
        raise httpx.ConnectTimeout(message, request=request)

    async with _client(network_failure) as client:
        with pytest.raises(OAuthProviderError, match="failed") as exc_info:
            await client.refresh(SecretStr("refresh"), now=_NOW)
    assert "network detail" not in repr(exc_info.value)

    async def cancelled(request: httpx.Request) -> httpx.Response:
        del request
        raise asyncio.CancelledError

    async with _client(cancelled) as client:
        with pytest.raises(asyncio.CancelledError):
            await client.refresh(SecretStr("refresh"), now=_NOW)


@pytest.mark.anyio
async def test_close_is_idempotent_and_closed_client_rejects_use() -> None:
    client = _client(lambda request: httpx.Response(200, request=request))

    await client.aclose()
    await client.aclose()

    assert client.closed is True
    with pytest.raises(OAuthProviderError, match="closed"):
        client.build_authorization_url(_start())


@pytest.mark.parametrize(("config", "policy"), [(cast("Any", object()), None), (_config(), cast("Any", object()))])
def test_provider_client_requires_normalized_configuration(config: Any, policy: Any) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        OAuthProviderClient(config, policy=policy)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("code", "transaction"),
    [(cast("Any", "code"), _transaction()), (SecretStr("code"), replace(_transaction(), provider="other"))],
)
async def test_exchange_rejects_malformed_code_or_provider(code: Any, transaction: OAuthTransaction) -> None:
    async with _client(lambda request: httpx.Response(200, request=request)) as client:
        with pytest.raises(OAuthProviderError, match="failed"):
            await client.exchange_code(code=code, transaction=transaction, now=_NOW)


@pytest.mark.anyio
async def test_refresh_rejects_malformed_token_and_naive_time() -> None:
    async with _client(lambda request: httpx.Response(200, request=request)) as client:
        with pytest.raises(OAuthProviderError, match="failed"):
            await client.refresh(cast("Any", "refresh"), now=_NOW)
        with pytest.raises(OAuthProviderError, match="failed"):
            await client.refresh(SecretStr("refresh"), now=_NOW.replace(tzinfo=None))


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": ""},
        {"client_id": ""},
        {"authorization_endpoint": "http://issuer.example/authorize"},
        {"token_endpoint": "https://issuer.example/token#fragment"},
        {"revocation_endpoint": "https://user@issuer.example/revoke"},
        {"allowed_scopes": frozenset[str]()},
        {"required_scopes": frozenset({"admin"})},
        {"client_auth": OAuthClientAuth.CLIENT_SECRET_BASIC, "client_secret": None},
        {"client_auth": OAuthClientAuth.NONE, "client_secret": SecretStr("unexpected")},
        {"extra_authorization_parameters": {"state": "override"}},
        {"client_auth": cast("Any", "client_secret_basic")},
        {"extra_authorization_parameters": cast("Any", [])},
        {"extra_authorization_parameters": {"": "value"}},
        {"extra_authorization_parameters": {"prompt": ""}},
        {"allowed_scopes": cast("Any", {"openid"})},
        {"allowed_scopes": frozenset({'bad"scope'})},
        {"required_scopes": cast("Any", {"openid"})},
        {"required_scopes": frozenset({""})},
        {"token_endpoint": "https://issuer.example:invalid/token"},
        {"token_endpoint": "https://issuer.example/token?query=true"},
        {"token_endpoint": " https://issuer.example/token"},
        {"token_endpoint": "https://*.example/token"},
        {"token_endpoint": "https://issuer.example\\token"},
    ],
)
def test_endpoint_configuration_fails_closed(overrides: dict[str, Any]) -> None:
    arguments: dict[str, Any] = {
        "name": "example",
        "client_id": "client-id",
        "client_secret": SecretStr("secret"),
        "client_auth": OAuthClientAuth.CLIENT_SECRET_BASIC,
        "authorization_endpoint": _AUTHORIZATION_ENDPOINT,
        "token_endpoint": _TOKEN_ENDPOINT,
        "revocation_endpoint": _REVOCATION_ENDPOINT,
        "allowed_scopes": frozenset({"openid"}),
        "required_scopes": frozenset({"openid"}),
    }
    arguments.update(overrides)

    with pytest.raises(ImproperlyConfiguredException):
        OAuthEndpointConfig(**arguments)


@pytest.mark.parametrize(
    "overrides",
    [
        {"connect_timeout": 0},
        {"read_timeout": float("inf")},
        {"write_timeout": -1},
        {"pool_timeout": 0},
        {"maximum_connections": 0},
        {"maximum_response_bytes": 0},
    ],
)
def test_http_policy_requires_bounded_positive_resources(overrides: dict[str, Any]) -> None:
    arguments: dict[str, Any] = {}
    arguments.update(overrides)
    with pytest.raises(ImproperlyConfiguredException):
        OAuthHTTPPolicy(**arguments)


@pytest.mark.parametrize(
    "overrides",
    [
        {"access_token": cast("Any", "access")},
        {"token_type": "MAC"},
        {"scopes": cast("Any", {"openid"})},
        {"scopes": frozenset({""})},
        {"expires_at": _NOW.replace(tzinfo=None)},
        {"refresh_token": cast("Any", "refresh")},
        {"id_token": cast("Any", "id")},
    ],
)
def test_provider_token_set_rejects_malformed_values(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="token set"):
        replace(_tokens(), **overrides)


@pytest.mark.parametrize(
    "overrides",
    [{"scopes": cast("Any", {"openid"})}, {"scopes": frozenset({""})}, {"expires_at": _NOW.replace(tzinfo=None)}],
)
def test_provider_grant_rejects_malformed_values(overrides: dict[str, Any]) -> None:
    grant = ProviderGrant(scopes=frozenset({"openid"}), expires_at=_NOW + timedelta(hours=1))
    with pytest.raises(ValueError, match="grant"):
        replace(grant, **overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {"provider": ""},
        {"issuer": ""},
        {"subject": ""},
        {"display_name": ""},
        {"email": ""},
        {"email_verified": cast("Any", 1)},
        {"raw_claims": cast("Any", [])},
        {"raw_claims": {"": "value"}},
    ],
)
def test_provider_identity_rejects_malformed_values(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="identity"):
        replace(_identity(), **overrides)


def test_provider_identity_allows_optional_profile_values_and_freezes_claims() -> None:
    claims = {"sub": "subject-1"}
    identity = replace(_identity(), display_name=None, email=None, raw_claims=claims)
    claims["sub"] = "changed"

    assert identity.raw_claims["sub"] == "subject-1"


def _tokens() -> ProviderTokenSet:
    return ProviderTokenSet(
        access_token=SecretStr("access-token"),
        token_type="Bearer",  # noqa: S106 - standardized OAuth token type, not a credential
        scopes=frozenset({"openid"}),
        expires_at=_NOW + timedelta(hours=1),
        refresh_token=SecretStr("refresh-token"),
        id_token=SecretStr("id-token"),
    )


def _identity() -> ProviderIdentity:
    return ProviderIdentity(
        provider="example",
        issuer="https://issuer.example",
        subject="subject-1",
        display_name="Example",
        email="user@example.com",
        email_verified=True,
        raw_claims={"sub": "subject-1"},
    )


def test_token_identity_and_grant_types_validate_and_redact() -> None:
    tokens = _tokens()
    identity = _identity()
    grant = ProviderGrant(scopes=tokens.scopes, expires_at=tokens.expires_at)

    assert "access-token" not in repr(tokens)
    assert identity.subject == "subject-1"
    assert grant.scopes == frozenset({"openid"})
