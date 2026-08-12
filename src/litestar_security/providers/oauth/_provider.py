"""Generic OAuth provider contracts and hardened async HTTP boundary."""

import asyncio
import ipaddress
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from types import MappingProxyType
from typing import NoReturn, Protocol, cast, runtime_checkable
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

import httpx
from litestar.exceptions import ImproperlyConfiguredException
from typing_extensions import Self

from litestar_security.providers._internal import (
    AddressResolver,
    public_address,
    reject_non_finite,
    resolve_addresses,
    unique_object,
    validate_depth,
)
from litestar_security.providers.oauth._transactions import OAuthTransaction, OAuthTransactionStart, SecretStr

__all__ = (
    "GitHubOAuthProvider",
    "InvalidProviderGrantError",
    "OAuthClientAuth",
    "OAuthEndpointConfig",
    "OAuthHTTPPolicy",
    "OAuthProvider",
    "OAuthProviderClient",
    "OAuthProviderError",
    "ProviderGrant",
    "ProviderIdentity",
    "ProviderTokenSet",
)


_DEFAULT_CONNECT_TIMEOUT = 2.0
_DEFAULT_READ_TIMEOUT = 5.0
_DEFAULT_WRITE_TIMEOUT = 5.0
_DEFAULT_POOL_TIMEOUT = 2.0
_DEFAULT_CONNECTIONS = 20
_DEFAULT_RESPONSE_BYTES = 65_536
_MAXIMUM_CONNECTIONS = 1_000
_MAXIMUM_RESPONSE_BYTES = 1_048_576
_MAXIMUM_EXPIRES_SECONDS = 315_360_000
_MAXIMUM_JSON_DEPTH = 16
_MAXIMUM_TCP_PORT = 65_535
_SCOPE_ASCII_MINIMUM = 0x21
_SCOPE_ASCII_MAXIMUM = 0x7E
_HTTP_OK = 200
_HTTP_NO_CONTENT = 204
_BEARER_TOKEN_TYPE = "Bearer"  # noqa: S105 - standardized OAuth token type, not a credential
_GITHUB_ISSUER = "https://github.com"
_GITHUB_API = "https://api.github.com"
_GITHUB_TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"  # noqa: S105 - endpoint, not a credential
_GITHUB_ACCEPT = "application/vnd.github+json"
_GITHUB_API_VERSION = "2022-11-28"
_GITHUB_REQUIRED_SCOPES = frozenset({"read:user", "user:email"})
_GITHUB_MAXIMUM_RETRY_AFTER = 86_400
_RESERVED_AUTHORIZATION_PARAMETERS = frozenset({
    "client_id",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
})


def _empty_parameters() -> dict[str, str]:
    return {}


class OAuthClientAuth(str, Enum):
    """Supported OAuth token-endpoint client authentication methods."""

    CLIENT_SECRET_BASIC = "client_secret_basic"  # noqa: S105 - standardized OAuth auth method identifier
    CLIENT_SECRET_POST = "client_secret_post"  # noqa: S105 - standardized OAuth auth method identifier
    NONE = "none"


@dataclass(frozen=True, slots=True)
class OAuthHTTPPolicy:
    """Bounded HTTP resource policy shared by one provider client."""

    connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT
    read_timeout: float = _DEFAULT_READ_TIMEOUT
    write_timeout: float = _DEFAULT_WRITE_TIMEOUT
    pool_timeout: float = _DEFAULT_POOL_TIMEOUT
    maximum_connections: int = _DEFAULT_CONNECTIONS
    maximum_response_bytes: int = _DEFAULT_RESPONSE_BYTES

    def __post_init__(self) -> None:
        """Require finite timeouts and bounded integer resources."""
        if (
            not _positive_finite(self.connect_timeout)
            or not _positive_finite(self.read_timeout)
            or not _positive_finite(self.write_timeout)
            or not _positive_finite(self.pool_timeout)
            or self.maximum_connections.__class__ is not int
            or not 1 <= self.maximum_connections <= _MAXIMUM_CONNECTIONS
            or self.maximum_response_bytes.__class__ is not int
            or not 1 <= self.maximum_response_bytes <= _MAXIMUM_RESPONSE_BYTES
        ):
            _raise_config("OAuth HTTP resource limits must be positive and bounded")


@dataclass(frozen=True, slots=True)
class OAuthEndpointConfig:
    """Normalized operator-controlled endpoints and provider client policy."""

    name: str
    client_id: str
    client_secret: SecretStr | None
    client_auth: OAuthClientAuth
    authorization_endpoint: str
    token_endpoint: str
    revocation_endpoint: str | None
    allowed_scopes: frozenset[str]
    required_scopes: frozenset[str]
    extra_authorization_parameters: Mapping[str, str] = field(default_factory=_empty_parameters)

    def __post_init__(self) -> None:
        """Validate provider identity, fixed endpoints, scopes, and client auth."""
        if not _strict_text(self.name) or not _strict_text(self.client_id):
            _raise_config("OAuth provider name and client ID must not be blank")
        if self.client_auth.__class__ is not OAuthClientAuth:
            _raise_config("OAuth client authentication method is invalid")
        has_secret = self.client_secret is not None and self.client_secret.__class__ is SecretStr
        if (self.client_auth is OAuthClientAuth.NONE and self.client_secret is not None) or (
            self.client_auth is not OAuthClientAuth.NONE and not has_secret
        ):
            _raise_config("OAuth client secret does not match the authentication method")
        _validate_endpoint(self.authorization_endpoint)
        _validate_endpoint(self.token_endpoint)
        if self.revocation_endpoint is not None:
            _validate_endpoint(self.revocation_endpoint)
        if (
            self.allowed_scopes.__class__ is not frozenset
            or not self.allowed_scopes
            or any(not _valid_scope(scope) for scope in self.allowed_scopes)
            or self.required_scopes.__class__ is not frozenset
            or any(not _valid_scope(scope) for scope in self.required_scopes)
            or not self.required_scopes.issubset(self.allowed_scopes)
        ):
            _raise_config("OAuth provider scopes must be immutable, valid, and allowlisted")
        parameters = cast("object", self.extra_authorization_parameters)
        if not isinstance(parameters, Mapping):
            _raise_config("OAuth authorization parameters must be a mapping")
        normalized_parameters: dict[str, str] = {}
        for key, value in self.extra_authorization_parameters.items():
            if (
                not _strict_text(key)
                or not _strict_text(value)
                or key in _RESERVED_AUTHORIZATION_PARAMETERS
                or key in normalized_parameters
            ):
                _raise_config("OAuth authorization parameters cannot override protocol bindings")
            normalized_parameters[key] = value
        object.__setattr__(self, "extra_authorization_parameters", MappingProxyType(normalized_parameters))


@dataclass(frozen=True, slots=True)
class ProviderTokenSet:
    """Validated provider credentials kept out of normal representations."""

    access_token: SecretStr = field(repr=False)
    token_type: str
    scopes: frozenset[str]
    expires_at: datetime
    refresh_token: SecretStr | None = field(default=None, repr=False)
    id_token: SecretStr | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Require bearer credentials, immutable scopes, and aware expiry."""
        if (
            self.access_token.__class__ is not SecretStr
            or self.token_type != _BEARER_TOKEN_TYPE
            or self.scopes.__class__ is not frozenset
            or any(not _valid_scope(scope) for scope in self.scopes)
            or not _aware_time(self.expires_at)
            or (self.refresh_token is not None and self.refresh_token.__class__ is not SecretStr)
            or (self.id_token is not None and self.id_token.__class__ is not SecretStr)
        ):
            message = "Provider token set is invalid"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class ProviderGrant:
    """Secret-free provider scope grant projection."""

    scopes: frozenset[str]
    expires_at: datetime

    def __post_init__(self) -> None:
        """Require immutable valid scopes and an aware expiry."""
        if (
            self.scopes.__class__ is not frozenset
            or any(not _valid_scope(scope) for scope in self.scopes)
            or not _aware_time(self.expires_at)
        ):
            message = "Provider grant is invalid"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class ProviderIdentity:
    """Verified immutable provider identity."""

    provider: str
    issuer: str
    subject: str
    display_name: str | None
    email: str | None
    email_verified: bool
    raw_claims: Mapping[str, object] = field(repr=False)
    acr: str | None = None
    amr: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Require stable identity keys and freeze verified raw claims."""
        raw_claims = cast("object", self.raw_claims)
        if (
            not _strict_text(self.provider)
            or not _strict_text(self.issuer)
            or not _strict_text(self.subject)
            or (self.display_name is not None and not _strict_text(self.display_name))
            or (self.email is not None and not _strict_text(self.email))
            or self.email_verified.__class__ is not bool
            or (self.acr is not None and not _strict_text(self.acr))
            or self.amr.__class__ is not tuple
            or any(not _strict_text(method) for method in self.amr)
            or len(self.amr) != len(set(self.amr))
            or not isinstance(raw_claims, Mapping)
            or any(not _strict_text(key) for key in self.raw_claims)
        ):
            message = "Provider identity is invalid"
            raise ValueError(message)
        object.__setattr__(self, "raw_claims", _freeze_mapping(self.raw_claims))


@runtime_checkable
class OAuthProvider(Protocol):
    """Interactive OAuth provider lifecycle implemented by configured providers."""

    name: str

    def build_authorization_url(self, start: OAuthTransactionStart) -> str:
        """Build the provider URL from one ephemeral transaction start.

        Args:
            start: The transaction plus its redacted raw browser values.

        Returns:
            The fixed provider authorization endpoint and bound query.
        """
        ...  # pragma: no cover

    async def exchange_code(
        self, *, code: SecretStr, transaction: OAuthTransaction, now: datetime | None = None
    ) -> ProviderTokenSet:
        """Exchange one callback code.

        Args:
            code: The provider callback code.
            transaction: The atomically consumed transaction.
            now: The authoritative response time.

        Returns:
            Validated provider tokens.
        """
        ...  # pragma: no cover

    async def resolve_identity(
        self, tokens: ProviderTokenSet, *, transaction: OAuthTransaction, now: datetime | None = None
    ) -> ProviderIdentity:
        """Resolve a verified identity from validated tokens.

        Args:
            tokens: Validated provider tokens.
            transaction: The consumed transaction binding this identity lookup.
            now: The authoritative verification time.

        Returns:
            The verified provider identity.
        """
        ...  # pragma: no cover

    async def refresh(
        self, refresh_token: SecretStr, *, current_scopes: frozenset[str] | None = None, now: datetime | None = None
    ) -> ProviderTokenSet:
        """Refresh provider credentials.

        Args:
            refresh_token: The protected stored refresh credential.
            current_scopes: Current grant used when the response omits scope.
            now: The authoritative response time.

        Returns:
            The rotated validated provider token set.
        """
        ...  # pragma: no cover

    async def revoke(self, token: SecretStr, *, token_type_hint: str | None) -> None:
        """Revoke a provider credential.

        Args:
            token: The credential to revoke.
            token_type_hint: The optional standardized token type hint.
        """
        ...  # pragma: no cover


class OAuthProviderError(RuntimeError):
    """Stable secret-free provider request failure."""

    def __init__(self, *, closed: bool = False, retry_after: int | None = None) -> None:
        """Initialize a closed-client or generic request failure."""
        self.retry_after = retry_after
        super().__init__("OAuth provider client is closed" if closed else "OAuth provider request failed")


class InvalidProviderGrantError(OAuthProviderError):
    """Indicate that refresh requires provider reauthorization."""


class OAuthProviderClient:
    """Lifecycle-owned fixed-endpoint OAuth HTTP client."""

    __slots__ = ("_client", "_closed", "_resolver", "config", "policy")

    def __init__(
        self,
        config: OAuthEndpointConfig,
        *,
        policy: OAuthHTTPPolicy | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: AddressResolver | None = None,
    ) -> None:
        """Create one bounded async client.

        Args:
            config: Normalized static provider configuration.
            policy: Explicit resource limits.
            transport: Optional test or application transport.
            resolver: Optional asynchronous endpoint address resolver.
        """
        if config.__class__ is not OAuthEndpointConfig:
            _raise_config("OAuth endpoint configuration is invalid")
        if policy is not None and policy.__class__ is not OAuthHTTPPolicy:
            _raise_config("OAuth HTTP policy is invalid")
        self.config = config
        self.policy = policy or OAuthHTTPPolicy()
        self._resolver = resolver or resolve_addresses
        self._closed = False
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            limits=httpx.Limits(
                max_connections=self.policy.maximum_connections,
                max_keepalive_connections=self.policy.maximum_connections,
            ),
            timeout=httpx.Timeout(
                connect=self.policy.connect_timeout,
                read=self.policy.read_timeout,
                write=self.policy.write_timeout,
                pool=self.policy.pool_timeout,
            ),
            transport=transport,
            trust_env=False,
            verify=True,
        )

    @property
    def name(self) -> str:
        """Return the configured provider name."""
        return self.config.name

    @property
    def closed(self) -> bool:
        """Return whether the owned HTTP client has closed."""
        return self._closed

    def build_authorization_url(self, start: OAuthTransactionStart) -> str:
        """Build an Authorization Code plus S256 URL.

        Args:
            start: The ephemeral transaction start.

        Returns:
            The fixed authorization endpoint and encoded transaction bindings.

        Raises:
            OAuthProviderError: If the client is closed or the transaction does
                not match the provider configuration.
        """
        self._require_open()
        transaction = start.transaction
        if (
            transaction.provider != self.name
            or not transaction.requested_scopes.issubset(self.config.allowed_scopes)
            or not self.config.required_scopes.issubset(transaction.requested_scopes)
        ):
            _raise_provider()
        query: dict[str, str] = {
            "client_id": self.config.client_id,
            "code_challenge": start.pkce_challenge,
            "code_challenge_method": "S256",
            "redirect_uri": transaction.redirect_uri,
            "response_type": "code",
            "scope": " ".join(sorted(transaction.requested_scopes)),
            "state": start.state.get_secret_value(),
            **self.config.extra_authorization_parameters,
        }
        if start.nonce is not None:
            query["nonce"] = start.nonce.get_secret_value()
        return f"{self.config.authorization_endpoint}?{urlencode(query)}"

    async def exchange_code(
        self, *, code: SecretStr, transaction: OAuthTransaction, now: datetime | None = None
    ) -> ProviderTokenSet:
        """Exchange one code using the exact redirect URI and PKCE verifier.

        Args:
            code: The callback authorization code.
            transaction: The atomically consumed transaction.
            now: The authoritative response time.

        Returns:
            Validated provider tokens.

        Raises:
            OAuthProviderError: If the request or response fails validation.
        """
        self._require_open()
        if code.__class__ is not SecretStr or transaction.provider != self.name:
            _raise_provider()
        data = {
            "code": code.get_secret_value(),
            "code_verifier": transaction.pkce_verifier.get_secret_value(),
            "grant_type": "authorization_code",
            "redirect_uri": transaction.redirect_uri,
        }
        return await self._token_request(data, fallback_scopes=transaction.requested_scopes, now=_response_time(now))

    async def refresh(
        self, refresh_token: SecretStr, *, current_scopes: frozenset[str] | None = None, now: datetime | None = None
    ) -> ProviderTokenSet:
        """Refresh provider credentials through the fixed token endpoint.

        Args:
            refresh_token: The protected stored refresh credential.
            current_scopes: Current grant used when the response omits scope.
            now: The authoritative response time.

        Returns:
            Validated rotated tokens.

        Raises:
            OAuthProviderError: If the request or response fails validation.
        """
        self._require_open()
        if refresh_token.__class__ is not SecretStr:
            _raise_provider()
        return await self._token_request(
            {"grant_type": "refresh_token", "refresh_token": refresh_token.get_secret_value()},
            fallback_scopes=current_scopes if current_scopes is not None else self.config.required_scopes,
            fallback_refresh_token=refresh_token,
            now=_response_time(now),
        )

    async def revoke(self, token: SecretStr, *, token_type_hint: str | None) -> None:
        """Revoke a provider credential at the configured fixed endpoint.

        Args:
            token: The access or refresh credential.
            token_type_hint: Optional RFC 7009 token type hint.

        Raises:
            OAuthProviderError: If revocation is unsupported or fails.
        """
        self._require_open()
        if (
            self.config.revocation_endpoint is None
            or token.__class__ is not SecretStr
            or (token_type_hint is not None and token_type_hint not in {"access_token", "refresh_token"})
        ):
            _raise_provider()
        data = {"token": token.get_secret_value()}
        if token_type_hint is not None:
            data["token_type_hint"] = token_type_hint
        auth, request_data = self._client_auth(data)
        try:
            url, host, sni_hostname = await self._pinned_endpoint(self.config.revocation_endpoint)
            async with self._client.stream(
                "POST",
                url,
                data=request_data,
                auth=auth,
                headers={"Accept": "application/json", "Accept-Encoding": "identity", "Host": host},
                extensions={"sni_hostname": sni_hostname},
            ) as response:
                if response.status_code != _HTTP_OK:
                    _raise_provider()
                await _read_bounded(response, self.policy.maximum_response_bytes)
        except OAuthProviderError:
            raise
        except Exception:  # noqa: BLE001 - sanitize transport and provider response failures
            raise OAuthProviderError from None

    async def aclose(self) -> None:
        """Close the owned client idempotently."""
        if not self._closed:
            self._closed = True
            await self._client.aclose()

    async def __aenter__(self) -> Self:
        """Enter the owned-client context."""
        self._require_open()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        """Close the owned client on context exit."""
        await self.aclose()

    async def _token_request(
        self,
        data: dict[str, str],
        *,
        fallback_scopes: frozenset[str],
        fallback_refresh_token: SecretStr | None = None,
        now: datetime,
    ) -> ProviderTokenSet:
        auth, request_data = self._client_auth(data)
        try:
            url, host, sni_hostname = await self._pinned_endpoint(self.config.token_endpoint)
            async with self._client.stream(
                "POST",
                url,
                data=request_data,
                auth=auth,
                headers={
                    "Accept": "application/json, application/x-www-form-urlencoded",
                    "Accept-Encoding": "identity",
                    "Host": host,
                },
                extensions={"sni_hostname": sni_hostname},
            ) as response:
                body = await _read_bounded(response, self.policy.maximum_response_bytes)
                if response.status_code != _HTTP_OK:
                    if _is_invalid_grant_response(response.headers.get("content-type", ""), body):
                        raise InvalidProviderGrantError  # noqa: TRY301 - preserve provider reauthorization classification
                    _raise_provider()
                document = _parse_token_document(response.headers.get("content-type", ""), body)
            return _token_set(
                document,
                fallback_scopes=fallback_scopes,
                config=self.config,
                fallback_refresh_token=fallback_refresh_token,
                now=now,
            )
        except OAuthProviderError:
            raise
        except Exception:  # noqa: BLE001 - sanitize transport, parsing, and provider response failures
            raise OAuthProviderError from None

    def _client_auth(self, data: dict[str, str]) -> tuple[httpx.Auth | None, dict[str, str]]:
        request_data = dict(data)
        if self.config.client_auth is OAuthClientAuth.CLIENT_SECRET_BASIC:
            secret = cast("SecretStr", self.config.client_secret)
            return httpx.BasicAuth(self.config.client_id, secret.get_secret_value()), request_data
        request_data["client_id"] = self.config.client_id
        if self.config.client_auth is OAuthClientAuth.CLIENT_SECRET_POST:
            secret = cast("SecretStr", self.config.client_secret)
            request_data["client_secret"] = secret.get_secret_value()
        return None, request_data

    async def _pinned_endpoint(self, endpoint: str) -> tuple[httpx.URL, str, str]:
        url = httpx.URL(endpoint)
        hostname = url.raw_host.decode("ascii")
        port = url.port or 443
        try:
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            addresses = tuple(await self._resolver(hostname, port))
        else:
            addresses = (str(literal),)
        if not addresses:
            _raise_provider()
        try:
            parsed = tuple(ipaddress.ip_address(address) for address in addresses)
        except ValueError:
            _raise_provider()
        if any(not public_address(address) for address in parsed):
            _raise_provider()
        selected = str(parsed[0])
        default_port = 443 if url.scheme == "https" else 80
        authority_host = f"[{hostname}]" if ":" in hostname else hostname
        host = authority_host if port == default_port else f"{authority_host}:{port}"
        return url.copy_with(host=selected), host, hostname

    def _require_open(self) -> None:
        if self._closed:
            raise OAuthProviderError(closed=True)


class GitHubOAuthProvider:
    """GitHub OAuth specialization using current profile and verified-email APIs."""

    __slots__ = ("oauth",)

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: SecretStr,
        scopes: frozenset[str] = _GITHUB_REQUIRED_SCOPES,
        policy: OAuthHTTPPolicy | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """Create a GitHub provider with fixed authorization and API endpoints.

        Args:
            client_id: Registered GitHub OAuth application identifier.
            client_secret: Protected GitHub OAuth application secret.
            scopes: Allowlisted request scopes.
            policy: Bounded shared HTTP policy.
            transport: Optional application or test transport.
        """
        self.oauth = OAuthProviderClient(
            OAuthEndpointConfig(
                name="github",
                client_id=client_id,
                client_secret=client_secret,
                client_auth=OAuthClientAuth.CLIENT_SECRET_BASIC,
                authorization_endpoint="https://github.com/login/oauth/authorize",
                token_endpoint=_GITHUB_TOKEN_ENDPOINT,
                revocation_endpoint=None,
                allowed_scopes=frozenset(scopes),
                required_scopes=_GITHUB_REQUIRED_SCOPES,
            ),
            policy=policy,
            transport=transport,
        )

    @property
    def name(self) -> str:
        """Return GitHub's stable local provider name."""
        return self.oauth.name

    def build_authorization_url(self, start: OAuthTransactionStart) -> str:
        """Build the GitHub Authorization Code plus PKCE URL.

        Args:
            start: The bound transaction start values.

        Returns:
            The fixed GitHub authorization URL.
        """
        return self.oauth.build_authorization_url(start)

    async def exchange_code(
        self, *, code: SecretStr, transaction: OAuthTransaction, now: datetime | None = None
    ) -> ProviderTokenSet:
        """Exchange a GitHub authorization code.

        Args:
            code: The callback code.
            transaction: The consumed transaction.
            now: The authoritative response time.

        Returns:
            The validated GitHub token set.
        """
        return await self.oauth.exchange_code(code=code, transaction=transaction, now=now)

    async def resolve_identity(
        self, tokens: ProviderTokenSet, *, transaction: OAuthTransaction, now: datetime | None = None
    ) -> ProviderIdentity:
        """Re-fetch GitHub profile and verified email for this login.

        Args:
            tokens: The validated GitHub token set.
            transaction: The consumed transaction.
            now: The authoritative identity resolution time.

        Returns:
            Identity keyed only by GitHub's stable numeric user ID.

        Raises:
            OAuthProviderError: If the transaction, scopes, or API responses are invalid.
        """
        _response_time(now)
        if (
            tokens.__class__ is not ProviderTokenSet
            or transaction.__class__ is not OAuthTransaction
            or transaction.provider != self.name
            or transaction.expected_issuer != _GITHUB_ISSUER
            or not _GITHUB_REQUIRED_SCOPES.issubset(tokens.scopes)
        ):
            _raise_provider()
        profile, emails = await asyncio.gather(
            self._api_json("/user", tokens.access_token), self._api_json("/user/emails", tokens.access_token)
        )
        if not isinstance(profile, Mapping) or not isinstance(emails, list):
            _raise_provider()
        profile_document = cast("Mapping[str, object]", profile)
        user_id = profile_document.get("id")
        login = profile_document.get("login")
        name = profile_document.get("name")
        if (
            not isinstance(user_id, int)
            or isinstance(user_id, bool)
            or user_id < 1
            or not _strict_text(login)
            or (name is not None and not _strict_text(name))
        ):
            _raise_provider()
        email = _github_verified_email(cast("list[object]", emails))
        raw_claims = dict(profile_document)
        raw_claims["verified_email"] = email
        return ProviderIdentity(
            provider=self.name,
            issuer=_GITHUB_ISSUER,
            subject=str(user_id),
            display_name=cast("str", name) if name is not None else cast("str", login),
            email=email,
            email_verified=email is not None,
            raw_claims=raw_claims,
        )

    async def refresh(
        self, refresh_token: SecretStr, *, current_scopes: frozenset[str] | None = None, now: datetime | None = None
    ) -> ProviderTokenSet:
        """Refresh an expiring GitHub user token.

        Args:
            refresh_token: The protected GitHub refresh credential.
            current_scopes: Current grant used when the response omits scope.
            now: The authoritative response time.

        Returns:
            The rotated GitHub token set.
        """
        return await self.oauth.refresh(refresh_token, current_scopes=current_scopes, now=now)

    async def revoke(self, token: SecretStr, *, token_type_hint: str | None) -> None:
        """Delete one GitHub OAuth application token grant.

        Args:
            token: The access token to delete.
            token_type_hint: Must be ``access_token`` when supplied.

        Raises:
            OAuthProviderError: If deletion fails.
        """
        self.oauth._require_open()  # pyright: ignore[reportPrivateUsage] # noqa: SLF001 - specialization shares its composed transport lifecycle
        if token.__class__ is not SecretStr or token_type_hint not in {None, "access_token"}:
            _raise_provider()
        secret = cast("SecretStr", self.oauth.config.client_secret)
        try:
            async with self.oauth._client.stream(  # pyright: ignore[reportPrivateUsage] # noqa: SLF001 - specialization shares its composed hardened client
                "DELETE",
                f"{_GITHUB_API}/applications/{quote(self.oauth.config.client_id, safe='')}/token",
                auth=httpx.BasicAuth(self.oauth.config.client_id, secret.get_secret_value()),
                json={"access_token": token.get_secret_value()},
                headers=_github_headers(),
            ) as response:
                if response.status_code != _HTTP_NO_CONTENT:
                    _raise_github_response(response)
                await _read_bounded(response, self.oauth.policy.maximum_response_bytes)
        except OAuthProviderError:
            raise
        except Exception:  # noqa: BLE001 - sanitize transport failures
            raise OAuthProviderError from None

    async def aclose(self) -> None:
        """Close the shared owned GitHub HTTP client."""
        await self.oauth.aclose()

    async def _api_json(self, path: str, token: SecretStr) -> object:
        self.oauth._require_open()  # pyright: ignore[reportPrivateUsage] # noqa: SLF001 - specialization shares its composed transport lifecycle
        try:
            async with self.oauth._client.stream(  # pyright: ignore[reportPrivateUsage] # noqa: SLF001 - specialization shares its composed hardened client
                "GET",
                f"{_GITHUB_API}{path}",
                headers={**_github_headers(), "Authorization": f"Bearer {token.get_secret_value()}"},
            ) as response:
                if response.status_code != _HTTP_OK:
                    _raise_github_response(response)
                body = await _read_bounded(response, self.oauth.policy.maximum_response_bytes)
                if response.headers.get("content-type", "").partition(";")[0].strip().lower() != "application/json":
                    _raise_provider()
            value = json.loads(body, object_pairs_hook=unique_object, parse_constant=reject_non_finite)
            validate_depth(value, maximum=_MAXIMUM_JSON_DEPTH)
        except OAuthProviderError:
            raise
        except Exception:  # noqa: BLE001 - sanitize transport and provider response failures
            raise OAuthProviderError from None
        return value


async def _read_bounded(response: httpx.Response, maximum: int) -> bytes:
    if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
        _raise_provider()
    content_length = response.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > maximum:
                _raise_provider()
        except ValueError:
            raise OAuthProviderError from None
    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(chunk) > maximum - len(body):
            _raise_provider()
        body.extend(chunk)
    return bytes(body)


def _github_verified_email(values: list[object]) -> str | None:
    verified: list[tuple[bool, str]] = []
    for value in values:
        if not isinstance(value, Mapping):
            _raise_provider()
        record = cast("Mapping[str, object]", value)
        email = record.get("email")
        is_verified = record.get("verified")
        is_primary = record.get("primary")
        if not _strict_text(email):
            _raise_provider()
        verified_value = _exact_bool(is_verified)
        primary_value = _exact_bool(is_primary)
        if verified_value:
            verified.append((primary_value, cast("str", email)))
    if not verified:
        return None
    verified.sort(key=lambda candidate: not candidate[0])
    return verified[0][1]


def _github_headers() -> dict[str, str]:
    return {"Accept": _GITHUB_ACCEPT, "Accept-Encoding": "identity", "X-GitHub-Api-Version": _GITHUB_API_VERSION}


def _raise_github_response(response: httpx.Response) -> NoReturn:
    retry_after: int | None = None
    if response.status_code in {httpx.codes.FORBIDDEN, httpx.codes.TOO_MANY_REQUESTS}:
        value = response.headers.get("retry-after")
        if value is not None and value.isascii() and value.isdigit():
            parsed = int(value)
            if 1 <= parsed <= _GITHUB_MAXIMUM_RETRY_AFTER:
                retry_after = parsed
    raise OAuthProviderError(retry_after=retry_after)


def _parse_token_document(content_type: str, body: bytes) -> dict[str, object]:
    media_type = content_type.partition(";")[0].strip().lower()
    if media_type == "application/json":
        document = json.loads(body, object_pairs_hook=unique_object, parse_constant=reject_non_finite)
        validate_depth(document, maximum=_MAXIMUM_JSON_DEPTH)
        if not isinstance(document, dict):
            raise ValueError
        return cast("dict[str, object]", document)
    if media_type == "application/x-www-form-urlencoded":
        text = body.decode("utf-8")
        pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=True)
        values: dict[str, object] = {}
        for key, value in pairs:
            if key in values:
                raise ValueError
            values[key] = value
        return values
    return _raise_provider()


def _is_invalid_grant_response(content_type: str, body: bytes) -> bool:
    try:
        document = _parse_token_document(content_type, body)
    except Exception:  # noqa: BLE001 - malformed provider errors remain one sanitized failure
        return False
    return document.get("error") == "invalid_grant"


def _token_set(
    document: Mapping[str, object],
    *,
    fallback_scopes: frozenset[str],
    config: OAuthEndpointConfig,
    fallback_refresh_token: SecretStr | None = None,
    now: datetime,
) -> ProviderTokenSet:
    access_token = _required_text(document, "access_token")
    token_type = _required_text(document, "token_type")
    if token_type.lower() != _BEARER_TOKEN_TYPE.lower():
        _raise_provider()
    expires_seconds = _expires_seconds(document.get("expires_in"))
    scopes = _response_scopes(document.get("scope"), fallback=fallback_scopes)
    if not config.required_scopes.issubset(scopes) or not scopes.issubset(config.allowed_scopes):
        _raise_provider()
    refresh_token = _optional_secret(document, "refresh_token") or fallback_refresh_token
    id_token = _optional_secret(document, "id_token")
    return ProviderTokenSet(
        access_token=SecretStr(access_token),
        token_type=_BEARER_TOKEN_TYPE,
        scopes=scopes,
        expires_at=now + timedelta(seconds=expires_seconds),
        refresh_token=refresh_token,
        id_token=id_token,
    )


def _required_text(document: Mapping[str, object], key: str) -> str:
    value = document.get(key)
    if not _strict_text(value):
        _raise_provider()
    return cast("str", value)


def _optional_secret(document: Mapping[str, object], key: str) -> SecretStr | None:
    value = document.get(key)
    if value is None:
        return None
    if not _strict_text(value):
        _raise_provider()
    return SecretStr(cast("str", value))


def _expires_seconds(value: object) -> int:
    if isinstance(value, str) and value.__class__ is str and value.isascii() and value.isdigit():
        value = int(value)
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= _MAXIMUM_EXPIRES_SECONDS:
        _raise_provider()
    return value


def _response_scopes(value: object, *, fallback: frozenset[str]) -> frozenset[str]:
    if value is None:
        return fallback
    if not _strict_text(value):
        _raise_provider()
    parts = cast("str", value).split(" ")
    if any(not _valid_scope(part) for part in parts) or len(parts) != len(set(parts)):
        _raise_provider()
    return frozenset(parts)


def _response_time(value: datetime | None) -> datetime:
    now = value or datetime.now(timezone.utc)
    if not _aware_time(now):
        _raise_provider()
    return now


def _validate_endpoint(value: str) -> None:
    if value.__class__ is not str or value != value.strip() or "*" in value or "\\" in value:
        _raise_config("OAuth endpoints must be exact HTTPS URLs")
    try:
        split = urlsplit(value)
        port = split.port
    except ValueError:
        _raise_config("OAuth endpoints must be exact HTTPS URLs")
    if (
        split.scheme != "https"
        or not split.netloc
        or split.hostname is None
        or split.username is not None
        or split.password is not None
        or split.query
        or split.fragment
        or (port is not None and not 1 <= port <= _MAXIMUM_TCP_PORT)
    ):
        _raise_config("OAuth endpoints must be exact HTTPS URLs")


def _valid_scope(value: object) -> bool:
    return _strict_text(value) and all(
        _SCOPE_ASCII_MINIMUM <= ord(character) <= _SCOPE_ASCII_MAXIMUM and character not in {'"', "\\"}
        for character in cast("str", value)
    )


def _strict_text(value: object) -> bool:
    return isinstance(value, str) and value.__class__ is str and bool(value.strip())


def _aware_time(value: object) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None


def _freeze_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType({key: _freeze_value(item) for key, item in value.items()})


def _freeze_value(value: object) -> object:
    if isinstance(value, Mapping):
        mapping = cast("Mapping[object, object]", value)
        if any(not _strict_text(key) for key in mapping):
            message = "Provider identity is invalid"
            raise ValueError(message)
        return MappingProxyType({cast("str", key): _freeze_value(item) for key, item in mapping.items()})
    if isinstance(value, (list, tuple)):
        items = cast("list[object] | tuple[object, ...]", value)
        return tuple(_freeze_value(item) for item in items)
    return value


def _positive_finite(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0


def _exact_bool(value: object) -> bool:
    if not isinstance(value, bool) or value.__class__ is not bool:
        _raise_provider()
    return value


def _raise_provider() -> NoReturn:
    raise OAuthProviderError


def _raise_config(message: str) -> NoReturn:
    raise ImproperlyConfiguredException(detail=message)
