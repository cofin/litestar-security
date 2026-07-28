"""Generic OAuth provider contracts and hardened async HTTP boundary."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from types import MappingProxyType
from typing import NoReturn, Protocol, cast, runtime_checkable
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx
from litestar.exceptions import ImproperlyConfiguredException
from typing_extensions import Self

from litestar_security.providers._internal import reject_non_finite, unique_object, validate_depth
from litestar_security.providers.oauth._transactions import OAuthTransaction, OAuthTransactionStart, SecretStr

__all__ = (
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
_BEARER_TOKEN_TYPE = "Bearer"  # noqa: S105 - standardized OAuth token type, not a credential
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
            or not isinstance(raw_claims, Mapping)
            or any(not _strict_text(key) for key in self.raw_claims)
        ):
            message = "Provider identity is invalid"
            raise ValueError(message)
        object.__setattr__(self, "raw_claims", MappingProxyType(dict(self.raw_claims)))


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

    async def resolve_identity(self, tokens: ProviderTokenSet) -> ProviderIdentity:
        """Resolve a verified identity from validated tokens.

        Args:
            tokens: Validated provider tokens.

        Returns:
            The verified provider identity.
        """
        ...  # pragma: no cover

    async def refresh(self, refresh_token: SecretStr, *, now: datetime | None = None) -> ProviderTokenSet:
        """Refresh provider credentials.

        Args:
            refresh_token: The protected stored refresh credential.
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

    def __init__(self, *, closed: bool = False) -> None:
        """Initialize a closed-client or generic request failure."""
        super().__init__("OAuth provider client is closed" if closed else "OAuth provider request failed")


class OAuthProviderClient:
    """Lifecycle-owned fixed-endpoint OAuth HTTP client."""

    __slots__ = ("_client", "_closed", "config", "policy")

    def __init__(
        self,
        config: OAuthEndpointConfig,
        *,
        policy: OAuthHTTPPolicy | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """Create one bounded async client.

        Args:
            config: Normalized static provider configuration.
            policy: Explicit resource limits.
            transport: Optional test or application transport.
        """
        if config.__class__ is not OAuthEndpointConfig:
            _raise_config("OAuth endpoint configuration is invalid")
        if policy is not None and policy.__class__ is not OAuthHTTPPolicy:
            _raise_config("OAuth HTTP policy is invalid")
        self.config = config
        self.policy = policy or OAuthHTTPPolicy()
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

    async def refresh(self, refresh_token: SecretStr, *, now: datetime | None = None) -> ProviderTokenSet:
        """Refresh provider credentials through the fixed token endpoint.

        Args:
            refresh_token: The protected stored refresh credential.
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
            fallback_scopes=frozenset(),
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
            async with self._client.stream(
                "POST",
                self.config.revocation_endpoint,
                data=request_data,
                auth=auth,
                headers={"Accept": "application/json", "Accept-Encoding": "identity"},
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
        self, data: dict[str, str], *, fallback_scopes: frozenset[str], now: datetime
    ) -> ProviderTokenSet:
        auth, request_data = self._client_auth(data)
        try:
            async with self._client.stream(
                "POST",
                self.config.token_endpoint,
                data=request_data,
                auth=auth,
                headers={
                    "Accept": "application/json, application/x-www-form-urlencoded",
                    "Accept-Encoding": "identity",
                },
            ) as response:
                if response.status_code != _HTTP_OK:
                    _raise_provider()
                body = await _read_bounded(response, self.policy.maximum_response_bytes)
                document = _parse_token_document(response.headers.get("content-type", ""), body)
            return _token_set(
                document,
                fallback_scopes=fallback_scopes,
                required_scopes=self.config.required_scopes,
                allowed_scopes=self.config.allowed_scopes,
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

    def _require_open(self) -> None:
        if self._closed:
            raise OAuthProviderError(closed=True)


async def _read_bounded(response: httpx.Response, maximum: int) -> bytes:
    content_length = response.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > maximum:
                _raise_provider()
        except ValueError:
            raise OAuthProviderError from None
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > maximum:
            _raise_provider()
    return bytes(body)


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


def _token_set(
    document: Mapping[str, object],
    *,
    fallback_scopes: frozenset[str],
    required_scopes: frozenset[str],
    allowed_scopes: frozenset[str],
    now: datetime,
) -> ProviderTokenSet:
    access_token = _required_text(document, "access_token")
    token_type = _required_text(document, "token_type")
    if token_type.lower() != _BEARER_TOKEN_TYPE.lower():
        _raise_provider()
    expires_seconds = _expires_seconds(document.get("expires_in"))
    scopes = _response_scopes(document.get("scope"), fallback=fallback_scopes)
    if not required_scopes.issubset(scopes) or not scopes.issubset(allowed_scopes):
        _raise_provider()
    refresh_token = _optional_secret(document, "refresh_token")
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


def _positive_finite(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0


def _raise_provider() -> NoReturn:
    raise OAuthProviderError


def _raise_config(message: str) -> NoReturn:
    raise ImproperlyConfiguredException(detail=message)
