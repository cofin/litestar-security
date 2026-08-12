"""OIDC provider lifecycle layered over OAuth and a distinct JWT verifier."""

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from hashlib import sha256
from hmac import compare_digest
from typing import NoReturn, cast

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.authentication import (
    Authenticated,
    AuthenticationOutcome,
    InvalidCredentials,
    VerificationUnavailable,
)
from litestar_security.config import WorkerLimits
from litestar_security.providers._internal import DynamicVerifierCache
from litestar_security.providers.jwks import JWKSProvider
from litestar_security.providers.jwt import (
    JWTClaims,
    JWTValidationConfig,
    JWTVerifier,
    PyJWTVerifier,
    VerificationKey,
    parse_unverified_jwt_route,
)
from litestar_security.providers.oauth import (
    OAuthClientAuth,
    OAuthEndpointConfig,
    OAuthHTTPPolicy,
    OAuthProviderClient,
    OAuthProviderError,
    OAuthTransaction,
    OAuthTransactionStart,
    ProviderIdentity,
    ProviderTokenSet,
    SecretStr,
)
from litestar_security.providers.oidc._discovery import OIDCDiscoveryClient, OIDCMetadata

__all__ = (
    "OIDCProvider",
    "discover_google_oidc_provider",
    "discover_oidc_provider",
    "google_oidc_provider",
    "keycloak_oidc_provider",
    "oidc_provider",
)


_GOOGLE_ISSUER = "https://accounts.google.com"
_DEFAULT_SCOPES = frozenset({"openid", "email", "profile"})
_ID_TOKEN_TYPES = frozenset({"jwt"})
_MAXIMUM_REAUTHENTICATION_AGE = 600
_MAXIMUM_TIMESTAMP = 253_402_300_799
_MAXIMUM_TOKEN_BYTES = 16_384


@dataclass(frozen=True, slots=True)
class OIDCProvider:
    """OIDC code-flow provider with an independently configured ID-token verifier."""

    oauth: OAuthProviderClient
    metadata: OIDCMetadata
    verifier: JWTVerifier[JWTClaims]
    retain_tokens_by_default: bool = True

    def __post_init__(self) -> None:
        """Pin discovery, OAuth endpoints, and JWT trust to one issuer/client."""
        verifier_value = cast("object", self.verifier)
        if not isinstance(verifier_value, JWTVerifier):
            _raise_config("OIDC provider requires a JWT verifier")
        config = verifier_value.config
        if (
            self.oauth.__class__ is not OAuthProviderClient
            or self.metadata.__class__ is not OIDCMetadata
            or self.metadata.authorization_endpoint is None
            or self.metadata.token_endpoint is None
            or self.oauth.config.authorization_endpoint != self.metadata.authorization_endpoint
            or self.oauth.config.token_endpoint != self.metadata.token_endpoint
            or config.issuer != self.metadata.issuer
            or config.audiences != frozenset({self.oauth.config.client_id})
            or config.access_token_profile
            or config.token_types != _ID_TOKEN_TYPES
            or not config.algorithms
            or not config.algorithms.issubset(self.metadata.algorithms)
            or "openid" not in self.oauth.config.required_scopes
            or self.retain_tokens_by_default.__class__ is not bool
        ):
            _raise_config("OIDC provider trust configuration is inconsistent")

    @property
    def name(self) -> str:
        """Return the configured provider name."""
        return self.oauth.name

    @property
    def issuer(self) -> str:
        """Return the exact discovered issuer."""
        return self.metadata.issuer

    @property
    def end_session_endpoint(self) -> str | None:
        """Return the validated provider logout endpoint when advertised."""
        return self.metadata.end_session_endpoint

    def build_authorization_url(self, start: OAuthTransactionStart) -> str:
        """Build the OAuth authorization URL.

        Args:
            start: The bound transaction start values.

        Returns:
            The fixed provider authorization URL.
        """
        return self.oauth.build_authorization_url(start)

    def build_reauthentication_url(self, start: OAuthTransactionStart, *, max_age: int) -> str:
        """Build a forced-authentication request using OIDC ``max_age``.

        Args:
            start: The bound authorization transaction.
            max_age: Maximum accepted signed authentication age, including zero.

        Returns:
            The authorization URL with the reserved ``max_age`` parameter.

        Raises:
            OAuthProviderError: If the age is invalid or provider state is inconsistent.
        """
        if max_age.__class__ is not int or not 0 <= max_age <= _MAXIMUM_REAUTHENTICATION_AGE:
            _raise_provider()
        return f"{self.oauth.build_authorization_url(start)}&max_age={max_age}"

    async def exchange_code(
        self, *, code: SecretStr, transaction: OAuthTransaction, now: datetime | None = None
    ) -> ProviderTokenSet:
        """Exchange a code through the composed OAuth client.

        Args:
            code: The provider authorization code.
            transaction: The consumed transaction.
            now: The authoritative response time.

        Returns:
            The validated provider token set.
        """
        return await self.oauth.exchange_code(code=code, transaction=transaction, now=now)

    async def resolve_identity(
        self, tokens: ProviderTokenSet, *, transaction: OAuthTransaction, now: datetime | None = None
    ) -> ProviderIdentity:
        """Verify the ID token and bind its claims to the consumed transaction.

        Args:
            tokens: The provider token response containing an ID token.
            transaction: The consumed transaction containing issuer and nonce bindings.
            now: The authoritative verification time.

        Returns:
            An immutable normalized provider identity.

        Raises:
            OAuthProviderError: If verification or any OIDC binding fails.
        """
        if (
            tokens.__class__ is not ProviderTokenSet
            or tokens.id_token is None
            or transaction.__class__ is not OAuthTransaction
            or transaction.provider != self.name
            or transaction.expected_issuer != self.issuer
            or transaction.nonce is None
        ):
            _raise_provider()
        verification_time = _verification_time(now)
        outcome = await self.verifier.verify(tokens.id_token.get_secret_value(), now=verification_time)
        if not isinstance(outcome, Authenticated):
            _raise_provider()
        claims = outcome.claims
        raw = cast("Mapping[str, object]", claims.raw)
        if (
            claims.issuer != self.issuer
            or claims.subject is None
            or self.oauth.config.client_id not in claims.audiences
        ):
            _raise_provider()
        _validate_authorized_party(raw.get("azp"), audiences=claims.audiences, client_id=self.oauth.config.client_id)
        _validate_nonce(raw.get("nonce"), transaction.nonce)
        display_name = _optional_text(raw.get("name"))
        if display_name is None:
            display_name = _optional_text(raw.get("preferred_username"))
        email = _optional_text(raw.get("email"))
        email_verified = _boolean(raw.get("email_verified", False))
        if email_verified and email is None:
            _raise_provider()
        acr = _optional_text(raw.get("acr"))
        amr = _authentication_methods(raw.get("amr"))
        authenticated_at = _authentication_time(raw.get("auth_time"))
        return ProviderIdentity(
            provider=self.name,
            issuer=claims.issuer,
            subject=claims.subject,
            display_name=display_name,
            email=email,
            email_verified=email_verified,
            raw_claims=raw,
            acr=acr,
            amr=amr,
            authenticated_at=authenticated_at,
        )

    async def refresh(
        self, refresh_token: SecretStr, *, current_scopes: frozenset[str] | None = None, now: datetime | None = None
    ) -> ProviderTokenSet:
        """Refresh provider credentials.

        Args:
            refresh_token: The protected refresh credential.
            current_scopes: Existing granted scopes when the provider omits them.
            now: The authoritative response time.

        Returns:
            The rotated token set.
        """
        return await self.oauth.refresh(refresh_token, current_scopes=current_scopes, now=now)

    async def revoke(self, token: SecretStr, *, token_type_hint: str | None) -> None:
        """Revoke a provider credential.

        Args:
            token: The credential to revoke.
            token_type_hint: Its optional standardized kind.
        """
        await self.oauth.revoke(token, token_type_hint=token_type_hint)

    async def aclose(self) -> None:
        """Close the owned OAuth transport."""
        await self.oauth.aclose()


@dataclass(frozen=True, slots=True)
class _DiscoveredOIDCVerifier:
    config: JWTValidationConfig
    jwks: JWKSProvider
    jwks_uri: str
    worker_limits: WorkerLimits = field(repr=False, compare=False)
    _verifiers: DynamicVerifierCache[PyJWTVerifier] = field(
        default_factory=DynamicVerifierCache[PyJWTVerifier], init=False, repr=False, compare=False
    )

    async def verify(self, token: str, *, now: datetime) -> AuthenticationOutcome[JWTClaims]:
        route = parse_unverified_jwt_route(token, maximum_token_bytes=_MAXIMUM_TOKEN_BYTES)
        if isinstance(route, InvalidCredentials):
            return route
        algorithm = route.header.get("alg")
        key_id = route.header.get("kid")
        if not isinstance(algorithm, str) or algorithm not in self.config.algorithms:
            return InvalidCredentials()
        if not isinstance(key_id, str) or not key_id:
            return InvalidCredentials()
        selection = cast(
            "object", await self.jwks.select_key(self.config.issuer, self.jwks_uri, key_id, algorithm, now=now)
        )
        if isinstance(selection, (InvalidCredentials, VerificationUnavailable)):
            return selection
        if not isinstance(selection, VerificationKey):
            return VerificationUnavailable()
        verifier = self._verifiers.get_or_create(
            (key_id, algorithm),
            selection.key,
            lambda: PyJWTVerifier(
                config=replace(self.config, algorithms=frozenset({algorithm})),
                key=selection.key,
                mechanism_name="oidc",
                slot_name="oauth.id-token",
                maximum_token_bytes=_MAXIMUM_TOKEN_BYTES,
                limiter=self.worker_limits.crypto_limiter,
                worker_timeout=self.worker_limits.timeout,
            ),
        )
        return await verifier.verify(token, now=now)


async def discover_oidc_provider(  # noqa: PLR0913 - discovery trust inputs remain explicit
    *,
    name: str,
    issuer: str,
    client_id: str,
    client_secret: SecretStr | None,
    discovery: OIDCDiscoveryClient,
    jwks: JWKSProvider,
    scopes: frozenset[str] = _DEFAULT_SCOPES,
    client_auth: OAuthClientAuth = OAuthClientAuth.CLIENT_SECRET_BASIC,
    worker_limits: WorkerLimits | None = None,
    http_policy: OAuthHTTPPolicy | None = None,
) -> OIDCProvider:
    """Discover and construct OIDC over application-owned shared resources.

    Args:
        name: Stable local provider name.
        issuer: Exact issuer allowed by the discovery client.
        client_id: Registered OIDC client identifier.
        client_secret: Protected client secret when required.
        discovery: Shared application-owned discovery client.
        jwks: Shared application-owned JWKS provider.
        scopes: Allowlisted provider scopes.
        client_auth: Token endpoint client authentication method.
        worker_limits: Shared bounded crypto-worker budget.
        http_policy: Bounded OAuth transport policy.

    Returns:
        A discovered provider whose OAuth client is owned by the result.

    Raises:
        ImproperlyConfiguredException: If shared resources or trust inputs are invalid.
        OIDCDiscoveryError: If discovery fails.
    """
    if not isinstance(cast("object", discovery), OIDCDiscoveryClient) or not isinstance(
        cast("object", jwks), JWKSProvider
    ):
        _raise_config("OIDC discovery factory requires shared discovery and JWKS resources")
    metadata = await discovery.discover(issuer)
    workers = WorkerLimits() if worker_limits is None else worker_limits
    config = JWTValidationConfig(
        issuer=metadata.issuer,
        audiences=frozenset({client_id}),
        algorithms=metadata.algorithms,
        required_claims=frozenset({"iss", "sub", "aud", "exp", "iat"}),
        access_token_profile=False,
        token_types=_ID_TOKEN_TYPES,
    )
    verifier = _DiscoveredOIDCVerifier(config=config, jwks=jwks, jwks_uri=metadata.jwks_uri, worker_limits=workers)
    return oidc_provider(
        name=name,
        client_id=client_id,
        client_secret=client_secret,
        metadata=metadata,
        verifier=verifier,
        scopes=scopes,
        client_auth=client_auth,
        http_policy=http_policy,
    )


async def discover_google_oidc_provider(  # noqa: PLR0913 - discovery trust inputs remain explicit
    *,
    client_id: str,
    client_secret: SecretStr,
    discovery: OIDCDiscoveryClient,
    jwks: JWKSProvider,
    scopes: frozenset[str] = _DEFAULT_SCOPES,
    offline_access: bool = False,
    worker_limits: WorkerLimits | None = None,
    http_policy: OAuthHTTPPolicy | None = None,
) -> OIDCProvider:
    """Discover Google's exact issuer using caller-owned shared resources."""
    if not isinstance(cast("object", discovery), OIDCDiscoveryClient) or not isinstance(
        cast("object", jwks), JWKSProvider
    ):
        _raise_config("OIDC discovery factory requires shared discovery and JWKS resources")
    metadata = await discovery.discover(_GOOGLE_ISSUER)
    workers = WorkerLimits() if worker_limits is None else worker_limits
    verifier = _DiscoveredOIDCVerifier(
        config=JWTValidationConfig(
            issuer=metadata.issuer,
            audiences=frozenset({client_id}),
            algorithms=metadata.algorithms,
            required_claims=frozenset({"iss", "sub", "aud", "exp", "iat"}),
            access_token_profile=False,
            token_types=_ID_TOKEN_TYPES,
        ),
        jwks=jwks,
        jwks_uri=metadata.jwks_uri,
        worker_limits=workers,
    )
    return google_oidc_provider(
        client_id=client_id,
        client_secret=client_secret,
        metadata=metadata,
        verifier=verifier,
        scopes=scopes,
        offline_access=offline_access,
        http_policy=http_policy,
    )


def oidc_provider(  # noqa: PLR0913 - constructor keeps every trust and transport input explicit
    *,
    name: str,
    client_id: str,
    client_secret: SecretStr | None,
    metadata: OIDCMetadata,
    verifier: JWTVerifier[JWTClaims],
    scopes: frozenset[str] = _DEFAULT_SCOPES,
    client_auth: OAuthClientAuth = OAuthClientAuth.CLIENT_SECRET_BASIC,
    revocation_endpoint: str | None = None,
    extra_authorization_parameters: Mapping[str, str] | None = None,
    http_policy: OAuthHTTPPolicy | None = None,
) -> OIDCProvider:
    """Construct a generic OIDC provider from validated discovery metadata.

    Args:
        name: Stable local provider name.
        client_id: Registered OIDC client identifier.
        client_secret: Protected client secret, if required.
        metadata: Validated discovery result.
        verifier: Distinct verifier pinned to the issuer and client.
        scopes: Allowed request scopes; ``openid`` is always required.
        client_auth: Token-endpoint client authentication method.
        revocation_endpoint: Optional fixed revocation endpoint.
        extra_authorization_parameters: Optional fixed authorization parameters.
        http_policy: Bounded OAuth transport policy.

    Returns:
        A configured OIDC lifecycle provider.

    Raises:
        ImproperlyConfiguredException: If required discovery endpoints are absent.
    """
    if metadata.authorization_endpoint is None or metadata.token_endpoint is None:
        _raise_config("OIDC provider requires authorization and token endpoints")
    allowed_scopes = frozenset(scopes)
    if "openid" not in allowed_scopes:
        _raise_config("OIDC provider requires the openid scope")
    oauth = OAuthProviderClient(
        OAuthEndpointConfig(
            name=name,
            client_id=client_id,
            client_secret=client_secret,
            client_auth=client_auth,
            authorization_endpoint=metadata.authorization_endpoint,
            token_endpoint=metadata.token_endpoint,
            revocation_endpoint=revocation_endpoint,
            allowed_scopes=allowed_scopes,
            required_scopes=frozenset({"openid"}),
            extra_authorization_parameters=extra_authorization_parameters or {},
        ),
        policy=http_policy,
    )
    return OIDCProvider(oauth=oauth, metadata=metadata, verifier=verifier)


def google_oidc_provider(  # noqa: PLR0913 - constructor keeps the provider trust inputs explicit
    *,
    client_id: str,
    client_secret: SecretStr,
    metadata: OIDCMetadata,
    verifier: JWTVerifier[JWTClaims],
    scopes: frozenset[str] = _DEFAULT_SCOPES,
    offline_access: bool = False,
    http_policy: OAuthHTTPPolicy | None = None,
) -> OIDCProvider:
    """Construct Google's pinned OIDC profile.

    Args:
        client_id: Registered Google client identifier.
        client_secret: Protected Google client secret.
        metadata: Validated Google discovery result.
        verifier: ID-token verifier pinned to Google and the client.
        scopes: Allowed Google scopes.
        offline_access: Request refresh access while the user is absent.
        http_policy: Bounded OAuth transport policy.

    Returns:
        The Google OIDC provider.

    Raises:
        ImproperlyConfiguredException: If discovery does not name Google's exact issuer.
    """
    if metadata.issuer != _GOOGLE_ISSUER:
        _raise_config("Google OIDC issuer is invalid")
    configured = oidc_provider(
        name="google",
        client_id=client_id,
        client_secret=client_secret,
        metadata=metadata,
        verifier=verifier,
        scopes=scopes,
        revocation_endpoint=metadata.revocation_endpoint,
        extra_authorization_parameters={"access_type": "offline"} if offline_access else None,
        http_policy=http_policy,
    )
    return OIDCProvider(
        oauth=configured.oauth,
        metadata=configured.metadata,
        verifier=configured.verifier,
        retain_tokens_by_default=offline_access,
    )


def keycloak_oidc_provider(  # noqa: PLR0913 - constructor keeps realm trust and client inputs explicit
    *,
    base_url: str,
    realm: str,
    client_id: str,
    client_secret: SecretStr | None,
    metadata: OIDCMetadata,
    verifier: JWTVerifier[JWTClaims],
    scopes: frozenset[str] = _DEFAULT_SCOPES,
    client_auth: OAuthClientAuth = OAuthClientAuth.CLIENT_SECRET_BASIC,
    http_policy: OAuthHTTPPolicy | None = None,
) -> OIDCProvider:
    """Construct a Keycloak provider pinned to one exact realm issuer.

    Args:
        base_url: Exact HTTPS Keycloak base URL.
        realm: Exact realm path segment.
        client_id: Registered Keycloak client identifier.
        client_secret: Protected client secret, if required.
        metadata: Validated realm discovery result.
        verifier: ID-token verifier pinned to the realm and client.
        scopes: Allowed Keycloak scopes.
        client_auth: Token-endpoint client authentication method.
        http_policy: Bounded OAuth transport policy.

    Returns:
        The realm-pinned Keycloak OIDC provider.

    Raises:
        ImproperlyConfiguredException: If the realm issuer is not exact.
    """
    if (
        not _strict_text(base_url)
        or base_url.endswith("/")
        or not _strict_text(realm)
        or "/" in realm
        or metadata.issuer != f"{base_url}/realms/{realm}"
    ):
        _raise_config("Keycloak OIDC realm issuer is invalid")
    return oidc_provider(
        name="keycloak",
        client_id=client_id,
        client_secret=client_secret,
        metadata=metadata,
        verifier=verifier,
        scopes=scopes,
        client_auth=client_auth,
        http_policy=http_policy,
    )


def _validate_authorized_party(value: object, *, audiences: frozenset[str], client_id: str) -> None:
    if (len(audiences) > 1 and value != client_id) or (value is not None and value != client_id):
        _raise_provider()


def _validate_nonce(value: object, expected: SecretStr) -> None:
    if not _strict_text(value):
        _raise_provider()
    actual_digest = sha256(cast("str", value).encode()).digest()
    expected_digest = sha256(expected.get_secret_value().encode()).digest()
    if not compare_digest(actual_digest, expected_digest):
        _raise_provider()


def _authentication_methods(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    methods = cast("list[object] | tuple[object, ...]", value)
    if (
        not isinstance(value, (list, tuple))
        or any(not _strict_text(method) for method in methods)
        or len(methods) != len(set(cast("list[str] | tuple[str, ...]", methods)))
    ):
        _raise_provider()
    return tuple(cast("list[str] | tuple[str, ...]", methods))


def _authentication_time(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        _raise_provider()
    timestamp = value
    if not 0 <= timestamp <= _MAXIMUM_TIMESTAMP:
        _raise_provider()
    try:
        return datetime.fromtimestamp(timestamp, timezone.utc)
    except (OverflowError, OSError, ValueError):
        _raise_provider()


def _boolean(value: object) -> bool:
    if not isinstance(value, bool) or value.__class__ is not bool:
        _raise_provider()
    return value


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    if not _strict_text(value):
        _raise_provider()
    return cast("str", value)


def _verification_time(value: datetime | None) -> datetime:
    now = value or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        _raise_provider()
    return now.astimezone(timezone.utc)


def _strict_text(value: object) -> bool:
    return isinstance(value, str) and value.__class__ is str and bool(value.strip()) and value == value.strip()


def _raise_provider() -> NoReturn:
    raise OAuthProviderError


def _raise_config(message: str) -> NoReturn:
    raise ImproperlyConfiguredException(detail=message)
