"""OIDC provider lifecycle layered over OAuth and a distinct JWT verifier."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from hmac import compare_digest
from typing import NoReturn, cast

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.authentication import Authenticated
from litestar_security.providers.jwt import JWTClaims, JWTVerifier
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
from litestar_security.providers.oidc._discovery import OIDCMetadata

__all__ = ("OIDCProvider", "google_oidc_provider", "keycloak_oidc_provider", "oidc_provider")


_GOOGLE_ISSUER = "https://accounts.google.com"
_DEFAULT_SCOPES = frozenset({"openid", "email", "profile"})
_ID_TOKEN_TYPES = frozenset({"jwt"})


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
