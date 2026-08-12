"""Deterministic local-only support objects for the runnable examples."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from litestar.datastructures import Cookie
from litestar.middleware.session.client_side import CookieBackendConfig

from litestar_security.accounts import (
    LocalAuth,
    LocalAuthConfig,
    LocalAuthSecrets,
    PasswordVerificationOutcome,
    PasswordVerificationStatus,
    PurposeTokenCodec,
    RefreshReceiptKey,
    RefreshReceiptSealer,
    RefreshTokenCodec,
    RegistrationPolicy,
    SessionBindingConfig,
)
from litestar_security.context import AuthorizationSnapshot, Principal
from litestar_security.providers.api_key import APIKeyClaims, APIKeyConfig
from litestar_security.providers.iap import GoogleIAPClaims, GoogleIAPConfig
from litestar_security.providers.jwt import LocalKeyRing, SigningKey
from litestar_security.providers.oauth import (
    OAuthAuthorization,
    OAuthCallbackOutcome,
    OAuthConfig,
    OAuthLogout,
    OAuthOperation,
    OAuthOperationSummary,
)
from litestar_security.providers.oidc import ServiceTokenConfig
from litestar_security.testing import InMemoryLocalAccountStore, InMemorySecurityBackend
from litestar_security.websocket import WebSocketSecurityConfig

if TYPE_CHECKING:
    from litestar.connection import Request

    from litestar_security.authentication import InvalidCredentials
    from litestar_security.providers.jwks import JWKSProvider

__all__ = (
    "build_api_team_config",
    "build_iap_config",
    "build_local_auth",
    "build_oauth_config",
    "build_websocket_config",
    "example_account_store",
    "example_session_config",
)

_PURPOSE_PEPPER = b"p" * 32
_REFRESH_PEPPER = b"r" * 32
_RECEIPT_KEY = b"k" * 32
_BINDING_PEPPER = b"b" * 32
_IAP_AUDIENCE = "/projects/123/global/backendServices/456"


class _UnavailableJWKS:
    async def select_key(
        self, issuer: str, jwks_uri: str, kid: str, algorithm: str, *, now: datetime
    ) -> InvalidCredentials:
        del issuer, jwks_uri, kid, algorithm, now
        from litestar_security.authentication import InvalidCredentials  # noqa: PLC0415 - type used on request only

        return InvalidCredentials()

    async def warmup(self, *, now: datetime) -> None:
        del now

    async def aclose(self) -> None:
        return None


class _ExampleIdentityResolver:
    async def resolve(self, claims: APIKeyClaims | GoogleIAPClaims) -> Principal[object]:
        subject = getattr(claims, "subject_id", None) or getattr(claims, "subject", None)
        return Principal(id=cast("str", subject), user=object())


class _ExampleOAuthService:
    def __init__(self, provider_name: str) -> None:
        self.provider_names = frozenset({provider_name})

    async def begin(  # noqa: PLR0913 - mirrors the public OAuth service boundary
        self,
        *,
        provider: str,
        operation: OAuthOperation,
        account_id: str | None,
        provider_account_id: str | None,
        return_to: str,
        scopes: frozenset[str] | None,
        step_up_grant: str | None,
        request: Request[Any, Any, Any],
    ) -> OAuthAuthorization:
        del operation, account_id, provider_account_id, return_to, scopes, step_up_grant, request
        return OAuthAuthorization(
            url=f"https://provider.example/authorize?provider={provider}&code_challenge=example",
            binding_cookie=Cookie(
                key="__Host-litestar-security-oauth",
                value="example-binding",
                path="/",
                secure=True,
                httponly=True,
                samesite="lax",
            ),
        )

    async def complete_callback(
        self, *, provider: str, code: str, state: str, request: Request[Any, Any, Any]
    ) -> OAuthCallbackOutcome:
        del code, state, request
        return cast("OAuthCallbackOutcome", SimpleNamespace(operation=OAuthOperation.LOGIN, provider=provider))

    async def establish_login(self, outcome: object, *, request: Request[Any, Any, Any]) -> OAuthOperationSummary:
        del request
        return OAuthOperationSummary(
            detail="Authenticated.", provider_account_id=f"{cast('Any', outcome).provider}-account"
        )

    async def unlink(self, **_kwargs: object) -> OAuthOperationSummary:
        return OAuthOperationSummary(detail="Unlinked.")

    async def revoke(self, **_kwargs: object) -> OAuthOperationSummary:
        return OAuthOperationSummary(detail="Revoked.")

    async def logout(self, **_kwargs: object) -> OAuthLogout:
        return OAuthLogout()


def build_iap_config() -> GoogleIAPConfig[object]:
    """Build the deterministic exact-audience IAP trust boundary."""
    return GoogleIAPConfig(
        audience=_IAP_AUDIENCE,
        identity_resolver=_ExampleIdentityResolver(),
        jwks=cast("JWKSProvider", _UnavailableJWKS()),
    )


def build_oauth_config(mode: str) -> OAuthConfig:
    """Build local-stub OAuth/OIDC routes for one provider mode."""
    provider_name = {"google-oauth": "google", "github-oauth": "github", "keycloak": "keycloak"}.get(mode)
    if provider_name is None:
        message = f"Unsupported OAuth example mode: {mode}"
        raise ValueError(message)
    return OAuthConfig(oauth_service=_ExampleOAuthService(provider_name))


def build_api_team_config() -> tuple[APIKeyConfig, ServiceTokenConfig]:
    """Build API-key and userless workload-JWT boundaries for the API example."""
    backend = InMemorySecurityBackend()
    jwks = cast("JWKSProvider", _UnavailableJWKS())
    return (
        APIKeyConfig(store=backend.api_keys, pepper=b"a" * 32, identity_resolver=_ExampleIdentityResolver()),
        ServiceTokenConfig(
            issuer="https://workload.example",
            audiences=frozenset({"team-api"}),
            allowed_algorithms=frozenset({"ES256"}),
            jwks=jwks,
            jwks_uri="https://workload.example/jwks",
        ),
    )


class _ExampleSnapshotRefresher:
    async def refresh(
        self, *, principal: Principal[object], previous: AuthorizationSnapshot, route_name: str
    ) -> AuthorizationSnapshot:
        del principal, route_name
        return previous


def build_websocket_config() -> WebSocketSecurityConfig:
    """Build exact-origin WebSocket policy with bounded snapshot refresh."""
    return WebSocketSecurityConfig(
        allowed_origins=frozenset({"http://testserver.local"}),
        refresh_interval=timedelta(seconds=30),
        snapshot_refresher=_ExampleSnapshotRefresher(),
    )


@dataclass(frozen=True, slots=True)
class _ExamplePasswordHasher:
    async def hash(self, password: str) -> str:
        return f"example-hash:{password}"

    async def verify(self, encoded_hash: str | None, password: str) -> PasswordVerificationOutcome:
        return PasswordVerificationOutcome(
            PasswordVerificationStatus.VERIFIED
            if encoded_hash == f"example-hash:{password}"
            else PasswordVerificationStatus.INVALID
        )


def example_account_store() -> InMemoryLocalAccountStore:
    """Return an application-owned in-memory store.

    Returns:
        An isolated application-owned in-memory account store.
    """
    return InMemorySecurityBackend().accounts


def example_session_config() -> CookieBackendConfig:
    """Build the explicit insecure-loopback session configuration.

    Returns:
        A native Litestar client-side session configuration.
    """
    return CookieBackendConfig(secret=bytes(range(16)), key="example-session", max_age=600, secure=False, httponly=True)


def build_local_auth(mode: str) -> LocalAuthConfig[object]:
    """Build one explicit local-auth transport profile.

    Args:
        mode: ``local-session``, ``local-token``, or ``local-hybrid``.

    Returns:
        The selected local-auth profile.

    Raises:
        ValueError: If ``mode`` is not a local-auth example mode.
    """
    accounts = example_account_store()
    registration = RegistrationPolicy.public(require_verification=False)
    shared: dict[str, object] = {"accounts": accounts, "registration": registration, "route_prefix": "/auth"}
    if mode == "local-session":
        return LocalAuth.session(
            **cast("Any", shared),
            secrets=LocalAuthSecrets.session(purpose_token_pepper=_PURPOSE_PEPPER),
            password_hasher=_ExamplePasswordHasher(),
            binding=SessionBindingConfig(
                pepper=_BINDING_PEPPER, cookie_name="example-binding", secure=False, allow_insecure=True, max_age=600
            ),
        )
    if mode in {"local-token", "local-hybrid"}:
        private_key = Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        secrets = LocalAuthSecrets(
            purpose_tokens=PurposeTokenCodec(pepper=_PURPOSE_PEPPER),
            refresh_codec=RefreshTokenCodec(pepper=_REFRESH_PEPPER),
            refresh_receipts=RefreshReceiptSealer(active_key=RefreshReceiptKey(key_id="example", key=_RECEIPT_KEY)),
        )
        key_ring = LocalKeyRing(
            issuer="http://127.0.0.1:8000",
            active_signing_key=SigningKey(key_id="example", algorithm="EdDSA", private_key=private_key),
        )
        if mode == "local-token":
            return LocalAuth.tokens(
                **cast("Any", shared),
                secrets=secrets,
                key_ring=key_ring,
                token_audience="litestar-security-example",  # noqa: S106 - public JWT audience identifier
                password_hasher=_ExamplePasswordHasher(),
            )
        return LocalAuth.hybrid(
            **cast("Any", shared),
            secrets=secrets,
            binding=SessionBindingConfig(
                pepper=_BINDING_PEPPER, cookie_name="example-binding", secure=False, allow_insecure=True, max_age=600
            ),
            key_ring=key_ring,
            token_audience="litestar-security-example",  # noqa: S106 - public JWT audience identifier
            password_hasher=_ExamplePasswordHasher(),
        )
    message = f"Unsupported local example mode: {mode}"
    raise ValueError(message)
