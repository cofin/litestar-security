"""Curated authentication provider contracts."""

from importlib import import_module
from typing import TYPE_CHECKING, Any

from litestar_security._lazy import import_optional_attribute
from litestar_security.providers.api_key import (
    APIKeyClaims,
    APIKeyCodec,
    APIKeyConfig,
    APIKeyGenerationError,
    APIKeyProof,
    APIKeyRecord,
    APIKeyService,
    APIKeyStore,
    APIKeyUsageSink,
    BufferedAPIKeyUsage,
    IssuedAPIKey,
)
from litestar_security.providers.iap import GoogleIAPClaims, GoogleIAPConfig
from litestar_security.providers.jwks import (
    AsyncJWKSFetcher,
    CachedJWKSProvider,
    HttpxJWKSFetcher,
    JWKSCacheEntry,
    JWKSCachePolicy,
    JWKSFetchRequest,
    JWKSFetchResponse,
    JWKSProvider,
    NoOpSecurityMetrics,
    SecurityMetrics,
    SyncJWKSFetcher,
    WorkerLimits,
    normalize_fetcher,
)
from litestar_security.providers.jwt import (
    BearerSlotSelector,
    BearerTokenSlot,
    CompositeBearerConfig,
    JSONValue,
    JWTClaims,
    JWTValidationConfig,
    JWTVerifier,
    LocalJWKSConfig,
    LocalKeyRing,
    SigningKey,
    SyncJWTVerifier,
    SyncTokenSigner,
    TokenSigner,
    VerificationKey,
    VerificationKeySet,
    VerifiedCapability,
    build_access_token_claims,
    build_local_jwks_handler,
    extend_composite_bearer,
    normalize_signer,
    normalize_verifier,
)

if TYPE_CHECKING:
    from litestar_security.providers.oauth import (
        AESGCMOAuthTransactionProtector,
        GitHubOAuthProvider,
        OAuthAccountService,
        OAuthAccountStore,
        OAuthConfig,
        OAuthProvider,
        OAuthRouteService,
        OAuthTransactionProtectorKey,
        TokenVault,
    )
    from litestar_security.providers.oidc import (
        DiscoveryPolicy,
        KeycloakClaims,
        OIDCDiscoveryClient,
        OIDCDiscoveryError,
        OIDCJWTLogoutTokenConsumer,
        OIDCMetadata,
        OIDCProvider,
        ServiceTokenConfig,
        google_oidc_provider,
        keycloak_oidc_provider,
        map_keycloak_claims,
        oidc_provider,
    )

__all__ = (
    "AESGCMOAuthTransactionProtector",
    "APIKeyClaims",
    "APIKeyCodec",
    "APIKeyConfig",
    "APIKeyGenerationError",
    "APIKeyProof",
    "APIKeyRecord",
    "APIKeyService",
    "APIKeyStore",
    "APIKeyUsageSink",
    "AsyncJWKSFetcher",
    "BearerSlotSelector",
    "BearerTokenSlot",
    "BufferedAPIKeyUsage",
    "CachedJWKSProvider",
    "CompositeBearerConfig",
    "DiscoveryPolicy",
    "GitHubOAuthProvider",
    "GoogleIAPClaims",
    "GoogleIAPConfig",
    "HttpxJWKSFetcher",
    "IssuedAPIKey",
    "JSONValue",
    "JWKSCacheEntry",
    "JWKSCachePolicy",
    "JWKSFetchRequest",
    "JWKSFetchResponse",
    "JWKSProvider",
    "JWTClaims",
    "JWTValidationConfig",
    "JWTVerifier",
    "KeycloakClaims",
    "LocalJWKSConfig",
    "LocalKeyRing",
    "NoOpSecurityMetrics",
    "OAuthAccountService",
    "OAuthAccountStore",
    "OAuthConfig",
    "OAuthProvider",
    "OAuthRouteService",
    "OAuthTransactionProtectorKey",
    "OIDCDiscoveryClient",
    "OIDCDiscoveryError",
    "OIDCJWTLogoutTokenConsumer",
    "OIDCMetadata",
    "OIDCProvider",
    "SecurityMetrics",
    "ServiceTokenConfig",
    "SigningKey",
    "SyncJWKSFetcher",
    "SyncJWTVerifier",
    "SyncTokenSigner",
    "TokenSigner",
    "TokenVault",
    "VerificationKey",
    "VerificationKeySet",
    "VerifiedCapability",
    "WorkerLimits",
    "build_access_token_claims",
    "build_local_jwks_handler",
    "extend_composite_bearer",
    "google_oidc_provider",
    "keycloak_oidc_provider",
    "map_keycloak_claims",
    "normalize_fetcher",
    "normalize_signer",
    "normalize_verifier",
    "oidc_provider",
)

_OAUTH_EXPORTS = frozenset({
    "AESGCMOAuthTransactionProtector",
    "GitHubOAuthProvider",
    "OAuthAccountService",
    "OAuthAccountStore",
    "OAuthConfig",
    "OAuthProvider",
    "OAuthRouteService",
    "OAuthTransactionProtectorKey",
    "TokenVault",
})
_OIDC_EXPORTS = frozenset({
    "DiscoveryPolicy",
    "KeycloakClaims",
    "OIDCDiscoveryClient",
    "OIDCDiscoveryError",
    "OIDCJWTLogoutTokenConsumer",
    "OIDCMetadata",
    "OIDCProvider",
    "ServiceTokenConfig",
    "google_oidc_provider",
    "keycloak_oidc_provider",
    "map_keycloak_claims",
    "oidc_provider",
})


def __getattr__(name: str) -> Any:  # noqa: ANN401 - module lazy-export hook is dynamically typed
    """Resolve OAuth exports without loading their provider tree eagerly."""
    if name in _OAUTH_EXPORTS:
        return import_optional_attribute(
            "litestar_security.providers.oauth", name, extras="oauth", dependencies=frozenset()
        )
    if name in _OIDC_EXPORTS:
        return getattr(import_module("litestar_security.providers.oidc"), name)
    message = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(message)
