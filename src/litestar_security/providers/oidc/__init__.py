"""OpenID Connect discovery with pinned, validated issuer metadata."""

from litestar_security.providers.oidc._discovery import DiscoveryPolicy, OIDCDiscoveryClient, OIDCMetadata
from litestar_security.providers.oidc._internal import OIDCDiscoveryError
from litestar_security.providers.oidc._keycloak import KeycloakClaims, map_keycloak_claims
from litestar_security.providers.oidc._logout import OIDCJWTLogoutTokenConsumer
from litestar_security.providers.oidc._provider import (
    OIDCProvider,
    google_oidc_provider,
    keycloak_oidc_provider,
    oidc_provider,
)
from litestar_security.providers.oidc._service import ServiceTokenConfig

__all__ = (
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
)
