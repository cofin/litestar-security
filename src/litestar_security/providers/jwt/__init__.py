"""JSON Web Token signing, verification, and bearer slot composition.

Note that PyJWTVerifier, UnverifiedJWTRoute, and parse_unverified_jwt_route
are importable from this package but deliberately absent from __all__,
matching the surface sibling providers and tests reach for directly.
"""

from litestar_security.providers._internal import JSONValue
from litestar_security.providers.jwt._keyring import (
    LocalJWKSConfig,
    LocalKeyRing,
    SyncTokenSigner,
    TokenSigner,
    VerificationKeySet,
    VerifiedCapability,
    build_local_jwks_handler,
    normalize_signer,
)
from litestar_security.providers.jwt._tokens import (
    BearerSlotSelector,
    BearerTokenSlot,
    CompositeBearerConfig,
    JWTClaims,
    JWTValidationConfig,
    JWTVerifier,
    SigningKey,
    SyncJWTVerifier,
    VerificationKey,
    build_access_token_claims,
    extend_composite_bearer,
    normalize_verifier,
)
from litestar_security.providers.jwt._tokens import JWTAlgorithm as JWTAlgorithm
from litestar_security.providers.jwt._tokens import PyJWTVerifier as PyJWTVerifier
from litestar_security.providers.jwt._tokens import UnverifiedJWTRoute as UnverifiedJWTRoute
from litestar_security.providers.jwt._tokens import parse_unverified_jwt_route as parse_unverified_jwt_route

__all__ = (
    "BearerSlotSelector",
    "BearerTokenSlot",
    "CompositeBearerConfig",
    "JSONValue",
    "JWTClaims",
    "JWTValidationConfig",
    "JWTVerifier",
    "LocalJWKSConfig",
    "LocalKeyRing",
    "SigningKey",
    "SyncJWTVerifier",
    "SyncTokenSigner",
    "TokenSigner",
    "VerificationKey",
    "VerificationKeySet",
    "VerifiedCapability",
    "build_access_token_claims",
    "build_local_jwks_handler",
    "extend_composite_bearer",
    "normalize_signer",
    "normalize_verifier",
)
