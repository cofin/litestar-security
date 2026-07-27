"""JSON Web Token signing, verification, and bearer slot composition."""

from litestar_security.providers._internal import JSONValue
from litestar_security.providers.jwt._bearer import (
    BearerSlotSelector,
    BearerTokenSlot,
    CompositeBearerConfig,
    extend_composite_bearer,
)
from litestar_security.providers.jwt._claims import JWTAlgorithm as JWTAlgorithm
from litestar_security.providers.jwt._claims import JWTClaims, JWTValidationConfig, build_access_token_claims
from litestar_security.providers.jwt._keyring import (
    LocalJWKSConfig,
    LocalKeyRing,
    VerificationKeySet,
    build_local_jwks_handler,
)
from litestar_security.providers.jwt._keys import SigningKey, VerificationKey
from litestar_security.providers.jwt._signing import SyncTokenSigner, TokenSigner, normalize_signer
from litestar_security.providers.jwt._verification import JWTVerifier, SyncJWTVerifier, normalize_verifier

# Importable from this package but deliberately absent from ``__all__``, matching the
# surface the flat module exposed: sibling providers and tests reach for these directly.
from litestar_security.providers.jwt._verification import PyJWTVerifier as PyJWTVerifier
from litestar_security.providers.jwt._verification import UnverifiedJWTRoute as UnverifiedJWTRoute
from litestar_security.providers.jwt._verification import parse_unverified_jwt_route as parse_unverified_jwt_route

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
    "build_access_token_claims",
    "build_local_jwks_handler",
    "extend_composite_bearer",
    "normalize_signer",
    "normalize_verifier",
)
