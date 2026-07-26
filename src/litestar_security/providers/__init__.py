"""Curated authentication provider contracts."""

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
    TokenSigner,
    VerificationKey,
    VerificationKeySet,
    build_access_token_claims,
    build_local_jwks_handler,
)

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
    "TokenSigner",
    "VerificationKey",
    "VerificationKeySet",
    "build_access_token_claims",
    "build_local_jwks_handler",
)
