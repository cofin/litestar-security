"""Curated authentication provider contracts."""

from litestar_security.providers.jwt import (
    BearerSlotSelector,
    BearerTokenSlot,
    CompositeBearerConfig,
    JSONValue,
    JWTClaims,
    JWTValidationConfig,
    JWTVerifier,
    LocalKeyRing,
    SigningKey,
    TokenSigner,
    VerificationKey,
    VerificationKeySet,
    build_access_token_claims,
)

__all__ = (
    "BearerSlotSelector",
    "BearerTokenSlot",
    "CompositeBearerConfig",
    "JSONValue",
    "JWTClaims",
    "JWTValidationConfig",
    "JWTVerifier",
    "LocalKeyRing",
    "SigningKey",
    "TokenSigner",
    "VerificationKey",
    "VerificationKeySet",
    "build_access_token_claims",
)
