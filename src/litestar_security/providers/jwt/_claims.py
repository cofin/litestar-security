"""Compatibility shim for jwt claims.

All claim definitions have been consolidated into litestar_security.providers.jwt._tokens.
"""

import sys
from types import ModuleType

from litestar_security.providers.jwt import _tokens as _canonical_module
from litestar_security.providers.jwt._tokens import (
    JWTAlgorithm,
    JWTClaims,
    JWTValidationConfig,
    build_access_token_claims,
    normalize_audiences,
    normalize_claims,
    validate_header,
    validate_local_access_claims,
)

__all__ = (
    "JWTAlgorithm",
    "JWTClaims",
    "JWTValidationConfig",
    "build_access_token_claims",
    "normalize_audiences",
    "normalize_claims",
    "validate_header",
    "validate_local_access_claims",
)


class _ShimModule(ModuleType):
    """Module proxy forwarding attribute mutations to the canonical module."""

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if hasattr(_canonical_module, name):
            setattr(_canonical_module, name, value)

    def __getattr__(self, name: str) -> object:
        return getattr(_canonical_module, name)


sys.modules[__name__].__class__ = _ShimModule
