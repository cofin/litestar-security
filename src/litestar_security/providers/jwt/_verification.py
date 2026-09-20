"""Compatibility shim for jwt verification.

All verification definitions have been consolidated into litestar_security.providers.jwt._tokens.
"""

import sys
from types import ModuleType

from litestar_security.providers.jwt import _tokens as _canonical_module
from litestar_security.providers.jwt._tokens import (
    JWTVerifier,
    PyJWTVerifier,
    SyncJWTVerifier,
    UnverifiedJWTRoute,
    normalize_verifier,
    parse_unverified_jwt_route,
)

__all__ = (
    "JWTVerifier",
    "PyJWTVerifier",
    "SyncJWTVerifier",
    "UnverifiedJWTRoute",
    "normalize_verifier",
    "parse_unverified_jwt_route",
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
