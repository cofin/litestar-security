"""Compatibility shim for jwt capabilities.

All capability definitions have been consolidated into litestar_security.providers.jwt._keyring.
"""

import sys
from types import ModuleType

from litestar_security.providers.jwt import _keyring as _canonical_module
from litestar_security.providers.jwt._keyring import (
    CAPABILITY_TOKEN_TYPE,
    VerifiedCapability,
    build_capability_claims,
    normalize_capability_claims,
    validate_capability_header,
)

__all__ = (
    "CAPABILITY_TOKEN_TYPE",
    "VerifiedCapability",
    "build_capability_claims",
    "normalize_capability_claims",
    "validate_capability_header",
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
