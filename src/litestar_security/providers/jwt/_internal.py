"""Compatibility shim for jwt internals.

All internal definitions have been consolidated into litestar_security.providers.jwt._tokens.
"""

import sys
from types import ModuleType

from litestar_security.providers.jwt import _tokens as _canonical_module
from litestar_security.providers.jwt._tokens import (
    aware_utc,
    decode_base64url,
    decode_json_segment,
    freeze_json,
    is_scope_token,
    is_strict_identifier,
    raise_value,
    strict_identifier,
    strict_identifier_value,
)

__all__ = (
    "aware_utc",
    "decode_base64url",
    "decode_json_segment",
    "freeze_json",
    "is_scope_token",
    "is_strict_identifier",
    "raise_value",
    "strict_identifier",
    "strict_identifier_value",
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
