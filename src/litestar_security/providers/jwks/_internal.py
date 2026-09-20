"""Compatibility shim for jwks internal helpers.

Internal helper definitions have been consolidated into litestar_security.providers.jwks._provider
and litestar_security.providers.jwks._transport.
"""

import sys
from types import ModuleType

from litestar_security.providers.jwks import _provider as _canonical_module
from litestar_security.providers.jwks._provider import aware_utc, etag, negative_cache
from litestar_security.providers.jwks._transport import empty_headers, strict_value, valid_selection_value

__all__ = ("aware_utc", "empty_headers", "etag", "negative_cache", "strict_value", "valid_selection_value")


class _ShimModule(ModuleType):
    """Module proxy forwarding attribute mutations to the canonical module."""

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if hasattr(_canonical_module, name):
            setattr(_canonical_module, name, value)

    def __getattr__(self, name: str) -> object:
        return getattr(_canonical_module, name)


sys.modules[__name__].__class__ = _ShimModule
