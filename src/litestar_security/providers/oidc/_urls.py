"""Compatibility shim for oidc urls.

All URL definitions have been consolidated into litestar_security.providers.oidc._discovery.
"""

import sys
from types import ModuleType

from litestar_security.providers.oidc import _discovery as _canonical_module
from litestar_security.providers.oidc._discovery import NormalizedURL, normalize_url, optional_url_value

__all__ = ("NormalizedURL", "normalize_url", "optional_url_value")


class _ShimModule(ModuleType):
    """Module proxy forwarding attribute mutations to the canonical module."""

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if hasattr(_canonical_module, name):
            setattr(_canonical_module, name, value)

    def __getattr__(self, name: str) -> object:
        return getattr(_canonical_module, name)


sys.modules[__name__].__class__ = _ShimModule
