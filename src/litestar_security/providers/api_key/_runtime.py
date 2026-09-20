"""Backward-compatibility shim re-exporting API-key runtime symbols.

This module is deprecated in favor of litestar_security.providers.api_key._api_key.
"""

from __future__ import annotations

import sys
from types import ModuleType

from litestar_security.providers.api_key import _api_key
from litestar_security.providers.api_key._api_key import (
    APIKeyClaims,
    APIKeyService,
    BufferedAPIKeyUsage,
    build_api_key_runtime,
)

__all__ = ("APIKeyClaims", "APIKeyService", "BufferedAPIKeyUsage", "build_api_key_runtime")


class _APIKeyRuntimeModule(ModuleType):
    """Module proxy forwarding monkeypatched attributes to canonical _api_key.py."""

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if hasattr(_api_key, name):
            setattr(_api_key, name, value)

    def __getattr__(self, name: str) -> object:
        return getattr(_api_key, name)


sys.modules[__name__].__class__ = _APIKeyRuntimeModule
