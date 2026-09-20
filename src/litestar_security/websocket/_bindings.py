"""Compatibility shim for websocket bindings.

All binding definitions have been consolidated into litestar_security.websocket._transport.
"""

import sys
from types import ModuleType

from litestar_security.websocket import _transport as _canonical_module
from litestar_security.websocket._transport import (
    AuthorizationSnapshotRefresher,
    WebSocketBinding,
    WebSocketHandshake,
    WebSocketRevocationSource,
)

__all__ = ("AuthorizationSnapshotRefresher", "WebSocketBinding", "WebSocketHandshake", "WebSocketRevocationSource")


class _ShimModule(ModuleType):
    """Module proxy forwarding attribute mutations to the canonical module."""

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if hasattr(_canonical_module, name):
            setattr(_canonical_module, name, value)

    def __getattr__(self, name: str) -> object:
        return getattr(_canonical_module, name)


sys.modules[__name__].__class__ = _ShimModule
