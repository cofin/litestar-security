"""Compatibility shim for websocket lifecycle.

All lifecycle definitions have been consolidated into litestar_security.websocket._transport.
"""

import sys
from types import ModuleType

from litestar_security.websocket import _transport as _canonical_module
from litestar_security.websocket._transport import (
    WebSocketCloseCoordinator,
    close_websocket,
    create_websocket_binding,
    handle_websocket,
    supervise_websocket_lifetime,
    websocket_policy_fingerprint,
    websocket_route_name,
)

__all__ = (
    "WebSocketCloseCoordinator",
    "close_websocket",
    "create_websocket_binding",
    "handle_websocket",
    "supervise_websocket_lifetime",
    "websocket_policy_fingerprint",
    "websocket_route_name",
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
