"""Compatibility shim for websocket internal helpers.

All internal helper definitions have been consolidated into litestar_security.websocket._transport.
"""

import sys
from types import ModuleType

from litestar_security.websocket import _transport as _canonical_module
from litestar_security.websocket._transport import (
    DEFAULT_UNAUTHENTICATED_CLOSE,
    DEFAULT_UNAUTHORIZED_CLOSE,
    DEFAULT_UNAVAILABLE_CLOSE,
    RESERVED_QUERY_PARAMETERS,
    aware_utc,
    canonical_hostname,
    canonical_origin,
    configuration_error,
    duration,
    invalid_origin,
    normalize_allowed_origins,
    strict_text,
    transport_error,
    valid_percent_encoding,
    websocket_policy_fingerprint,
)

__all__ = (
    "DEFAULT_UNAUTHENTICATED_CLOSE",
    "DEFAULT_UNAUTHORIZED_CLOSE",
    "DEFAULT_UNAVAILABLE_CLOSE",
    "RESERVED_QUERY_PARAMETERS",
    "aware_utc",
    "canonical_hostname",
    "canonical_origin",
    "configuration_error",
    "duration",
    "invalid_origin",
    "normalize_allowed_origins",
    "strict_text",
    "transport_error",
    "valid_percent_encoding",
    "websocket_policy_fingerprint",
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
