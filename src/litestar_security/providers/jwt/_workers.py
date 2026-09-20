"""Compatibility shim for jwt workers.

All worker definitions have been consolidated into litestar_security.providers.jwt._tokens.
"""

import sys
from types import ModuleType

from litestar_security.providers.jwt import _tokens as _canonical_module
from litestar_security.providers.jwt._tokens import metric_sink, run_worker, validate_limiter

__all__ = ("metric_sink", "run_worker", "validate_limiter")


class _ShimModule(ModuleType):
    """Module proxy forwarding attribute mutations to the canonical module."""

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if hasattr(_canonical_module, name):
            setattr(_canonical_module, name, value)

    def __getattr__(self, name: str) -> object:
        return getattr(_canonical_module, name)


sys.modules[__name__].__class__ = _ShimModule
