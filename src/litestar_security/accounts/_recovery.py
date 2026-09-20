"""Backward-compatibility shim re-exporting password recovery and change symbols.

This module is deprecated in favor of litestar_security.accounts.lifecycle.
"""

import sys
from types import ModuleType

import litestar_security.accounts.lifecycle as _lifecycle
from litestar_security.accounts.lifecycle import (
    PasswordChangeService,
    RecoveryTokenService,
    validate_lifecycle_configuration,
)

__all__ = ("PasswordChangeService", "RecoveryTokenService", "validate_lifecycle_configuration")


class _RecoveryModule(ModuleType):
    """Module proxy forwarding monkeypatched attributes to canonical lifecycle.py."""

    def __setattr__(self, name: "str", value: "object") -> "None":
        super().__setattr__(name, value)
        if hasattr(_lifecycle, name):
            setattr(_lifecycle, name, value)

    def __getattr__(self, name: "str") -> "object":
        return getattr(_lifecycle, name)


sys.modules[__name__].__class__ = _RecoveryModule
