"""Backward-compatibility shim re-exporting registration and verification symbols.

This module is deprecated in favor of litestar_security.accounts.lifecycle.
"""

from __future__ import annotations

import sys
from types import ModuleType

import litestar_security.accounts.lifecycle as _lifecycle
from litestar_security.accounts.lifecycle import (
    RegistrationService,
    VerificationTokenService,
    validate_lifecycle_configuration,
)

__all__ = ("RegistrationService", "VerificationTokenService", "validate_lifecycle_configuration")


class _RegistrationModule(ModuleType):
    """Module proxy forwarding monkeypatched attributes to canonical lifecycle.py."""

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if hasattr(_lifecycle, name):
            setattr(_lifecycle, name, value)

    def __getattr__(self, name: str) -> object:
        return getattr(_lifecycle, name)


sys.modules[__name__].__class__ = _RegistrationModule
