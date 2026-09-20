"""Backward-compatibility shim re-exporting password hashing and policy symbols.

This module is deprecated in favor of litestar_security.accounts.passwords.
"""

from __future__ import annotations

import sys
from types import ModuleType

import litestar_security.accounts.passwords as _passwords
from litestar_security.accounts.passwords import (
    Argon2PasswordHasher,
    PasswordHasher,
    PasswordHashingUnavailableError,
    PasswordPolicy,
    PasswordPolicyDecision,
    PasswordVerificationOutcome,
)

__all__ = (
    "Argon2PasswordHasher",
    "PasswordHasher",
    "PasswordHashingUnavailableError",
    "PasswordPolicy",
    "PasswordPolicyDecision",
    "PasswordVerificationOutcome",
)


class _PasswordsModule(ModuleType):
    """Module proxy forwarding monkeypatched attributes to canonical passwords.py."""

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if hasattr(_passwords, name):
            setattr(_passwords, name, value)

    def __getattr__(self, name: str) -> object:
        return getattr(_passwords, name)


sys.modules[__name__].__class__ = _PasswordsModule
