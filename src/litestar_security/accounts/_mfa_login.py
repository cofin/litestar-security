"""Backward-compatibility shim re-exporting MFA login symbols.

This module is deprecated in favor of litestar_security.accounts.mfa.
"""

import sys
from types import ModuleType

import litestar_security.accounts.mfa as _mfa
from litestar_security.accounts.mfa import (
    MFA_LOGIN_METHODS,
    MFALoginChallenge,
    MFALoginChallengeStore,
    MFALoginService,
    MFARequired,
)

__all__ = ("MFA_LOGIN_METHODS", "MFALoginChallenge", "MFALoginChallengeStore", "MFALoginService", "MFARequired")


class _MFALoginModule(ModuleType):
    """Module proxy forwarding monkeypatched attributes to canonical mfa.py."""

    def __setattr__(self, name: "str", value: "object") -> "None":
        super().__setattr__(name, value)
        if hasattr(_mfa, name):
            setattr(_mfa, name, value)

    def __getattr__(self, name: "str") -> "object":
        return getattr(_mfa, name)


sys.modules[__name__].__class__ = _MFALoginModule
