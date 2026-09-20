"""Backward-compatibility shim re-exporting MFA and TOTP symbols.

This module is deprecated in favor of litestar_security.accounts.mfa.
"""

from __future__ import annotations

import sys
from types import ModuleType

import litestar_security.accounts.mfa as _mfa
from litestar_security.accounts.mfa import (
    AESGCMSecretProtector,
    MFAService,
    MFAStore,
    PendingTOTPEnrollment,
    ProtectedSecret,
    RecoveryCodeDigest,
    RecoveryCodeGrant,
    RecoveryCodePepper,
    SecretProtector,
    SecretProtectorKey,
    StepUpCredential,
    StepUpGrantState,
    StepUpService,
    StepUpStore,
    TOTPMethod,
    TOTPPolicy,
    TOTPProvisioningGrant,
    TOTPService,
    TOTPStore,
)

__all__ = (
    "AESGCMSecretProtector",
    "MFAService",
    "MFAStore",
    "PendingTOTPEnrollment",
    "ProtectedSecret",
    "RecoveryCodeDigest",
    "RecoveryCodeGrant",
    "RecoveryCodePepper",
    "SecretProtector",
    "SecretProtectorKey",
    "StepUpCredential",
    "StepUpGrantState",
    "StepUpService",
    "StepUpStore",
    "TOTPMethod",
    "TOTPPolicy",
    "TOTPProvisioningGrant",
    "TOTPService",
    "TOTPStore",
)


class _MFAModule(ModuleType):
    """Module proxy forwarding monkeypatched attributes to canonical mfa.py."""

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if hasattr(_mfa, name):
            setattr(_mfa, name, value)

    def __getattr__(self, name: str) -> object:
        return getattr(_mfa, name)


sys.modules[__name__].__class__ = _MFAModule
