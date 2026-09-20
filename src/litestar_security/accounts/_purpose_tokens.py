"""Purpose-bound one-time token issuing, delivery, and verification.

This module is a backward-compatible shim re-exporting purpose token symbols
from litestar_security.accounts.tokens.
"""

import sys
from types import ModuleType

import litestar_security.accounts.tokens as _tokens
from litestar_security.accounts.tokens import (
    NotificationCommand,
    PendingTokenIssue,
    PurposeTokenCodec,
    PurposeTokenDelivery,
    PurposeTokenGenerationError,
    PurposeTokenProof,
    RegistrationCommand,
    TokenIssue,
    approved_return_url,
    b64url_decode,
    b64url_encode,
    hmac_digest,
)

__all__ = (
    "NotificationCommand",
    "PendingTokenIssue",
    "PurposeTokenCodec",
    "PurposeTokenDelivery",
    "PurposeTokenGenerationError",
    "PurposeTokenProof",
    "RegistrationCommand",
    "TokenIssue",
    "approved_return_url",
    "b64url_decode",
    "b64url_encode",
    "hmac_digest",
)


class _PurposeTokensModule(ModuleType):
    """Module proxy forwarding monkeypatched attributes to tokens.py."""

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if hasattr(_tokens, name):
            setattr(_tokens, name, value)

    def __getattr__(self, name: str) -> object:
        return getattr(_tokens, name)


sys.modules[__name__].__class__ = _PurposeTokensModule
