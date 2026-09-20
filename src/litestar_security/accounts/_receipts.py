"""Sealed refresh receipts that make an interrupted rotation safe to retry.

This module is a backward-compatible shim re-exporting refresh receipt symbols
from litestar_security.accounts.tokens.
"""

from litestar_security.accounts import tokens as _tokens
from litestar_security.accounts.tokens import (
    RefreshReceiptContext,
    RefreshReceiptKey,
    RefreshReceiptReplay,
    RefreshReceiptSealer,
)

__all__ = ("RefreshReceiptContext", "RefreshReceiptKey", "RefreshReceiptReplay", "RefreshReceiptSealer")


def __getattr__(name: str) -> object:
    return getattr(_tokens, name)
