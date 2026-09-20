"""Backward-compatibility shim re-exporting native session management symbols.

This module is deprecated in favor of litestar_security.accounts.sessions.
"""

from __future__ import annotations

import sys
from types import ModuleType

import litestar_security.accounts.sessions as _sessions
from litestar_security.accounts.sessions import (
    CreateSessionCommand,
    NativeSessionAuth,
    NativeSessionStore,
    ResolvedUserAuthSession,
    SessionAuthentication,
    SessionBindingConfig,
    SessionBindingProof,
    SessionRebindPlan,
    SessionRegistry,
    SessionSummary,
    UserAuthSession,
    UserAuthSessionResolver,
    compare_digest,
)

__all__ = (
    "CreateSessionCommand",
    "NativeSessionAuth",
    "NativeSessionStore",
    "ResolvedUserAuthSession",
    "SessionAuthentication",
    "SessionBindingConfig",
    "SessionBindingProof",
    "SessionRebindPlan",
    "SessionRegistry",
    "SessionSummary",
    "UserAuthSession",
    "UserAuthSessionResolver",
    "compare_digest",
)


class _SessionsModule(ModuleType):
    """Module proxy forwarding monkeypatched attributes to canonical sessions.py."""

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if hasattr(_sessions, name):
            setattr(_sessions, name, value)

    def __getattr__(self, name: str) -> object:
        return getattr(_sessions, name)


sys.modules[__name__].__class__ = _SessionsModule
