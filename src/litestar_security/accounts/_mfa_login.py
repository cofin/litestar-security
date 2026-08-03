"""Contracts for password logins that require a second factor."""

from dataclasses import dataclass, field
from datetime import datetime

__all__ = ("MFA_LOGIN_METHODS", "MFARequired")


MFA_LOGIN_METHODS: frozenset[str] = frozenset({"totp", "recovery-code"})
"""Second-factor methods the initial local-login challenge can request."""


@dataclass(frozen=True, slots=True)
class MFARequired:
    """Sanitized outcome: the password verified but a second factor is owed."""

    challenge: str = field(repr=False)
    expires_at: datetime
    methods: frozenset[str]
    code: str = "mfa_required"
