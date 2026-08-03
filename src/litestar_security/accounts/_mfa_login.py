"""Contracts for password logins that require a second factor."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from hashlib import sha256
from typing import Protocol, cast, runtime_checkable

from litestar_security.accounts._internal import aware_utc_time, strict_context_text, valid_security_epoch

__all__ = ("MFA_LOGIN_METHODS", "MFALoginChallenge", "MFALoginChallengeStore", "MFARequired")


MFA_LOGIN_METHODS: frozenset[str] = frozenset({"totp", "recovery-code"})
"""Second-factor methods the initial local-login challenge can request."""

_DEFAULT_MFA_LOGIN_TTL = timedelta(minutes=5)
_MAXIMUM_MFA_LOGIN_TTL = timedelta(minutes=10)


@dataclass(frozen=True, slots=True)
class MFARequired:
    """Sanitized outcome: the password verified but a second factor is owed."""

    challenge: str = field(repr=False)
    expires_at: datetime
    methods: frozenset[str]
    code: str = "mfa_required"


@dataclass(frozen=True, slots=True)
class MFALoginChallenge:
    """Digest-only pending second-factor state for one password login."""

    challenge_digest: bytes = field(repr=False)
    account_id: str
    security_epoch: int
    client_key: str | None
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        """Require exact digest, context, and bounded UTC lifetime bindings."""
        challenge_digest = cast("object", self.challenge_digest)
        issued_at = aware_utc_time(self.issued_at)
        expires_at = aware_utc_time(self.expires_at)
        if (
            not isinstance(challenge_digest, bytes)
            or challenge_digest.__class__ is not bytes
            or len(challenge_digest) != sha256().digest_size
            or not strict_context_text(self.account_id)
            or not valid_security_epoch(self.security_epoch)
            or (self.client_key is not None and not strict_context_text(self.client_key))
            or expires_at <= issued_at
            or expires_at - issued_at > _MAXIMUM_MFA_LOGIN_TTL
        ):
            message = "MFA login challenge requires exact digest, context, epoch, and lifetime bindings"
            raise ValueError(message)
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)


@runtime_checkable
class MFALoginChallengeStore(Protocol):
    """Persist and atomically consume digest-only MFA login challenges."""

    async def put(self, challenge: MFALoginChallenge) -> None:
        """Persist one pending challenge."""
        ...  # pragma: no cover

    async def consume(
        self, challenge_digest: bytes, *, account_id: str, security_epoch: int, now: datetime
    ) -> MFALoginChallenge | None:
        """Atomically burn and return one exact, unexpired challenge binding.

        Implementations must remove and return exactly one record in one transaction
        only when its account and security epoch match. A found digest is consumed
        before validating those predicates, including expiry, so every failed reveal
        attempt burns the challenge.
        """
        ...  # pragma: no cover
