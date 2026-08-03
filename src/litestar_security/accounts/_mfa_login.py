"""Contracts and service for password logins that require a second factor."""

from base64 import urlsafe_b64encode
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from hashlib import sha256
from hmac import compare_digest
from hmac import new as new_hmac
from secrets import token_bytes
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._internal import (
    MINIMUM_PEPPER_BYTES,
    aware_utc_time,
    strict_context_text,
    utc_now,
    valid_security_epoch,
)
from litestar_security.accounts._mfa import MFAService
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.context import AuthenticationEvidence

if TYPE_CHECKING:
    from litestar_security.accounts._records import LocalAccount

__all__ = ("MFA_LOGIN_METHODS", "MFALoginChallenge", "MFALoginChallengeStore", "MFALoginService", "MFARequired")


MFA_LOGIN_METHODS: frozenset[str] = frozenset({"totp", "recovery-code"})
"""Second-factor methods the initial local-login challenge can request."""

_DEFAULT_MFA_LOGIN_TTL = timedelta(minutes=5)
_MAXIMUM_MFA_LOGIN_TTL = timedelta(minutes=10)
_MFA_LOGIN_TOKEN_BYTES = 32


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


@dataclass(frozen=True, slots=True)
class MFALoginService:
    """Issue and consume opaque, account-bound MFA login challenges."""

    store: MFALoginChallengeStore = field(repr=False)
    mfa: MFAService = field(repr=False)
    pepper: bytes = field(repr=False)
    methods: frozenset[str] = MFA_LOGIN_METHODS
    ttl: timedelta = _DEFAULT_MFA_LOGIN_TTL
    clock: Callable[[], datetime] = field(default=utc_now, repr=False, compare=False)
    entropy: Callable[[int], bytes] = field(default=token_bytes, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Require an atomic store and bounded, explicit cryptographic inputs."""
        store = cast("object", self.store)
        mfa = cast("object", self.mfa)
        pepper = cast("object", self.pepper)
        methods = cast("object", self.methods)
        ttl = cast("object", self.ttl)
        clock = cast("object", self.clock)
        entropy = cast("object", self.entropy)
        if not isinstance(store, MFALoginChallengeStore):
            message = "MFA login service store must implement MFALoginChallengeStore"
            raise ImproperlyConfiguredException(detail=message)
        if not isinstance(mfa, MFAService):
            message = "MFA login service MFA capability must be an MFAService"
            raise ImproperlyConfiguredException(detail=message)
        if not isinstance(pepper, bytes) or pepper.__class__ is not bytes or len(pepper) < MINIMUM_PEPPER_BYTES:
            message = "MFA login challenge pepper must be at least 32 exact bytes"
            raise ImproperlyConfiguredException(detail=message)
        if not _valid_methods(methods):
            message = "MFA login methods must be a non-empty exact set of supported methods"
            raise ImproperlyConfiguredException(detail=message)
        if (
            not isinstance(ttl, timedelta)
            or ttl.__class__ is not timedelta
            or not timedelta() < ttl <= _MAXIMUM_MFA_LOGIN_TTL
        ):
            message = "MFA login challenge lifetime must be positive and at most ten minutes"
            raise ImproperlyConfiguredException(detail=message)
        if not callable(clock) or not callable(entropy):
            message = "MFA login clock and entropy must be callable"
            raise ImproperlyConfiguredException(detail=message)

    async def issue(
        self, account: "LocalAccount[object]", *, client_key: str | None
    ) -> MFARequired | VerificationUnavailable:
        """Persist and reveal one short-lived MFA challenge for a verified password login."""
        try:
            now = aware_utc_time(self.clock())
            if (
                not strict_context_text(account.account_id)
                or not valid_security_epoch(account.security_epoch)
                or not _valid_client_key(client_key)
            ):
                return VerificationUnavailable()
            raw_value = cast("object", self.entropy(_MFA_LOGIN_TOKEN_BYTES))
            if (
                not isinstance(raw_value, bytes)
                or raw_value.__class__ is not bytes
                or len(raw_value) != _MFA_LOGIN_TOKEN_BYTES
            ):
                return VerificationUnavailable()
            token = urlsafe_b64encode(raw_value).rstrip(b"=").decode("ascii")
            expires_at = now + self.ttl
            await self.store.put(
                MFALoginChallenge(
                    challenge_digest=_challenge_digest(self.pepper, token),
                    account_id=account.account_id,
                    security_epoch=account.security_epoch,
                    client_key=client_key,
                    issued_at=now,
                    expires_at=expires_at,
                )
            )
        except Exception:  # noqa: BLE001 - sanitize clock, entropy, and store failures
            return VerificationUnavailable()
        return MFARequired(challenge=token, expires_at=expires_at, methods=self.methods)

    async def consume(
        self, challenge: str, *, account_id: str, security_epoch: int, client_key: str | None
    ) -> MFALoginChallenge | InvalidCredentials | VerificationUnavailable:
        """Atomically burn one challenge before checking its client binding."""
        if (
            not _strict_ascii_context(challenge)
            or not strict_context_text(account_id)
            or not valid_security_epoch(security_epoch)
        ):
            return InvalidCredentials()
        try:
            now = aware_utc_time(self.clock())
            record = await self.store.consume(
                _challenge_digest(self.pepper, challenge),
                account_id=account_id,
                security_epoch=security_epoch,
                now=now,
            )
        except Exception:  # noqa: BLE001 - sanitize clock and store failures
            return VerificationUnavailable()
        if record is None or not _valid_client_key(client_key) or not _client_keys_match(record.client_key, client_key):
            return InvalidCredentials()
        return record

    async def verify(
        self, record: MFALoginChallenge, *, method: str, method_id: str | None, code: str
    ) -> AuthenticationEvidence | InvalidCredentials | VerificationUnavailable:
        """Verify the selected factor for a consumed login challenge."""
        if method.__class__ is not str or method not in self.methods:
            return InvalidCredentials()
        try:
            if method == "totp":
                if method_id is None or method_id.__class__ is not str:
                    return InvalidCredentials()
                return await self.mfa.verify_totp(record.account_id, method_id, code)
            if method == "recovery-code":
                return await self.mfa.consume_recovery_code(record.account_id, code)
        except Exception:  # noqa: BLE001 - sanitize MFA port failures
            return VerificationUnavailable()
        return InvalidCredentials()


def _challenge_digest(pepper: bytes, challenge: str) -> bytes:
    """Return the domain-separated digest for one strict-ASCII challenge."""
    return new_hmac(pepper, challenge.encode("ascii"), sha256).digest()


def _strict_ascii_context(value: object) -> bool:
    """Accept only exact, nonblank, control-free ASCII context text."""
    try:
        return strict_context_text(value) and cast("str", value).isascii()
    except UnicodeError:
        return False


def _valid_client_key(value: object) -> bool:
    """Allow no client binding or one strict client context value."""
    try:
        return value is None or strict_context_text(value)
    except UnicodeError:
        return False


def _valid_methods(value: object) -> bool:
    """Require a concrete non-empty subset of the supported MFA methods."""
    if type(value) is not frozenset:
        return False
    methods = cast("frozenset[object]", value)
    return bool(methods) and all(type(method) is str and method in MFA_LOGIN_METHODS for method in methods)


def _client_keys_match(expected: str | None, actual: object) -> bool:
    """Compare optional stored and presented client bindings without shortcuts."""
    if expected is None or actual is None:
        return expected is None and actual is None
    if not isinstance(actual, str):
        return False
    try:
        return compare_digest(expected.encode("utf-8"), actual.encode("utf-8"))
    except UnicodeError:
        return False
