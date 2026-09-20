"""Password policy evaluation, Argon2id hashing, and login authentication services."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import partial
from hmac import compare_digest
from logging import getLogger
from time import perf_counter
from typing import TYPE_CHECKING, Generic, Protocol, TypeVar, cast, runtime_checkable

from anyio import to_thread
from argon2 import PasswordHasher as _Argon2Engine
from argon2 import extract_parameters
from argon2.exceptions import Argon2Error, InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type as Argon2Type
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._internal import aware_utc_time, new_event_id, utc_now
from litestar_security.accounts._operations import (
    LOGIN,
    OUTCOME_ATTEMPTED,
    OUTCOME_MALFORMED_HASH,
    OUTCOME_UPDATED,
    OUTCOME_VERIFIED,
    PASSWORD_REHASH,
    PASSWORD_VERIFY,
)
from litestar_security.accounts._rate_limits import RateLimited, RateLimitGuard
from litestar_security.accounts.models import (
    LocalAccountState,
    NoOpSecurityEventSink,
    PasswordPolicyViolation,
    PasswordReauthenticationProof,
    PasswordVerificationStatus,
    SecurityEvent,
    SecurityEventSink,
    emit_security_event,
    normalize_identifier,
)
from litestar_security.accounts.protocols import AccountLookup, PasswordCredentialStore
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.workers import WorkerLimits

if TYPE_CHECKING:
    from collections.abc import Callable

    from argon2 import Parameters

__all__ = (
    "Argon2PasswordHasher",
    "PasswordHasher",
    "PasswordHashingUnavailableError",
    "PasswordLoginService",
    "PasswordPolicy",
    "PasswordPolicyDecision",
    "PasswordReauthenticationService",
    "PasswordVerificationOutcome",
)

UserT = TypeVar("UserT")
_MAXIMUM_PASSWORD_BYTES = 1_024
_DUMMY_PASSWORD = b"litestar-security constant-work password"
_DEFAULT_DUMMY_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$1jpw6PiEXNroO450O0ENlg$k5iQe1zKB0ogyhtm3Mlb9jKlwlPcJ5YeD5GJQ9faW+E"
)
_MAXIMUM_ARGON2_MEMORY_COST = 262_144
_MAXIMUM_ARGON2_TIME_COST = 10
_MAXIMUM_ARGON2_PARALLELISM = 8
_MAXIMUM_ARGON2_SALT_LENGTH = 64
_MAXIMUM_ARGON2_HASH_LENGTH = 64
_MAXIMUM_ENCODED_PASSWORD_HASH_BYTES = 1_024
_MAXIMUM_ARGON2_WORKER_MEMORY_KIB = 1_048_576
_ARGON2_VERSION = 19
_DEFAULT_REAUTHENTICATION_TTL = timedelta(minutes=5)
_LOGGER = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PasswordPolicyDecision:
    """Secret-free immutable password-policy decision."""

    violations: "frozenset[PasswordPolicyViolation]" = frozenset()

    @property
    def accepted(self) -> "bool":
        """Return whether no policy violation was found."""
        return not self.violations


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """Length-first password policy without composition or rotation rules."""

    minimum_length: "int" = 12
    maximum_length: "int" = 128
    maximum_bytes: "int" = _MAXIMUM_PASSWORD_BYTES
    normalizer: "Callable[[str], str]" = field(default=normalize_identifier, repr=False, compare=False)
    compromised: "Callable[[str], bool] | None" = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> "None":
        """Reject contradictory bounds and invalid customization hooks."""
        normalizer_value: object = object.__getattribute__(self, "normalizer")
        compromised_value: object = object.__getattribute__(self, "compromised")
        if (
            self.minimum_length.__class__ is not int
            or self.maximum_length.__class__ is not int
            or self.maximum_bytes.__class__ is not int
            or self.minimum_length < 1
            or self.maximum_length < self.minimum_length
            or not 1 <= self.maximum_bytes <= _MAXIMUM_PASSWORD_BYTES
        ):
            msg = "Password policy lengths must be positive, ordered, and bounded"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(normalizer_value):
            msg = "Password policy normalizer must be callable"
            raise ImproperlyConfiguredException(detail=msg)
        if compromised_value is not None and not callable(compromised_value):
            msg = "Password policy compromised-password predicate must be callable"
            raise ImproperlyConfiguredException(detail=msg)

    def check(self, password: "str", *, normalized_identifier: "str | None" = None) -> "PasswordPolicyDecision":
        """Evaluate one candidate without retaining or rendering it.

        Args:
            password: The candidate password.
            normalized_identifier: The account identifier, rejected as a password.

        Returns:
            The violations found, which is empty when the candidate is acceptable.
            Violation names never echo the candidate back.
        """
        if password.__class__ is not str:
            return PasswordPolicyDecision(frozenset({PasswordPolicyViolation.INVALID_TEXT}))
        violations = _password_shape_violations(password, self)
        if normalized_identifier is not None:
            try:
                matches_identifier = _password_matches_identifier(password, normalized_identifier, self.normalizer)
            except (TypeError, UnicodeError, ValueError):
                violations.add(PasswordPolicyViolation.INVALID_TEXT)
            else:
                if matches_identifier:
                    violations.add(PasswordPolicyViolation.MATCHES_IDENTIFIER)
        if not violations and self.compromised is not None:
            compromised_value: object = self.compromised(password)
            if compromised_value.__class__ is not bool:
                msg = "Password policy compromised-password predicate must return bool"
                raise ImproperlyConfiguredException(detail=msg)
            if compromised_value:
                violations.add(PasswordPolicyViolation.COMPROMISED)
        return PasswordPolicyDecision(frozenset(violations))


@dataclass(frozen=True, slots=True)
class PasswordVerificationOutcome:
    """Sanitized verification decision with an optional secret rehash value."""

    status: "PasswordVerificationStatus"
    replacement_hash: "str | None" = field(default=None, repr=False)

    def __post_init__(self) -> "None":
        """Allow a replacement hash only after successful verification."""
        if self.replacement_hash is not None and self.status is not PasswordVerificationStatus.VERIFIED:
            msg = "Only verified passwords may carry a replacement hash"
            raise ValueError(msg)

    @property
    def verified(self) -> "bool":
        """Return whether the password matched the stored hash."""
        return self.status is PasswordVerificationStatus.VERIFIED


class PasswordHashingUnavailableError(RuntimeError):
    """Indicate that bounded password hashing could not complete."""

    def __init__(self) -> "None":
        """Initialize the stable secret-free error."""
        super().__init__("Password hashing unavailable")


@runtime_checkable
class PasswordHasher(Protocol):
    """Async password hashing boundary suitable for custom implementations."""

    async def hash(self, password: "str") -> "str":
        """Return one encoded password hash.

        Args:
            password: The password to hash.

        Returns:
            The encoded hash, including its algorithm parameters and salt.
        """
        ...

    async def verify(self, encoded_hash: "str | None", password: "str") -> "PasswordVerificationOutcome":
        """Verify one password with constant work for absent credentials.

        Spend the same work on a malformed or absent hash as on a real one, so
        response timing does not reveal whether an account exists.

        Args:
            encoded_hash: The stored hash to verify against.
            password: The submitted password.

        Returns:
            The sanitized decision, carrying a replacement hash only when the
            password matched and the stored parameters are outdated.
        """
        ...


@dataclass(frozen=True, slots=True)
class Argon2PasswordHasher:
    """Argon2id password hasher using one bounded crypto-worker budget."""

    memory_cost: "int" = 19_456
    time_cost: "int" = 2
    parallelism: "int" = 1
    salt_len: "int" = 16
    hash_len: "int" = 32
    worker_limits: "WorkerLimits" = field(default_factory=WorkerLimits, repr=False, compare=False)
    dummy_hash: "str" = field(default=_DEFAULT_DUMMY_HASH, repr=False, compare=False)
    _engine: "_Argon2Engine" = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> "None":
        """Validate bounded parameters and one policy-matched precomputed dummy."""
        _validate_argon2_configuration(
            memory_cost=self.memory_cost,
            time_cost=self.time_cost,
            parallelism=self.parallelism,
            salt_len=self.salt_len,
            hash_len=self.hash_len,
            worker_limits=self.worker_limits,
        )
        dummy_parameters = _safe_argon2_parameters(self.dummy_hash, self.worker_limits)
        if dummy_parameters is None or not _parameters_match_hasher(dummy_parameters, self):
            msg = "Argon2 dummy hash must exactly match the configured policy"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(self, "_engine", _build_argon2_engine(self))

    @classmethod
    async def create(
        cls,
        *,
        memory_cost: "int" = 19_456,
        time_cost: "int" = 2,
        parallelism: "int" = 1,
        salt_len: "int" = 16,
        hash_len: "int" = 32,
        worker_limits: "WorkerLimits | None" = None,
    ) -> "Argon2PasswordHasher":
        """Create a strengthened policy while generating its dummy in a worker.

        Args:
            memory_cost: Argon2 memory cost in kibibytes.
            time_cost: Argon2 iteration count.
            parallelism: Argon2 lanes.
            salt_len: Salt length in bytes.
            hash_len: Derived hash length in bytes.
            worker_limits: The shared crypto-worker budget hashing runs inside.

        Returns:
            A hasher whose dummy hash matches its own parameters, so verifying an
            absent account costs the same as verifying a real one.
        """
        workers = WorkerLimits() if worker_limits is None else worker_limits
        _validate_argon2_configuration(
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism,
            salt_len=salt_len,
            hash_len=hash_len,
            worker_limits=workers,
        )
        engine = _Argon2Engine(
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism,
            salt_len=salt_len,
            hash_len=hash_len,
            type=Argon2Type.ID,
        )
        try:
            dummy_hash = await _run_password_worker(partial(engine.hash, _DUMMY_PASSWORD), workers)
        except Exception:
            raise PasswordHashingUnavailableError from None
        return cls(
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism,
            salt_len=salt_len,
            hash_len=hash_len,
            worker_limits=workers,
            dummy_hash=dummy_hash,
        )

    async def hash(self, password: "str") -> "str":
        """Hash one bounded UTF-8 password in the dedicated crypto worker.

        Args:
            password: The password to hash.

        Returns:
            The encoded Argon2id hash.
        """
        password_bytes = _password_bytes(password)
        return await self._hash_bytes(password_bytes)

    async def verify(self, encoded_hash: "str | None", password: "str") -> "PasswordVerificationOutcome":
        """Verify with equal Argon2 work for absent, mismatched, and malformed hashes.

        Args:
            encoded_hash: The stored hash to verify against.
            password: The submitted password.

        Returns:
            The sanitized decision, carrying a rehash only when the password
            matched and the stored parameters are weaker than the current ones.
        """
        password_input = _password_verification_input(password)
        if isinstance(password_input, PasswordVerificationOutcome):
            return password_input
        password_bytes = password_input
        candidate_hash = self.dummy_hash if encoded_hash is None else encoded_hash
        parameters = _safe_argon2_parameters(candidate_hash, self.worker_limits)
        if parameters is None:
            await self._verify_dummy(password_bytes)
            return PasswordVerificationOutcome(PasswordVerificationStatus.MALFORMED)
        matched = await self._match_candidate(candidate_hash, password_bytes)
        if isinstance(matched, PasswordVerificationOutcome):
            return matched
        if encoded_hash is None or not matched:
            return PasswordVerificationOutcome(PasswordVerificationStatus.INVALID)
        needs_rehash = not _parameters_match_hasher(parameters, self)
        replacement = await self._hash_bytes(password_bytes) if needs_rehash else None
        return PasswordVerificationOutcome(PasswordVerificationStatus.VERIFIED, replacement_hash=replacement)

    async def _hash_bytes(self, password: "bytes") -> "str":
        try:
            return await _run_password_worker(partial(self._engine.hash, password), self.worker_limits)
        except Exception:
            raise PasswordHashingUnavailableError from None

    async def _match_candidate(self, candidate_hash: "str", password: "bytes") -> "bool | PasswordVerificationOutcome":
        try:
            return await self._verify_once(candidate_hash, password)
        except VerifyMismatchError:
            return False
        except (InvalidHashError, VerificationError):
            if candidate_hash == self.dummy_hash:
                raise PasswordHashingUnavailableError from None
            await self._verify_dummy(password)
            return PasswordVerificationOutcome(PasswordVerificationStatus.MALFORMED)
        except Exception:
            raise PasswordHashingUnavailableError from None

    async def _verify_once(self, encoded_hash: "str", password: "bytes") -> "bool":
        return await _run_password_worker(partial(self._engine.verify, encoded_hash, password), self.worker_limits)

    async def _verify_dummy(self, password: "bytes") -> "None":
        try:
            await self._verify_once(self.dummy_hash, password)
        except VerifyMismatchError:
            pass
        except Exception:
            raise PasswordHashingUnavailableError from None


class _PasswordTooLongError(ValueError):
    pass


def _password_shape_violations(password: "str", policy: "PasswordPolicy") -> "set[PasswordPolicyViolation]":
    violations: set[PasswordPolicyViolation] = set()
    if len(password) < policy.minimum_length:
        violations.add(PasswordPolicyViolation.TOO_SHORT)
    if len(password) > policy.maximum_length:
        violations.add(PasswordPolicyViolation.TOO_LONG)
    try:
        password_bytes = password.encode("utf-8")
    except UnicodeEncodeError:
        violations.add(PasswordPolicyViolation.INVALID_TEXT)
    else:
        if len(password_bytes) > policy.maximum_bytes:
            violations.add(PasswordPolicyViolation.TOO_MANY_BYTES)
    return violations


def _password_matches_identifier(
    password: "str", normalized_identifier: "str", normalizer: "Callable[[str], str]"
) -> "bool":
    candidate = normalizer(password).encode("utf-8")
    expected = normalizer(normalized_identifier).encode("utf-8")
    return compare_digest(candidate, expected)


def _password_bytes(password: "str") -> "bytes":
    if password.__class__ is not str:
        msg = "Password must be text"
        raise ValueError(msg)
    try:
        value = password.encode("utf-8")
    except UnicodeEncodeError:
        msg = "Password must contain valid UTF-8 text"
        raise ValueError(msg) from None
    if len(value) > _MAXIMUM_PASSWORD_BYTES:
        msg = "Password must not exceed 1,024 UTF-8 bytes"
        raise _PasswordTooLongError(msg)
    return value


def _password_verification_input(password: "str") -> "bytes | PasswordVerificationOutcome":
    try:
        return _password_bytes(password)
    except _PasswordTooLongError:
        return PasswordVerificationOutcome(PasswordVerificationStatus.TOO_LONG)
    except ValueError:
        return PasswordVerificationOutcome(PasswordVerificationStatus.INVALID)


async def _run_password_worker(operation: "Callable[[], UserT]", workers: "WorkerLimits") -> "UserT":
    started = perf_counter()
    result = await to_thread.run_sync(operation, abandon_on_cancel=False, limiter=workers.crypto_limiter)
    if perf_counter() - started > workers.timeout:
        raise TimeoutError
    return result


def _validate_argon2_configuration(
    *,
    memory_cost: "int",
    time_cost: "int",
    parallelism: "int",
    salt_len: "int",
    hash_len: "int",
    worker_limits: "WorkerLimits",
) -> "None":
    values = (
        (memory_cost, 19_456, _MAXIMUM_ARGON2_MEMORY_COST),
        (time_cost, 2, _MAXIMUM_ARGON2_TIME_COST),
        (parallelism, 1, _MAXIMUM_ARGON2_PARALLELISM),
        (salt_len, 16, _MAXIMUM_ARGON2_SALT_LENGTH),
        (hash_len, 32, _MAXIMUM_ARGON2_HASH_LENGTH),
    )
    if any(value.__class__ is not int or not minimum <= value <= maximum for value, minimum, maximum in values):
        msg = "Argon2 password parameters must be strengthened within safe bounds"
        raise ImproperlyConfiguredException(detail=msg)
    if worker_limits.__class__ is not WorkerLimits:
        msg = "Argon2 password worker limits must be WorkerLimits"
        raise ImproperlyConfiguredException(detail=msg)
    if memory_cost * worker_limits.crypto_tokens > _MAXIMUM_ARGON2_WORKER_MEMORY_KIB:
        msg = "Argon2 password memory cost and crypto workers must not exceed 1 GiB"
        raise ImproperlyConfiguredException(detail=msg)


def _build_argon2_engine(hasher: "Argon2PasswordHasher") -> "_Argon2Engine":
    try:
        return _Argon2Engine(
            memory_cost=hasher.memory_cost,
            time_cost=hasher.time_cost,
            parallelism=hasher.parallelism,
            salt_len=hasher.salt_len,
            hash_len=hasher.hash_len,
            type=Argon2Type.ID,
        )
    except (Argon2Error, TypeError, ValueError):
        msg = "Invalid Argon2 password parameters"
        raise ImproperlyConfiguredException(detail=msg) from None


def _safe_argon2_parameters(encoded_hash: "object", worker_limits: "WorkerLimits") -> "Parameters | None":
    if not isinstance(encoded_hash, str):
        return None
    try:
        encoded_bytes = encoded_hash.encode("ascii")
        if len(encoded_bytes) > _MAXIMUM_ENCODED_PASSWORD_HASH_BYTES:
            return None
        parameters = extract_parameters(encoded_hash)
    except (InvalidHashError, UnicodeError, ValueError):
        return None
    if (
        parameters.type is not Argon2Type.ID
        or parameters.version != _ARGON2_VERSION
        or not 1 <= parameters.memory_cost <= _MAXIMUM_ARGON2_MEMORY_COST
        or not 1 <= parameters.time_cost <= _MAXIMUM_ARGON2_TIME_COST
        or not 1 <= parameters.parallelism <= _MAXIMUM_ARGON2_PARALLELISM
        or not 1 <= parameters.salt_len <= _MAXIMUM_ARGON2_SALT_LENGTH
        or not 1 <= parameters.hash_len <= _MAXIMUM_ARGON2_HASH_LENGTH
        or parameters.memory_cost * worker_limits.crypto_tokens > _MAXIMUM_ARGON2_WORKER_MEMORY_KIB
    ):
        return None
    return parameters


def _parameters_match_hasher(parameters: "Parameters", hasher: "Argon2PasswordHasher") -> "bool":
    return (
        parameters.memory_cost,
        parameters.time_cost,
        parameters.parallelism,
        parameters.salt_len,
        parameters.hash_len,
    ) == (hasher.memory_cost, hasher.time_cost, hasher.parallelism, hasher.salt_len, hasher.hash_len)


@dataclass(frozen=True, slots=True)
class PasswordReauthenticationService:
    """Verify a current password and emit short-lived password evidence."""

    accounts: "PasswordCredentialStore" = field(repr=False)
    hasher: "PasswordHasher" = field(repr=False)
    evidence_ttl: "timedelta" = _DEFAULT_REAUTHENTICATION_TTL
    clock: "Callable[[], datetime]" = field(default=utc_now, repr=False, compare=False)
    events: "SecurityEventSink" = field(default_factory=NoOpSecurityEventSink, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=new_event_id, repr=False, compare=False)

    def __post_init__(self) -> "None":
        """Validate structural ports and the bounded evidence lifetime."""
        accounts_value: object = object.__getattribute__(self, "accounts")
        hasher_value: object = object.__getattribute__(self, "hasher")
        evidence_ttl_value: object = object.__getattribute__(self, "evidence_ttl")
        clock_value: object = object.__getattribute__(self, "clock")
        events_value: object = object.__getattribute__(self, "events")
        event_ids_value: object = object.__getattribute__(self, "event_ids")
        if not isinstance(accounts_value, PasswordCredentialStore):
            msg = "Password reauthentication accounts must implement PasswordCredentialStore"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(hasher_value, PasswordHasher):
            msg = "Password reauthentication hasher must implement PasswordHasher"
            raise ImproperlyConfiguredException(detail=msg)
        if (
            not isinstance(evidence_ttl_value, timedelta)
            or evidence_ttl_value <= timedelta(0)
            or evidence_ttl_value > _DEFAULT_REAUTHENTICATION_TTL
        ):
            msg = "Password reauthentication evidence lifetime must be positive and at most five minutes"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(clock_value):
            msg = "Password reauthentication clock must be callable"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(events_value, SecurityEventSink):
            msg = "Password reauthentication events must implement SecurityEventSink"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(event_ids_value):
            msg = "Password reauthentication event id factory must be callable"
            raise ImproperlyConfiguredException(detail=msg)

    async def verify(
        self, account_id: "str", password: "str", *, now: "datetime | None" = None
    ) -> "PasswordReauthenticationProof | InvalidCredentials | VerificationUnavailable":
        """Return an account- and epoch-bound proof or one sanitized domain outcome.

        Args:
            account_id: The authenticated caller's account.
            password: The current password to re-verify.
            now: Override the clock, for tests and replayable proofs.

        Returns:
            Short-lived evidence bound to the account and its epoch,
            ``InvalidCredentials`` when the password is rejected, or
            ``VerificationUnavailable`` when a dependency failed.
        """
        account_value: object = account_id
        if account_value.__class__ is not str or not (normalized_account_id := account_id.strip()):
            return InvalidCredentials()
        try:
            authenticated_at = aware_utc_time(self.clock() if now is None else now)
        except Exception:
            return VerificationUnavailable()
        read_unavailable = False
        try:
            state = await self.accounts.get_password_state(normalized_account_id)
        except Exception:
            state = None
            read_unavailable = True
        encoded_hash = state.password_hash if state is not None else None
        try:
            result = await self.hasher.verify(encoded_hash, password)
        except Exception:
            return VerificationUnavailable()
        if read_unavailable:
            return VerificationUnavailable()
        if not result.verified or encoded_hash is None or state is None:
            if result.status is PasswordVerificationStatus.MALFORMED:
                await self._emit_malformed(normalized_account_id, authenticated_at)
            return InvalidCredentials()
        if not state.active or not state.verified:
            return InvalidCredentials()
        if result.replacement_hash is not None and not await self._rehash(
            normalized_account_id, encoded_hash, result.replacement_hash, authenticated_at
        ):
            return VerificationUnavailable()
        return PasswordReauthenticationProof(
            account_id=normalized_account_id,
            security_epoch=state.security_epoch,
            authenticated_at=authenticated_at,
            expires_at=authenticated_at + self.evidence_ttl,
        )

    async def _rehash(
        self, account_id: "str", expected_hash: "str", replacement_hash: "str", occurred_at: "datetime"
    ) -> "bool":
        try:
            event = self._event(account_id, occurred_at, operation=PASSWORD_REHASH, outcome=OUTCOME_UPDATED)
            replaced: object = await self.accounts.compare_and_replace_password(
                account_id, expected_hash, replacement_hash, event=event
            )
        except Exception:
            return False
        return replaced is True

    def _event(
        self, account_id: "str", occurred_at: "datetime", *, operation: "str", outcome: "str"
    ) -> "SecurityEvent":
        event_id = self.event_ids().strip()
        if not event_id:
            raise ValueError
        return SecurityEvent(
            event_id=event_id,
            occurred_at=occurred_at,
            operation=operation,
            outcome=outcome,
            account_id=account_id,
            mechanism="password",
        )

    async def _emit_malformed(self, account_id: "str", occurred_at: "datetime") -> "None":
        try:
            event = self._event(account_id, occurred_at, operation=PASSWORD_VERIFY, outcome=OUTCOME_MALFORMED_HASH)
        except ValueError:
            _LOGGER.error("Security event could not be built for %s", PASSWORD_VERIFY)
            return
        await emit_security_event(self.events, event)


@dataclass(frozen=True, slots=True)
class PasswordLoginService(Generic[UserT]):
    """Authenticate one normalized identifier with exactly one password-work class."""

    accounts: "AccountLookup[UserT]" = field(repr=False)
    hasher: "PasswordHasher" = field(repr=False)
    normalizer: "Callable[[str], str]" = field(default=normalize_identifier, repr=False, compare=False)
    rate_limits: "RateLimitGuard | None" = field(default=None, repr=False, compare=False)
    clock: "Callable[[], datetime]" = field(default=utc_now, repr=False, compare=False)
    events: "SecurityEventSink" = field(default_factory=NoOpSecurityEventSink, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=new_event_id, repr=False, compare=False)
    _reauthentication: "PasswordReauthenticationService" = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> "None":
        """Validate the minimal lookup, password, limiting, and audit capabilities once."""
        accounts_value: object = object.__getattribute__(self, "accounts")
        hasher_value: object = object.__getattribute__(self, "hasher")
        normalizer_value: object = object.__getattribute__(self, "normalizer")
        rate_limits_value: object = object.__getattribute__(self, "rate_limits")
        events_value: object = object.__getattribute__(self, "events")
        if not isinstance(accounts_value, AccountLookup) or not isinstance(accounts_value, PasswordCredentialStore):
            msg = "Password login accounts must implement AccountLookup and PasswordCredentialStore"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(hasher_value, PasswordHasher):
            msg = "Password login hasher must implement PasswordHasher"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(normalizer_value):
            msg = "Password login normalizer must be callable"
            raise ImproperlyConfiguredException(detail=msg)
        if rate_limits_value is not None and rate_limits_value.__class__ is not RateLimitGuard:
            msg = "Password login rate limits must be a RateLimitGuard"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(events_value, SecurityEventSink):
            msg = "Password login events must implement SecurityEventSink"
            raise ImproperlyConfiguredException(detail=msg)
        clock_value: object = object.__getattribute__(self, "clock")
        event_ids_value: object = object.__getattribute__(self, "event_ids")
        if not callable(clock_value) or not callable(event_ids_value):
            msg = "Password login clock and event id factory must be callable"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(
            self,
            "_reauthentication",
            PasswordReauthenticationService(
                accounts=cast("PasswordCredentialStore", accounts_value),
                hasher=self.hasher,
                clock=self.clock,
                events=self.events,
                event_ids=self.event_ids,
            ),
        )

    async def authenticate(
        self, identifier: "str", password: "str", *, now: "datetime | None" = None, client_key: "str | None" = None
    ) -> "LocalAccountState[UserT] | RateLimited | InvalidCredentials | VerificationUnavailable":
        """Return an active verified account after limiting, lookup, and constant password work.

        The limiter runs before the store lookup and before Argon2, so a denied
        attempt costs neither. An absent account still pays for a hash, so a
        missing account is not measurably faster to probe than a present one.

        Args:
            identifier: The submitted identifier, normalized before lookup.
            password: The submitted password.
            now: Override the clock, for tests and replayable authentication.
            client_key: The caller identity for the rate-limit client bucket.

        Returns:
            The authenticated account, ``RateLimited`` when the budget is spent,
            ``InvalidCredentials`` when the credentials are rejected, or
            ``VerificationUnavailable`` when a dependency failed. A rejected
            identifier and a rejected password are not distinguished.
        """
        normalized_identifier = ""
        lookup_unavailable = False
        try:
            normalized_identifier = self.normalizer(identifier)
        except Exception:
            lookup_unavailable = True
        limited = await self._check_rate_limit(client_key, normalized_identifier)
        if limited is not None:
            return limited
        account, lookup_unavailable = await self._find_account(normalized_identifier, unavailable=lookup_unavailable)
        if account is None:
            return await self._absent_account_outcome(password, unavailable=lookup_unavailable)
        password_result = await self._reauthentication.verify(account.account_id, password, now=now)
        if not isinstance(password_result, PasswordReauthenticationProof):
            if isinstance(password_result, InvalidCredentials):
                await self._emit_decision(account.account_id, OUTCOME_ATTEMPTED)
            return password_result
        if (
            not account.active
            or not account.verified
            or password_result.account_id != account.account_id
            or password_result.security_epoch != account.security_epoch
        ):
            await self._emit_decision(account.account_id, OUTCOME_ATTEMPTED)
            return InvalidCredentials()
        await self._emit_decision(account.account_id, OUTCOME_VERIFIED)
        return account

    async def _find_account(
        self, normalized_identifier: "str", *, unavailable: "bool"
    ) -> "tuple[LocalAccountState[UserT] | None, bool]":
        if unavailable or not normalized_identifier:
            return None, unavailable
        try:
            return await self.accounts.find_for_login(normalized_identifier), False
        except Exception:
            return None, True

    async def _absent_account_outcome(
        self, password: "str", *, unavailable: "bool"
    ) -> "InvalidCredentials | VerificationUnavailable":
        try:
            await self.hasher.verify(None, password)
        except Exception:
            return VerificationUnavailable()
        if unavailable:
            return VerificationUnavailable()
        await self._emit_decision(None, OUTCOME_ATTEMPTED)
        return InvalidCredentials()

    async def _check_rate_limit(
        self, client_key: "str | None", normalized_identifier: "str"
    ) -> "RateLimited | VerificationUnavailable | None":
        rate_limits = self.rate_limits
        if rate_limits is None:
            return None
        return await rate_limits.check(LOGIN, client_key=client_key, identifier=normalized_identifier or None)

    async def _emit_decision(self, account_id: "str | None", outcome: "str") -> "None":
        try:
            event = SecurityEvent(
                event_id=self.event_ids(),
                occurred_at=aware_utc_time(self.clock()),
                operation=LOGIN,
                outcome=outcome,
                account_id=account_id,
                mechanism="password",
            )
        except Exception:
            _LOGGER.error("Security event could not be built for %s", LOGIN)
            return
        await emit_security_event(self.events, event)
