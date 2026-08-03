"""Password policy evaluation and Argon2id hashing."""

from dataclasses import dataclass, field
from functools import partial
from hmac import compare_digest
from time import perf_counter
from typing import TYPE_CHECKING, Protocol, TypeVar, runtime_checkable

from anyio import to_thread
from argon2 import PasswordHasher as _Argon2Engine
from argon2 import extract_parameters
from argon2.exceptions import Argon2Error, InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type as Argon2Type
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._records import (
    PasswordPolicyViolation,
    PasswordVerificationStatus,
    normalize_identifier,
)
from litestar_security.workers import WorkerLimits

if TYPE_CHECKING:
    from collections.abc import Callable

    from argon2 import Parameters

__all__ = (
    "Argon2PasswordHasher",
    "PasswordHasher",
    "PasswordHashingUnavailableError",
    "PasswordPolicy",
    "PasswordPolicyResult",
    "PasswordVerificationResult",
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


@dataclass(frozen=True, slots=True)
class PasswordPolicyResult:
    """Secret-free immutable password-policy decision."""

    violations: frozenset[PasswordPolicyViolation] = frozenset()

    @property
    def accepted(self) -> bool:
        """Return whether no policy violation was found."""
        return not self.violations


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """Length-first password policy without composition or rotation rules."""

    minimum_length: int = 15
    maximum_length: int = 128
    maximum_bytes: int = _MAXIMUM_PASSWORD_BYTES
    normalizer: "Callable[[str], str]" = field(default=normalize_identifier, repr=False, compare=False)
    compromised: "Callable[[str], bool] | None" = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
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

    def check(self, password: str, *, normalized_identifier: str | None = None) -> PasswordPolicyResult:
        """Evaluate one candidate without retaining or rendering it.

        Args:
            password: The candidate password.
            normalized_identifier: The account identifier, rejected as a password.

        Returns:
            The violations found, which is empty when the candidate is acceptable.
            Violation names never echo the candidate back.
        """
        if password.__class__ is not str:
            return PasswordPolicyResult(frozenset({PasswordPolicyViolation.INVALID_TEXT}))
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
        return PasswordPolicyResult(frozenset(violations))


@dataclass(frozen=True, slots=True)
class PasswordVerificationResult:
    """Sanitized verification decision with an optional secret rehash value."""

    status: PasswordVerificationStatus
    replacement_hash: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Allow a replacement hash only after successful verification."""
        if self.replacement_hash is not None and self.status is not PasswordVerificationStatus.VERIFIED:
            msg = "Only verified passwords may carry a replacement hash"
            raise ValueError(msg)

    @property
    def verified(self) -> bool:
        """Return whether the password matched the stored hash."""
        return self.status is PasswordVerificationStatus.VERIFIED


class PasswordHashingUnavailableError(RuntimeError):
    """Indicate that bounded password hashing could not complete."""

    def __init__(self) -> None:
        """Initialize the stable secret-free error."""
        super().__init__("Password hashing unavailable")


@runtime_checkable
class PasswordHasher(Protocol):
    """Async password hashing boundary suitable for custom implementations."""

    async def hash(self, password: str) -> str:
        """Return one encoded password hash.

        Args:
            password: The password to hash.

        Returns:
            The encoded hash, including its algorithm parameters and salt.
        """
        ...  # pragma: no cover

    async def verify(self, encoded_hash: str | None, password: str) -> PasswordVerificationResult:
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
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class Argon2PasswordHasher:
    """Argon2id password hasher using one bounded crypto-worker budget."""

    memory_cost: int = 19_456
    time_cost: int = 2
    parallelism: int = 1
    salt_len: int = 16
    hash_len: int = 32
    worker_limits: WorkerLimits = field(default_factory=WorkerLimits, repr=False, compare=False)
    dummy_hash: str = field(default=_DEFAULT_DUMMY_HASH, repr=False, compare=False)
    _engine: _Argon2Engine = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
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
    async def create(  # noqa: PLR0913 - explicit configuration surface; every input is named
        cls,
        *,
        memory_cost: int = 19_456,
        time_cost: int = 2,
        parallelism: int = 1,
        salt_len: int = 16,
        hash_len: int = 32,
        worker_limits: WorkerLimits | None = None,
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
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
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

    async def hash(self, password: str) -> str:
        """Hash one bounded UTF-8 password in the dedicated crypto worker.

        Args:
            password: The password to hash.

        Returns:
            The encoded Argon2id hash.
        """
        password_bytes = _password_bytes(password)
        return await self._hash_bytes(password_bytes)

    async def verify(self, encoded_hash: str | None, password: str) -> PasswordVerificationResult:
        """Verify with equal Argon2 work for absent, mismatched, and malformed hashes.

        Args:
            encoded_hash: The stored hash to verify against.
            password: The submitted password.

        Returns:
            The sanitized decision, carrying a rehash only when the password
            matched and the stored parameters are weaker than the current ones.
        """
        password_input = _password_verification_input(password)
        if isinstance(password_input, PasswordVerificationResult):
            return password_input
        password_bytes = password_input
        candidate_hash = self.dummy_hash if encoded_hash is None else encoded_hash
        parameters = _safe_argon2_parameters(candidate_hash, self.worker_limits)
        if parameters is None:
            await self._verify_dummy(password_bytes)
            return PasswordVerificationResult(PasswordVerificationStatus.MALFORMED)
        matched = await self._match_candidate(candidate_hash, password_bytes)
        if isinstance(matched, PasswordVerificationResult):
            return matched
        if encoded_hash is None or not matched:
            return PasswordVerificationResult(PasswordVerificationStatus.INVALID)
        needs_rehash = not _parameters_match_hasher(parameters, self)
        replacement = await self._hash_bytes(password_bytes) if needs_rehash else None
        return PasswordVerificationResult(PasswordVerificationStatus.VERIFIED, replacement_hash=replacement)

    async def _hash_bytes(self, password: bytes) -> str:
        try:
            return await _run_password_worker(partial(self._engine.hash, password), self.worker_limits)
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            raise PasswordHashingUnavailableError from None

    async def _match_candidate(self, candidate_hash: str, password: bytes) -> bool | PasswordVerificationResult:
        try:
            return await self._verify_once(candidate_hash, password)
        except VerifyMismatchError:
            return False
        except (InvalidHashError, VerificationError):
            if candidate_hash == self.dummy_hash:
                raise PasswordHashingUnavailableError from None
            await self._verify_dummy(password)
            return PasswordVerificationResult(PasswordVerificationStatus.MALFORMED)
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            raise PasswordHashingUnavailableError from None

    async def _verify_once(self, encoded_hash: str, password: bytes) -> bool:
        return await _run_password_worker(partial(self._engine.verify, encoded_hash, password), self.worker_limits)

    async def _verify_dummy(self, password: bytes) -> None:
        try:
            await self._verify_once(self.dummy_hash, password)
        except VerifyMismatchError:
            pass
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            raise PasswordHashingUnavailableError from None


class _PasswordTooLongError(ValueError):
    pass


def _password_shape_violations(password: str, policy: "PasswordPolicy") -> set[PasswordPolicyViolation]:
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


def _password_matches_identifier(password: str, normalized_identifier: str, normalizer: "Callable[[str], str]") -> bool:
    candidate = normalizer(password).encode("utf-8")
    expected = normalizer(normalized_identifier).encode("utf-8")
    return compare_digest(candidate, expected)


def _password_bytes(password: str) -> bytes:
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


def _password_verification_input(password: str) -> bytes | PasswordVerificationResult:
    try:
        return _password_bytes(password)
    except _PasswordTooLongError:
        return PasswordVerificationResult(PasswordVerificationStatus.TOO_LONG)
    except ValueError:
        return PasswordVerificationResult(PasswordVerificationStatus.INVALID)


async def _run_password_worker(operation: "Callable[[], UserT]", workers: WorkerLimits) -> UserT:
    started = perf_counter()
    result = await to_thread.run_sync(operation, abandon_on_cancel=False, limiter=workers.crypto_limiter)
    if perf_counter() - started > workers.timeout:
        raise TimeoutError
    return result


def _validate_argon2_configuration(  # noqa: PLR0913 - explicit configuration surface; every input is named
    *, memory_cost: int, time_cost: int, parallelism: int, salt_len: int, hash_len: int, worker_limits: WorkerLimits
) -> None:
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


def _build_argon2_engine(hasher: Argon2PasswordHasher) -> _Argon2Engine:
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


def _safe_argon2_parameters(encoded_hash: object, worker_limits: WorkerLimits) -> "Parameters | None":
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


def _parameters_match_hasher(parameters: "Parameters", hasher: Argon2PasswordHasher) -> bool:
    return (
        parameters.memory_cost,
        parameters.time_cost,
        parameters.parallelism,
        parameters.salt_len,
        parameters.hash_len,
    ) == (hasher.memory_cost, hasher.time_cost, hasher.parallelism, hasher.salt_len, hasher.hash_len)
