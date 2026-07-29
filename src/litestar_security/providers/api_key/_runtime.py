"""API-key request authentication, lifecycle services, and usage buffering."""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, TypeVar, cast

from litestar.connection import ASGIConnection
from litestar.openapi.spec import SecurityScheme

from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationOutcome,
    CredentialExtraction,
    CredentialSlot,
    IdentityResolver,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
    VerificationUnavailable,
)
from litestar_security.config import NoOpSecurityMetrics, SecurityMetrics
from litestar_security.context import AuthenticationEvidence, CredentialRestrictions
from litestar_security.providers._internal import safe_increment
from litestar_security.providers.api_key._api_key import APIKeyCodec, APIKeyConfig, APIKeyStore, IssuedAPIKey

__all__ = ("APIKeyClaims", "APIKeyService", "BufferedAPIKeyUsage")


UserT = TypeVar("UserT")

_MECHANISM_NAME = "api-key"
_SLOT_NAME = "api-key"
_ASCII_CONTROL_LIMIT = 32
_ASCII_DELETE = 127
_MAXIMUM_USAGE_BUFFER_CAPACITY = 1_000_000


@dataclass(frozen=True, slots=True)
class APIKeyClaims:
    """Verified digest-free identity carried from authentication to resolution."""

    key_id: str
    subject_id: str


@dataclass(slots=True)
class BufferedAPIKeyUsage:
    """Bound and coalesce best-effort usage observations away from requests."""

    sink: object
    interval: timedelta
    capacity: int = 1024
    metrics: SecurityMetrics = field(default_factory=NoOpSecurityMetrics)
    _pending: dict[str, datetime] = field(default_factory=dict[str, datetime], init=False, repr=False)
    _last_written: dict[str, datetime] = field(default_factory=dict[str, datetime], init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate a structural sink and positive finite buffer policy."""
        sink = self.sink
        metrics = cast("object", self.metrics)
        if not hasattr(sink, "record") or not callable(getattr(sink, "record", None)):
            message = "API-key usage sink must define record"
            raise ValueError(message)
        if self.interval.__class__ is not timedelta or self.interval <= timedelta(0):
            message = "API-key usage interval must be positive"
            raise ValueError(message)
        if self.capacity.__class__ is not int:
            message = "API-key usage capacity must be an integer"
            raise TypeError(message)
        if not 1 <= self.capacity <= _MAXIMUM_USAGE_BUFFER_CAPACITY:
            message = "API-key usage capacity must be positive and bounded"
            raise ValueError(message)
        if not isinstance(metrics, SecurityMetrics):
            message = "API-key usage metrics must implement SecurityMetrics"
            raise TypeError(message)

    def observe(self, key_id: str, used_at: datetime) -> None:
        """Retain one latest secret-free observation without performing I/O.

        Args:
            key_id: The public key lookup.
            used_at: The timezone-aware usage timestamp.
        """
        normalized = _utc(used_at)
        if key_id in self._pending:
            self._pending[key_id] = max(self._pending[key_id], normalized)
            safe_increment(self.metrics, "security.api_key.usage_coalesced")
            return
        if len(self._pending) >= self.capacity:
            safe_increment(self.metrics, "security.api_key.usage_dropped")
            return
        self._pending[key_id] = normalized

    async def flush(self, *, force: bool = False) -> None:
        """Write eligible coalesced observations without raising sink failures.

        Args:
            force: Ignore the interval during shutdown.
        """
        for key_id, used_at in tuple(self._pending.items()):
            last_written = self._last_written.get(key_id)
            if not force and last_written is not None and used_at - last_written < self.interval:
                continue
            try:
                await cast("Any", self.sink).record(key_id=key_id, used_at=used_at)
            except Exception:  # noqa: BLE001 - observational sink failures cannot alter authentication
                safe_increment(self.metrics, "security.api_key.usage_failure")
            else:
                self._last_written[key_id] = used_at
            self._pending.pop(key_id, None)

    async def close(self) -> None:
        """Flush every pending observation during shutdown."""
        await self.flush(force=True)


@dataclass(slots=True)
class APIKeyService:
    """Issue, rotate, revoke, and flush API keys through atomic application ports."""

    config: APIKeyConfig
    codec: APIKeyCodec
    clock: Callable[[], datetime] = field(repr=False)
    usage: BufferedAPIKeyUsage | None = field(default=None, repr=False)

    async def issue(
        self, *, subject_id: str, restrictions: CredentialRestrictions | None = None, expires_at: datetime | None = None
    ) -> IssuedAPIKey:
        """Issue one reveal-once key and persist only its digest record.

        Args:
            subject_id: The application identity the key authenticates.
            restrictions: Optional credential authorization bounds.
            expires_at: Optional exclusive expiry.

        Returns:
            The reveal-once key.
        """
        issued, record = self.codec.issue(subject_id=subject_id, restrictions=restrictions, expires_at=expires_at)
        await _runtime_store(self.config).create(record)
        return issued

    async def rotate(
        self,
        *,
        current_key_id: str,
        subject_id: str,
        restrictions: CredentialRestrictions | None = None,
        expires_at: datetime | None = None,
        overlap: timedelta = timedelta(0),
    ) -> IssuedAPIKey:
        """Atomically replace one key with an optional bounded overlap.

        Args:
            current_key_id: The public lookup being replaced.
            subject_id: The replacement identity binding.
            restrictions: Replacement authorization bounds.
            expires_at: Replacement exclusive expiry.
            overlap: How long the current key may remain valid.

        Returns:
            The reveal-once replacement.

        Raises:
            ValueError: If overlap is negative.
        """
        if overlap.__class__ is not timedelta or overlap < timedelta(0):
            message = "API-key rotation overlap must not be negative"
            raise ValueError(message)
        now = _utc(self.clock())
        issued, replacement = self.codec.issue(subject_id=subject_id, restrictions=restrictions, expires_at=expires_at)
        await _runtime_store(self.config).rotate(
            current_key_id=current_key_id,
            replacement=replacement,
            overlap_until=now + overlap if overlap else None,
            now=now,
        )
        return issued

    async def revoke(self, key_id: str) -> None:
        """Revoke one key immediately through the atomic store operation.

        Args:
            key_id: The public lookup to revoke.
        """
        await _runtime_store(self.config).revoke(key_id=key_id, now=_utc(self.clock()))

    async def flush_usage(self) -> None:
        """Flush eligible buffered usage observations."""
        if self.usage is not None:
            await self.usage.flush()

    async def close(self) -> None:
        """Flush all pending usage observations during application shutdown."""
        if self.usage is not None:
            await self.usage.close()


@dataclass(slots=True)
class _APIKeyCredentialSlot:
    header_name: str
    maximum_value_bytes: int
    name: str = field(default=_SLOT_NAME, init=False)

    def extract(self, connection: ASGIConnection[Any, Any, Any, Any]) -> CredentialExtraction[str]:
        values = tuple(
            value
            for name, value in connection.scope["headers"]
            if name.lower() == self.header_name.lower().encode("ascii")
        )
        if not values:
            return NoCredentials()
        if len(values) != 1 or not values[0] or len(values[0]) > self.maximum_value_bytes:
            return InvalidCredentials()
        try:
            value = values[0].decode("ascii")
        except (AttributeError, UnicodeDecodeError):
            return InvalidCredentials()
        if any(
            ord(character) < _ASCII_CONTROL_LIMIT or ord(character) == _ASCII_DELETE or character.isspace()
            for character in value
        ):
            return InvalidCredentials()
        return PresentedCredential(value)


@dataclass(slots=True)
class _APIKeyAuthenticator:
    config: APIKeyConfig
    codec: APIKeyCodec
    clock: Callable[[], datetime] = field(repr=False)
    usage: BufferedAPIKeyUsage | None = field(default=None, repr=False)
    participates_by_default: bool = True
    name: str = field(default=_MECHANISM_NAME, init=False)
    slot: str = field(default=_SLOT_NAME, init=False)

    async def authenticate(
        self, credential: str, connection: ASGIConnection[Any, Any, Any, Any]
    ) -> AuthenticationOutcome[APIKeyClaims]:
        del connection
        proof = self.codec.proof(credential)
        if proof is None:
            return InvalidCredentials()
        try:
            record = await _runtime_store(self.config).get(proof.key_id)
        except Exception:  # noqa: BLE001 - application stores may raise anything; fail closed
            return VerificationUnavailable()
        if record is None or not self.codec.matches(proof, record):
            return InvalidCredentials()
        now = _utc(self.clock())
        if not record.is_valid_at(now):
            return InvalidCredentials()
        if self.usage is not None:
            self.usage.observe(record.key_id, now)
        claims = APIKeyClaims(key_id=record.key_id, subject_id=record.subject_id)
        return Authenticated(
            claims=claims,
            evidence=AuthenticationEvidence(
                mechanism=self.name,
                slot=self.slot,
                authenticated_at=now,
                expires_at=record.expires_at,
                methods=frozenset({_MECHANISM_NAME}),
            ),
            restrictions=record.restrictions,
        )


def build_api_key_runtime(  # noqa: PLR0913 - explicit runtime dependencies are independently injectable
    config: APIKeyConfig,
    resolver: IdentityResolver[APIKeyClaims, UserT],
    *,
    clock: Callable[[], datetime],
    entropy: Callable[[int], bytes],
    metrics: SecurityMetrics,
    participates_by_default: bool,
) -> tuple[CredentialSlot[str], AuthenticationMechanism[str, APIKeyClaims, UserT], APIKeyService]:
    codec = APIKeyCodec(pepper=config.pepper, prefix=config.prefix, entropy=entropy)
    usage = (
        BufferedAPIKeyUsage(
            sink=config.usage_sink,
            interval=config.usage_write_interval,
            capacity=config.usage_buffer_capacity,
            metrics=metrics,
        )
        if config.usage_sink is not None
        else None
    )
    slot = _APIKeyCredentialSlot(
        header_name=config.header_name, maximum_value_bytes=len(config.prefix) + 1 + 16 + 1 + 43
    )
    authenticator = _APIKeyAuthenticator(
        config=config, codec=codec, clock=clock, usage=usage, participates_by_default=participates_by_default
    )
    mechanism = AuthenticationMechanism(
        authenticator=authenticator,
        resolver=resolver,
        scheme_name="APIKey",
        security_scheme=SecurityScheme(type="apiKey", name=config.header_name, security_scheme_in="header"),
    )
    api_key_service = APIKeyService(config=config, codec=codec, clock=clock, usage=usage)
    return slot, mechanism, api_key_service


def _runtime_store(config: APIKeyConfig) -> APIKeyStore:
    return cast("APIKeyStore", config.store)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        message = "API-key timestamp must be timezone-aware"
        raise ValueError(message)
    return value.astimezone(timezone.utc)
