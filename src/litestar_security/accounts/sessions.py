"""Native-session registry and strict refresh-family contracts."""

import json
from base64 import urlsafe_b64decode, urlsafe_b64encode
from binascii import Error as BinasciiError
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
from hmac import compare_digest
from hmac import digest as hmac_digest
from logging import getLogger
from secrets import token_bytes
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Generic, Literal, Protocol, TypeVar, cast, runtime_checkable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from litestar.connection import ASGIConnection
from litestar.datastructures import Cookie
from litestar.enums import ScopeType
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.authentication import (
    Authenticated,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
    VerificationUnavailable,
    _queue_security_response_header,  # pyright: ignore[reportPrivateUsage]
)
from litestar_security.context import AuthenticationEvidence, Principal

if TYPE_CHECKING:
    from litestar.types import Scope

    from litestar_security.accounts.local import LocalAccessTokenIssuer, LocalAccount, SecurityEvent

__all__ = (
    "REFRESH_RESPONSE_HEADERS",
    "CreateRefreshFamilyCommand",
    "CreateSessionCommand",
    "NativeSessionAuth",
    "NativeSessionStore",
    "PrepareRefreshResult",
    "RefreshFamilyContext",
    "RefreshReceiptContext",
    "RefreshReceiptKey",
    "RefreshReceiptReplay",
    "RefreshReceiptSealer",
    "RefreshRotationStatus",
    "RefreshTokenCodec",
    "RefreshTokenFamilyStore",
    "RefreshTokenIssue",
    "RefreshTokenProof",
    "RefreshTokenResponse",
    "RefreshTokenService",
    "RotateRefreshCommand",
    "RotateRefreshResult",
    "SessionAuthentication",
    "SessionBindingConfig",
    "SessionBindingProof",
    "SessionRecord",
    "SessionRegistry",
    "SessionSummary",
)

UserT = TypeVar("UserT")
_EMPTY_DISPLAY_METADATA: "Mapping[str, str]" = MappingProxyType({})
_MINIMUM_PEPPER_BYTES = 32
_MAXIMUM_SECURITY_EPOCH = 9_223_372_036_854_775_807
_SESSION_AUTHENTICATION_KEY = "_litestar_security"
_SESSION_PAYLOAD_VERSION = 1
_SESSION_BINDING_PREFIX = "sb_"
_SESSION_BINDING_DOMAIN = b"session-binding\x00"
_REFRESH_TOKEN_PREFIX = "rt_"  # noqa: S105 - public token namespace, not a credential
_REFRESH_FAMILY_PREFIX = "rf_"
_REFRESH_TOKEN_DOMAIN = b"refresh-token\x00"
_REFRESH_IDEMPOTENCY_DOMAIN = b"refresh-idempotency\x00"
_REFRESH_RECEIPT_VERSION = "rr1"
_LOOKUP_BYTES = 16
_SECRET_BYTES = 32
_LOOKUP_CHARACTERS = 22
_SECRET_CHARACTERS = 43
_DIGEST_BYTES = 32
_SESSION_ID_BYTES = 32
_DEFAULT_SESSION_MAX_AGE = 60 * 60 * 24 * 14
_DEFAULT_TOUCH_INTERVAL = timedelta(minutes=5)
_MAXIMUM_DISPLAY_METADATA = 32
_MAXIMUM_DISPLAY_METADATA_ITEM_BYTES = 256
_MAXIMUM_DISPLAY_METADATA_BYTES = 4_096
_ASCII_CONTROL_LIMIT = 32
_DEFAULT_REFRESH_IDLE_LIFETIME = timedelta(days=7)
_DEFAULT_REFRESH_ABSOLUTE_LIFETIME = timedelta(days=30)
_DEFAULT_REFRESH_RECEIPT_WINDOW = timedelta(seconds=30)
_MAXIMUM_REFRESH_RECEIPT_WINDOW = timedelta(seconds=30)
_MINIMUM_IDEMPOTENCY_CHARACTERS = 22
_MAXIMUM_IDEMPOTENCY_CHARACTERS = 128
_RECEIPT_NONCE_BYTES = 12
_MAXIMUM_RECEIPT_BYTES = 32_768
_AES_256_KEY_BYTES = 32
_MAXIMUM_CONTEXT_TEXT_BYTES = 512
_MAXIMUM_ACCESS_TOKEN_BYTES = 16_384
_COMPACT_JWT_SEGMENTS = 3
_MINIMUM_ACCESS_TOKEN_SECONDS = 30
_MAXIMUM_ACCESS_TOKEN_SECONDS = 3_600
REFRESH_RESPONSE_HEADERS: "Mapping[str, str]" = MappingProxyType({"Cache-Control": "no-store", "Pragma": "no-cache"})
_LOGGER = getLogger(__name__)


def _valid_security_epoch(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAXIMUM_SECURITY_EPOCH


def _strict_text(value: object) -> bool:
    return isinstance(value, str) and value.__class__ is str and bool(value.strip())


def _strict_context_text(value: object) -> bool:
    return (
        _strict_text(value)
        and cast("str", value) == cast("str", value).strip()
        and len(cast("str", value).encode("utf-8")) <= _MAXIMUM_CONTEXT_TEXT_BYTES
        and all(ord(character) >= _ASCII_CONTROL_LIMIT for character in cast("str", value))
    )


def _valid_refresh_scope(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and all(character == "!" or "#" <= character <= "[" or "]" <= character <= "~" for character in value)
    )


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError
    return value.astimezone(timezone.utc)


def _encode_random(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_random(value: str, expected_bytes: int) -> bytes | None:
    try:
        decoded = urlsafe_b64decode(f"{value}{'=' * (-len(value) % 4)}".encode("ascii"))
    except (BinasciiError, UnicodeEncodeError, ValueError):
        return None
    return decoded if len(decoded) == expected_bytes and _encode_random(decoded) == value else None


def _valid_identifier(value: object, *, prefix: str | None = None) -> bool:
    if not _strict_text(value):
        return False
    text = cast("str", value)
    if prefix is not None and not text.startswith(prefix):
        return False
    encoded = text[len(prefix) :] if prefix is not None else text
    expected_bytes = _LOOKUP_BYTES if prefix is not None else _SESSION_ID_BYTES
    return _decode_random(encoded, expected_bytes) is not None


def _freeze_display_metadata(value: Mapping[str, str]) -> "Mapping[str, str]":
    if len(value) > _MAXIMUM_DISPLAY_METADATA:
        msg = "Session display metadata must contain bounded non-blank text"
        raise ValueError(msg)
    total_bytes = 0
    for key, item in value.items():
        if not _strict_text(key) or not _strict_text(item):
            msg = "Session display metadata must contain bounded non-blank text"
            raise ValueError(msg)
        item_bytes = len(key.encode("utf-8")) + len(item.encode("utf-8"))
        total_bytes += item_bytes
        if item_bytes > _MAXIMUM_DISPLAY_METADATA_ITEM_BYTES or total_bytes > _MAXIMUM_DISPLAY_METADATA_BYTES:
            msg = "Session display metadata must contain bounded non-blank text"
            raise ValueError(msg)
    return MappingProxyType(dict(value))


def _validate_native_session_store(value: object) -> None:
    if not isinstance(value, NativeSessionStore):
        msg = "Native session accounts must implement account, epoch, and session registry capabilities"
        raise ImproperlyConfiguredException(detail=msg)


class RefreshRotationStatus(str, Enum):
    """Atomic refresh-token rotation outcomes."""

    ROTATED = "rotated"
    IDEMPOTENT_REPLAY = "idempotent_replay"
    REPLAY_DETECTED = "replay_detected"
    EXPIRED = "expired"
    REVOKED = "revoked"
    EPOCH_MISMATCH = "epoch_mismatch"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class SessionBindingConfig:
    """Independent proof-of-possession cookie configuration."""

    pepper: bytes = field(repr=False)
    cookie_name: str = "__Host-litestar-security-binding"
    secure: bool = True
    same_site: Literal["lax", "strict", "none"] = "lax"
    path: str = "/"
    domain: str | None = None
    max_age: int = _DEFAULT_SESSION_MAX_AGE
    touch_interval: timedelta = _DEFAULT_TOUCH_INTERVAL
    preserve_session_keys: tuple[str, ...] = ()
    allow_insecure: bool = False

    def __post_init__(self) -> None:
        """Reject configurations that cannot provide the planned binding boundary."""
        if self.pepper.__class__ is not bytes or len(self.pepper) < _MINIMUM_PEPPER_BYTES:
            msg = "Session binding pepper must contain at least 32 bytes"
            raise ImproperlyConfiguredException(detail=msg)
        _validate_binding_cookie_config(self)
        _validate_binding_lifetime_config(self)
        _validate_preserved_session_keys(self.preserve_session_keys)


def _validate_binding_cookie_config(config: SessionBindingConfig) -> None:
    secure_value: object = config.secure
    allow_insecure_value: object = config.allow_insecure
    if (
        not _strict_text(config.cookie_name)
        or config.cookie_name != config.cookie_name.strip()
        or any(character in config.cookie_name for character in '()<>@,;:\\"/[]?={} \t')
    ):
        msg = "Session binding cookie name must be strict cookie-safe text"
        raise ImproperlyConfiguredException(detail=msg)
    if secure_value.__class__ is not bool:
        msg = "Session binding Secure setting must be boolean"
        raise ImproperlyConfiguredException(detail=msg)
    if config.same_site not in {"lax", "strict", "none"}:
        msg = "Session binding SameSite must be lax, strict, or none"
        raise ImproperlyConfiguredException(detail=msg)
    if allow_insecure_value.__class__ is not bool:
        msg = "Session binding insecure-development opt-in must be boolean"
        raise ImproperlyConfiguredException(detail=msg)
    if config.secure and config.allow_insecure:
        msg = "Session binding insecure-development opt-in requires an insecure cookie"
        raise ImproperlyConfiguredException(detail=msg)
    if not config.secure and not config.allow_insecure:
        msg = "Insecure session binding cookies require explicit development opt-in"
        raise ImproperlyConfiguredException(detail=msg)
    if config.same_site == "none" and not config.secure:
        msg = "Session binding SameSite=None requires Secure"
        raise ImproperlyConfiguredException(detail=msg)
    _validate_binding_cookie_scope(config)


def _validate_binding_cookie_scope(config: SessionBindingConfig) -> None:
    if config.cookie_name.startswith("__Host-") and (config.secure, config.path, config.domain) != (True, "/", None):
        msg = "__Host- session binding cookies require Secure, Path=/, and no Domain"
        raise ImproperlyConfiguredException(detail=msg)
    if (
        not _strict_text(config.path)
        or not config.path.startswith("/")
        or any(character.isspace() or ord(character) < _ASCII_CONTROL_LIMIT for character in config.path)
    ):
        msg = "Session binding cookie path must be an absolute printable path"
        raise ImproperlyConfiguredException(detail=msg)
    if config.domain is not None and (
        not _strict_text(config.domain)
        or config.domain != config.domain.strip()
        or any(character.isspace() or ord(character) < _ASCII_CONTROL_LIMIT for character in config.domain)
    ):
        msg = "Session binding cookie domain must be strict printable text"
        raise ImproperlyConfiguredException(detail=msg)


def _validate_binding_lifetime_config(config: SessionBindingConfig) -> None:
    if config.max_age.__class__ is not int or config.max_age < 1:
        msg = "Session binding maximum age must be a positive integer"
        raise ImproperlyConfiguredException(detail=msg)
    if (
        config.touch_interval.__class__ is not timedelta
        or config.touch_interval <= timedelta(0)
        or config.touch_interval > timedelta(seconds=config.max_age)
    ):
        msg = "Session touch interval must be positive and no longer than the binding lifetime"
        raise ImproperlyConfiguredException(detail=msg)


def _validate_preserved_session_keys(keys: tuple[str, ...]) -> None:
    if keys.__class__ is not tuple:
        msg = "Preserved session keys must be an immutable tuple"
        raise ImproperlyConfiguredException(detail=msg)
    if (
        len(frozenset(keys)) != len(keys)
        or _SESSION_AUTHENTICATION_KEY in keys
        or any(not _strict_text(key) for key in keys)
    ):
        msg = "Preserved session keys must be unique non-security text"
        raise ImproperlyConfiguredException(detail=msg)


@dataclass(frozen=True, slots=True)
class SessionAuthentication:
    """Authentication state stored inside the native Litestar session."""

    session_id: str
    binding_id: str
    account_id: str
    security_epoch: int
    authenticated_at: "datetime"
    expires_at: "datetime"

    def __post_init__(self) -> None:
        """Reject malformed or contradictory native authentication payloads."""
        try:
            authenticated_at = _aware_utc(self.authenticated_at)
            expires_at = _aware_utc(self.expires_at)
        except (AttributeError, ValueError):
            msg = "Session authentication timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if not _valid_security_epoch(self.security_epoch):
            msg = "Session authentication security epoch is invalid"
            raise ValueError(msg)
        if (
            not _valid_identifier(self.session_id)
            or not _valid_identifier(self.binding_id, prefix=_SESSION_BINDING_PREFIX)
            or not _strict_text(self.account_id)
            or expires_at <= authenticated_at
        ):
            msg = "Session authentication payload is invalid"
            raise ValueError(msg)
        object.__setattr__(self, "authenticated_at", authenticated_at)
        object.__setattr__(self, "expires_at", expires_at)


@dataclass(frozen=True, slots=True)
class SessionBindingProof:
    """Parsed binding lookup and domain-separated digest without the raw secret."""

    binding_id: str
    digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Require canonical binding lookup and fixed-size digest."""
        if (
            not _valid_identifier(self.binding_id, prefix=_SESSION_BINDING_PREFIX)
            or self.digest.__class__ is not bytes
            or len(self.digest) != _DIGEST_BYTES
        ):
            msg = "Session binding proof is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """Application-owned authenticated-session registry projection."""

    session_id: str
    binding_id: str
    binding_digest: bytes = field(repr=False)
    account_id: str
    security_epoch: int
    created_at: "datetime"
    last_seen_at: "datetime"
    expires_at: "datetime"
    display_metadata: "Mapping[str, str]" = field(default=_EMPTY_DISPLAY_METADATA)

    def __post_init__(self) -> None:
        """Validate authoritative record state and freeze safe display metadata."""
        try:
            created_at = _aware_utc(self.created_at)
            last_seen_at = _aware_utc(self.last_seen_at)
            expires_at = _aware_utc(self.expires_at)
        except (AttributeError, ValueError):
            msg = "Session record timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if not _valid_security_epoch(self.security_epoch):
            msg = "Session record security epoch is invalid"
            raise ValueError(msg)
        if (
            not _valid_identifier(self.session_id)
            or not _valid_identifier(self.binding_id, prefix=_SESSION_BINDING_PREFIX)
            or self.binding_digest.__class__ is not bytes
            or len(self.binding_digest) != _DIGEST_BYTES
            or not _strict_text(self.account_id)
            or not created_at <= last_seen_at < expires_at
        ):
            msg = "Session record is invalid"
            raise ValueError(msg)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "last_seen_at", last_seen_at)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "display_metadata", _freeze_display_metadata(self.display_metadata))


@dataclass(frozen=True, slots=True)
class CreateSessionCommand:
    """Candidate authenticated-session record for one atomic creation."""

    session_id: str
    binding_id: str
    binding_digest: bytes = field(repr=False)
    account_id: str
    security_epoch: int
    created_at: "datetime"
    expires_at: "datetime"
    display_metadata: "Mapping[str, str]" = field(default=_EMPTY_DISPLAY_METADATA)

    def __post_init__(self) -> None:
        """Validate atomic creation material and freeze safe display metadata."""
        try:
            created_at = _aware_utc(self.created_at)
            expires_at = _aware_utc(self.expires_at)
        except (AttributeError, ValueError):
            msg = "Session creation timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if not _valid_security_epoch(self.security_epoch):
            msg = "Session creation security epoch is invalid"
            raise ValueError(msg)
        if (
            not _valid_identifier(self.session_id)
            or not _valid_identifier(self.binding_id, prefix=_SESSION_BINDING_PREFIX)
            or self.binding_digest.__class__ is not bytes
            or len(self.binding_digest) != _DIGEST_BYTES
            or not _strict_text(self.account_id)
            or expires_at <= created_at
        ):
            msg = "Session creation command is invalid"
            raise ValueError(msg)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "display_metadata", _freeze_display_metadata(self.display_metadata))


@dataclass(frozen=True, slots=True)
class SessionSummary:
    """Safe authenticated-session inventory projection."""

    session_id: str
    current: bool
    created_at: "datetime"
    last_seen_at: "datetime"
    expires_at: "datetime"
    display_metadata: "Mapping[str, str]" = field(default=_EMPTY_DISPLAY_METADATA)

    def __post_init__(self) -> None:
        """Validate safe listing state without accepting binding material."""
        try:
            created_at = _aware_utc(self.created_at)
            last_seen_at = _aware_utc(self.last_seen_at)
            expires_at = _aware_utc(self.expires_at)
        except (AttributeError, ValueError):
            msg = "Session summary timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if (
            not _valid_identifier(self.session_id)
            or self.current.__class__ is not bool
            or not created_at <= last_seen_at < expires_at
        ):
            msg = "Session summary is invalid"
            raise ValueError(msg)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "last_seen_at", last_seen_at)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "display_metadata", _freeze_display_metadata(self.display_metadata))


@runtime_checkable
class SessionRegistry(Protocol):
    """Atomic authenticated-session inventory and revocation boundary."""

    async def create(self, command: CreateSessionCommand, *, event: "SecurityEvent") -> SessionRecord:
        """Create a registry record with its durable event."""
        ...  # pragma: no cover

    async def get(self, session_id: str) -> SessionRecord | None:
        """Load one current session record."""
        ...  # pragma: no cover

    async def list_for_account(self, account_id: str) -> "Sequence[SessionRecord]":
        """List safe session metadata for one account."""
        ...  # pragma: no cover

    async def touch(self, session_id: str, *, now: "datetime") -> SessionRecord | None:
        """Apply the implementation's bounded last-seen write policy."""
        ...  # pragma: no cover

    async def revoke_session_for_account(self, account_id: str, session_id: str, *, event: "SecurityEvent") -> bool:
        """Revoke one session only when atomically owned by the account."""
        ...  # pragma: no cover

    async def revoke_sessions_for_account(self, account_id: str, *, event: "SecurityEvent") -> int:
        """Revoke every authenticated session for an account."""
        ...  # pragma: no cover

    async def revoke_other_sessions(self, account_id: str, session_id: str, *, event: "SecurityEvent") -> int:
        """Revoke all account sessions except the named current session."""
        ...  # pragma: no cover

    async def rebind(
        self, prior_session_id: str, command: CreateSessionCommand, *, event: "SecurityEvent"
    ) -> SessionRecord | None:
        """Revoke a prior record and create its replacement atomically."""
        ...  # pragma: no cover


@runtime_checkable
class NativeSessionStore(SessionRegistry, Protocol[UserT]):
    """Combined account, epoch, and session capabilities for native authentication."""

    async def get_by_id(self, account_id: str) -> "LocalAccount[UserT] | None":
        """Load one local account projection."""
        ...  # pragma: no cover

    async def current_epoch(self, account_id: str) -> int | None:
        """Load the authoritative account security epoch."""
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class _SessionCredential:
    authentication: SessionAuthentication
    binding: SessionBindingProof


@dataclass(slots=True)
class NativeSessionAuth(Generic[UserT]):
    """Native Litestar session mechanism and fixation-resistant lifecycle service."""

    accounts: NativeSessionStore[UserT] = field(repr=False)
    binding: SessionBindingConfig = field(repr=False)
    clock: "Callable[[], datetime]" = field(default=lambda: datetime.now(timezone.utc), repr=False, compare=False)
    entropy: "Callable[[int], bytes]" = field(default=token_bytes, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=lambda: _encode_random(token_bytes(16)), repr=False, compare=False)
    name: str = field(default="session", init=False)
    slot: str = field(default="session", init=False)
    participates_by_default: bool = field(default=True, init=False)

    def __post_init__(self) -> None:
        """Validate the combined account, epoch, registry, and customization ports."""
        _validate_native_session_store(self.accounts)
        if self.binding.__class__ is not SessionBindingConfig:
            msg = "Native session binding must be SessionBindingConfig"
            raise ImproperlyConfiguredException(detail=msg)
        clock_value: object = self.clock
        entropy_value: object = self.entropy
        event_ids_value: object = self.event_ids
        if not callable(clock_value) or not callable(entropy_value) or not callable(event_ids_value):
            msg = "Native session customization hooks must be callable"
            raise ImproperlyConfiguredException(detail=msg)

    def extract(
        self, connection: ASGIConnection[Any, Any, Any, Any]
    ) -> NoCredentials | PresentedCredential[_SessionCredential] | InvalidCredentials:
        """Extract the native authentication payload and independent binding proof once."""
        session = self._session_mapping(connection.scope)
        payload = session.get(_SESSION_AUTHENTICATION_KEY) if session is not None else None
        raw_binding = connection.cookies.get(self.binding.cookie_name)
        if payload is None and raw_binding is None:
            return NoCredentials()
        authentication = self._decode_authentication(payload)
        binding = self._binding_proof(raw_binding)
        if authentication is None or binding is None:
            self._clear_local_state(connection.scope)
            return InvalidCredentials()
        return PresentedCredential(_SessionCredential(authentication=authentication, binding=binding))

    async def authenticate(
        self, credential: _SessionCredential, connection: ASGIConnection[Any, Any, Any, Any]
    ) -> Authenticated["LocalAccount[UserT]"] | InvalidCredentials | VerificationUnavailable:
        """Verify registry, binding, account, and exact epoch state."""
        if credential.__class__ is not _SessionCredential:
            self._clear_local_state(connection.scope)
            return InvalidCredentials()
        authentication = credential.authentication
        try:
            now = _aware_utc(self.clock())
            record = await self.accounts.get(authentication.session_id)
            account = await self.accounts.get_by_id(authentication.account_id)
            current_epoch = await self.accounts.current_epoch(authentication.account_id)
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if (
            record is None
            or account is None
            or not self._valid_current_state(
                authentication, credential.binding, record, account=account, current_epoch=current_epoch, now=now
            )
        ):
            self._clear_local_state(connection.scope)
            return InvalidCredentials()
        if now - record.last_seen_at >= self.binding.touch_interval:
            try:
                await self.accounts.touch(record.session_id, now=now)
            except Exception:  # noqa: BLE001
                _LOGGER.error("Session last-seen update failed")  # noqa: TRY400
        return Authenticated(
            claims=account,
            evidence=AuthenticationEvidence(
                mechanism=self.name,
                slot=self.slot,
                authenticated_at=authentication.authenticated_at,
                expires_at=authentication.expires_at,
                methods=frozenset({"password"}),
                traits=frozenset({"session"}),
                amr=("pwd",),
            ),
        )

    async def resolve(self, claims: "LocalAccount[UserT]") -> Principal[UserT]:
        """Resolve an already validated local account without another store call."""
        return Principal(id=claims.account_id, display_name=claims.display_name, user=claims.user)

    async def establish(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        account: "LocalAccount[UserT]",
        *,
        display_metadata: Mapping[str, str] = _EMPTY_DISPLAY_METADATA,
        now: datetime | None = None,
    ) -> SessionAuthentication | VerificationUnavailable:
        """Create or atomically rebind authenticated state and reveal one binding cookie."""
        session = self._writable_http_session(connection.scope)
        if session is None or not self._valid_login_account(account):
            return VerificationUnavailable()
        try:
            occurred_at = _aware_utc(self.clock() if now is None else now)
            expires_at = occurred_at + timedelta(seconds=self.binding.max_age)
            token, proof = self._issue_binding()
            command = CreateSessionCommand(
                session_id=_encode_random(self._entropy(_SESSION_ID_BYTES)),
                binding_id=proof.binding_id,
                binding_digest=proof.digest,
                account_id=account.account_id,
                security_epoch=account.security_epoch,
                created_at=occurred_at,
                expires_at=expires_at,
                display_metadata=display_metadata,
            )
            prior = self._decode_authentication(session.get(_SESSION_AUTHENTICATION_KEY))
            event = self._event(
                occurred_at,
                operation="local.session.rebind" if prior is not None else "local.session.create",
                outcome="created",
                account_id=account.account_id,
            )
            record = (
                await self.accounts.rebind(prior.session_id, command, event=event)
                if prior is not None
                else await self.accounts.create(command, event=event)
            )
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if record is None or not self._record_matches_command(record, command):
            return VerificationUnavailable()
        authentication = SessionAuthentication(
            session_id=command.session_id,
            binding_id=command.binding_id,
            account_id=command.account_id,
            security_epoch=command.security_epoch,
            authenticated_at=occurred_at,
            expires_at=expires_at,
        )
        preserved = {key: session[key] for key in self.binding.preserve_session_keys if key in session}
        session.clear()
        session.update(preserved)
        session[_SESSION_AUTHENTICATION_KEY] = self._encode_authentication(authentication)
        self._queue_binding_cookie(connection.scope, token)
        return authentication

    async def logout(
        self, connection: ASGIConnection[Any, Any, Any, Any], *, now: datetime | None = None
    ) -> bool | VerificationUnavailable:
        """Clear local browser state and atomically revoke the current account-owned record."""
        session = self._writable_http_session(connection.scope)
        if session is None:
            return VerificationUnavailable()
        authentication = self._decode_authentication(session.get(_SESSION_AUTHENTICATION_KEY))
        self._clear_local_state(connection.scope)
        if authentication is None:
            return False
        try:
            occurred_at = _aware_utc(self.clock() if now is None else now)
            return bool(
                await self.accounts.revoke_session_for_account(
                    authentication.account_id,
                    authentication.session_id,
                    event=self._event(
                        occurred_at,
                        operation="local.session.logout",
                        outcome="revoked",
                        account_id=authentication.account_id,
                    ),
                )
            )
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()

    async def revoke_session(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        account_id: str,
        session_id: str,
        *,
        now: datetime | None = None,
    ) -> bool | VerificationUnavailable:
        """Atomically revoke one caller-owned session and clear it when current."""
        session = self._writable_http_session(connection.scope)
        if session is None:
            return VerificationUnavailable()
        if not _strict_text(account_id) or not _valid_identifier(session_id):
            return False
        try:
            occurred_at = _aware_utc(self.clock() if now is None else now)
            revoked = await self.accounts.revoke_session_for_account(
                account_id,
                session_id,
                event=self._event(
                    occurred_at, operation="local.session.revoke", outcome="revoked", account_id=account_id
                ),
            )
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        authentication = self._decode_authentication(session.get(_SESSION_AUTHENTICATION_KEY))
        if authentication is not None and (authentication.account_id, authentication.session_id) == (
            account_id,
            session_id,
        ):
            self._clear_local_state(connection.scope)
        return bool(revoked)

    async def list_sessions(
        self, account_id: str, *, current_session_id: str | None = None
    ) -> tuple[SessionSummary, ...]:
        """Return only safe account-session inventory projections."""
        if not _strict_text(account_id):
            return ()
        records = await self.accounts.list_for_account(account_id)
        return tuple(
            SessionSummary(
                session_id=record.session_id,
                current=record.session_id == current_session_id,
                created_at=record.created_at,
                last_seen_at=record.last_seen_at,
                expires_at=record.expires_at,
                display_metadata=record.display_metadata,
            )
            for record in records
            if record.account_id == account_id
        )

    def _issue_binding(self) -> tuple[str, SessionBindingProof]:
        lookup = self._entropy(_LOOKUP_BYTES)
        secret = self._entropy(_SECRET_BYTES)
        if lookup.__class__ is not bytes or len(lookup) != _LOOKUP_BYTES:
            raise ValueError
        if secret.__class__ is not bytes or len(secret) != _SECRET_BYTES:
            raise ValueError
        binding_id = f"{_SESSION_BINDING_PREFIX}{_encode_random(lookup)}"
        token = f"{binding_id}.{_encode_random(secret)}"
        return token, SessionBindingProof(binding_id, self._binding_digest(binding_id, secret))

    def _binding_proof(self, token: object) -> SessionBindingProof | None:
        if (
            not isinstance(token, str)
            or token.__class__ is not str
            or len(token) != len(_SESSION_BINDING_PREFIX) + _LOOKUP_CHARACTERS + 1 + _SECRET_CHARACTERS
        ):
            return None
        binding_id, separator, encoded_secret = token.partition(".")
        secret = _decode_random(encoded_secret, _SECRET_BYTES)
        if separator != "." or not _valid_identifier(binding_id, prefix=_SESSION_BINDING_PREFIX) or secret is None:
            return None
        return SessionBindingProof(binding_id, self._binding_digest(binding_id, secret))

    def _binding_digest(self, binding_id: str, secret: bytes) -> bytes:
        return hmac_digest(self.binding.pepper, _SESSION_BINDING_DOMAIN + binding_id.encode("ascii") + secret, sha256)

    @staticmethod
    def _session_mapping(scope: "Scope") -> MutableMapping[str, object] | None:
        value = cast("Mapping[str, object]", scope).get("session")
        return cast("MutableMapping[str, object]", value) if isinstance(value, MutableMapping) else None

    @classmethod
    def _writable_http_session(cls, scope: "Scope") -> MutableMapping[str, object] | None:
        return cls._session_mapping(scope) if scope["type"] == ScopeType.HTTP else None

    @staticmethod
    def _encode_authentication(authentication: SessionAuthentication) -> dict[str, object]:
        return {
            "version": _SESSION_PAYLOAD_VERSION,
            "session_id": authentication.session_id,
            "binding_id": authentication.binding_id,
            "account_id": authentication.account_id,
            "security_epoch": authentication.security_epoch,
            "authenticated_at": authentication.authenticated_at.isoformat(),
            "expires_at": authentication.expires_at.isoformat(),
        }

    @staticmethod
    def _decode_authentication(value: object) -> SessionAuthentication | None:
        if not isinstance(value, Mapping):
            return None
        payload = cast("Mapping[str, object]", value)
        if set(payload) != {
            "version",
            "session_id",
            "binding_id",
            "account_id",
            "security_epoch",
            "authenticated_at",
            "expires_at",
        }:
            return None
        version = payload.get("version")
        if version.__class__ is not int or version != _SESSION_PAYLOAD_VERSION:
            return None
        try:
            return SessionAuthentication(
                session_id=cast("str", payload["session_id"]),
                binding_id=cast("str", payload["binding_id"]),
                account_id=cast("str", payload["account_id"]),
                security_epoch=cast("int", payload["security_epoch"]),
                authenticated_at=datetime.fromisoformat(cast("str", payload["authenticated_at"])),
                expires_at=datetime.fromisoformat(cast("str", payload["expires_at"])),
            )
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _valid_login_account(account: object) -> bool:
        return (
            _strict_text(getattr(account, "account_id", None))
            and getattr(account, "active", None) is True
            and getattr(account, "verified", None) is True
            and _valid_security_epoch(getattr(account, "security_epoch", None))
        )

    @classmethod
    def _valid_current_state(  # noqa: PLR0913
        cls,
        authentication: SessionAuthentication,
        binding: SessionBindingProof,
        record: SessionRecord,
        *,
        account: "LocalAccount[UserT]",
        current_epoch: object,
        now: datetime,
    ) -> bool:
        if record.__class__ is not SessionRecord or not cls._valid_login_account(account):
            return False
        return (
            compare_digest(binding.binding_id.encode("ascii"), record.binding_id.encode("ascii"))
            and compare_digest(binding.digest, record.binding_digest)
            and record.session_id == authentication.session_id
            and record.account_id == authentication.account_id == getattr(account, "account_id", None)
            and record.security_epoch
            == authentication.security_epoch
            == current_epoch
            == getattr(account, "security_epoch", None)
            and record.binding_id == authentication.binding_id
            and record.created_at == authentication.authenticated_at
            and record.expires_at == authentication.expires_at
            and now < authentication.expires_at
        )

    @staticmethod
    def _record_matches_command(record: SessionRecord, command: CreateSessionCommand) -> bool:
        return (
            record.__class__ is SessionRecord
            and record.session_id == command.session_id
            and record.binding_id == command.binding_id
            and compare_digest(record.binding_digest, command.binding_digest)
            and record.account_id == command.account_id
            and record.security_epoch == command.security_epoch
            and record.created_at == command.created_at
            and record.expires_at == command.expires_at
        )

    def _clear_local_state(self, scope: "Scope") -> None:
        session = self._session_mapping(scope)
        if session is not None and scope["type"] == ScopeType.HTTP:
            session.pop(_SESSION_AUTHENTICATION_KEY, None)
        if scope["type"] == ScopeType.HTTP:
            cookie = Cookie(
                key=self.binding.cookie_name,
                value="",
                max_age=0,
                expires=0,
                domain=self.binding.domain,
                path=self.binding.path,
                secure=self.binding.secure,
                httponly=True,
                samesite=self.binding.same_site,
            )
            _queue_security_response_header(scope, cookie.to_encoded_header())

    def _queue_binding_cookie(self, scope: "Scope", token: str) -> None:
        cookie = Cookie(
            key=self.binding.cookie_name,
            value=token,
            max_age=self.binding.max_age,
            domain=self.binding.domain,
            path=self.binding.path,
            secure=self.binding.secure,
            httponly=True,
            samesite=self.binding.same_site,
        )
        _queue_security_response_header(scope, cookie.to_encoded_header())

    def _entropy(self, length: int) -> bytes:
        return self.entropy(length)

    def _event(self, occurred_at: datetime, *, operation: str, outcome: str, account_id: str) -> "SecurityEvent":
        from litestar_security.accounts.local import SecurityEvent  # noqa: PLC0415

        event_id = self.event_ids()
        if not _strict_text(event_id):
            raise ValueError
        return SecurityEvent(
            event_id=event_id.strip(),
            occurred_at=occurred_at,
            operation=operation,
            outcome=outcome,
            account_id=account_id,
            mechanism=self.name,
        )


@dataclass(frozen=True, slots=True)
class RefreshTokenProof:
    """Parsed refresh-token lookup and fixed-size domain-separated digest."""

    token_id: str
    digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Validate canonical lookup and digest material."""
        if (
            not _valid_identifier(self.token_id, prefix=_REFRESH_TOKEN_PREFIX)
            or self.digest.__class__ is not bytes
            or len(self.digest) != _DIGEST_BYTES
        ):
            msg = "Refresh token proof is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RefreshTokenIssue:
    """Reveal-once opaque refresh token plus storage-safe material."""

    refresh_token: str = field(repr=False)
    token_id: str
    digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Validate reveal-once and storage-safe material agree."""
        parsed = _parse_refresh_token(self.refresh_token)
        if (
            parsed is None
            or parsed[0] != self.token_id
            or self.digest.__class__ is not bytes
            or len(self.digest) != _DIGEST_BYTES
        ):
            msg = "Refresh token issue is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RefreshTokenCodec:
    """Issue and verify opaque refresh tokens while storing only HMAC digests."""

    pepper: bytes = field(repr=False)
    entropy: Callable[[int], bytes] = field(default=token_bytes, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate pepper and entropy configuration."""
        entropy_value: object = self.entropy
        if self.pepper.__class__ is not bytes or len(self.pepper) < _MINIMUM_PEPPER_BYTES:
            msg = "Refresh token pepper must contain at least 32 bytes"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(entropy_value):
            msg = "Refresh token entropy source must be callable"
            raise ImproperlyConfiguredException(detail=msg)

    def issue(self) -> RefreshTokenIssue:
        """Create one lookup/secret pair and its storage-safe digest."""
        lookup = self.entropy(_LOOKUP_BYTES)
        secret = self.entropy(_SECRET_BYTES)
        if (
            lookup.__class__ is not bytes
            or len(lookup) != _LOOKUP_BYTES
            or secret.__class__ is not bytes
            or len(secret) != _SECRET_BYTES
        ):
            msg = "Refresh token entropy source returned invalid material"
            raise RuntimeError(msg)
        token_id = f"{_REFRESH_TOKEN_PREFIX}{_encode_random(lookup)}"
        refresh_token = f"{token_id}.{_encode_random(secret)}"
        return RefreshTokenIssue(refresh_token=refresh_token, token_id=token_id, digest=self._digest(token_id, secret))

    def verify(self, refresh_token: str) -> RefreshTokenProof | InvalidCredentials:
        """Parse one canonical token while keeping malformed work in the HMAC class."""
        parsed = _parse_refresh_token(refresh_token)
        token_id, secret = (
            parsed
            if parsed is not None
            else (f"{_REFRESH_TOKEN_PREFIX}{_encode_random(bytes(_LOOKUP_BYTES))}", bytes(_SECRET_BYTES))
        )
        digest = self._digest(token_id, secret)
        return RefreshTokenProof(token_id=token_id, digest=digest) if parsed is not None else InvalidCredentials()

    def digest_idempotency_key(self, token_id: str, value: str) -> bytes | InvalidCredentials:
        """Hash one canonical key carrying at least 128 bits of caller entropy."""
        if (
            not _valid_identifier(token_id, prefix=_REFRESH_TOKEN_PREFIX)
            or value.__class__ is not str
            or not _MINIMUM_IDEMPOTENCY_CHARACTERS <= len(value) <= _MAXIMUM_IDEMPOTENCY_CHARACTERS
        ):
            return InvalidCredentials()
        try:
            decoded = _decode_random_unbounded(value)
        except (BinasciiError, UnicodeEncodeError, ValueError):
            return InvalidCredentials()
        return hmac_digest(
            self.pepper, _REFRESH_IDEMPOTENCY_DOMAIN + token_id.encode("ascii") + b"\x00" + decoded, sha256
        )

    def _digest(self, token_id: str, secret: bytes) -> bytes:
        return hmac_digest(self.pepper, _REFRESH_TOKEN_DOMAIN + token_id.encode("ascii") + b"\x00" + secret, sha256)


def _parse_refresh_token(value: object) -> tuple[str, bytes] | None:
    if not isinstance(value, str) or value.__class__ is not str:
        return None
    token_id, separator, encoded_secret = value.partition(".")
    if (
        separator != "."
        or "." in encoded_secret
        or not _valid_identifier(token_id, prefix=_REFRESH_TOKEN_PREFIX)
        or len(encoded_secret) != _SECRET_CHARACTERS
    ):
        return None
    secret = _decode_random(encoded_secret, _SECRET_BYTES)
    return (token_id, secret) if secret is not None else None


def _valid_compact_jwt(value: object) -> bool:
    if not isinstance(value, str) or value.__class__ is not str or len(value) > _MAXIMUM_ACCESS_TOKEN_BYTES:
        return False
    segments = value.split(".")
    if len(segments) != _COMPACT_JWT_SEGMENTS or any(not segment for segment in segments):
        return False
    try:
        return all(bool(_decode_random_unbounded(segment)) for segment in segments)
    except (BinasciiError, UnicodeEncodeError, ValueError):
        return False


@dataclass(frozen=True, slots=True)
class RefreshTokenResponse:
    """Secret-safe token response recovered from a sealed rotation receipt."""

    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    expires_in: int
    token_type: Literal["Bearer"] = field(default="Bearer", init=False)

    def __post_init__(self) -> None:
        """Validate exact bearer response fields without exposing credentials."""
        if (
            not _valid_compact_jwt(self.access_token)
            or _parse_refresh_token(self.refresh_token) is None
            or self.expires_in.__class__ is not int
            or self.expires_in < _MINIMUM_ACCESS_TOKEN_SECONDS
            or self.expires_in > _MAXIMUM_ACCESS_TOKEN_SECONDS
        ):
            msg = "Refresh token response is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RefreshReceiptContext:
    """Public receipt binding values; no raw credential material is retained."""

    token_id: str
    family_id: str
    account_id: str
    security_epoch: int
    idempotency_digest: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Validate every authenticated receipt binding value."""
        if (
            not _valid_identifier(self.token_id, prefix=_REFRESH_TOKEN_PREFIX)
            or not _valid_identifier(self.family_id, prefix=_REFRESH_FAMILY_PREFIX)
            or not _strict_context_text(self.account_id)
            or not _valid_security_epoch(self.security_epoch)
            or (
                self.idempotency_digest is not None
                and (self.idempotency_digest.__class__ is not bytes or len(self.idempotency_digest) != _DIGEST_BYTES)
            )
        ):
            msg = "Refresh receipt context is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RefreshReceiptKey:
    """One AES-256-GCM receipt key selected by a non-secret key ID."""

    key_id: str
    key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Require one safe lookup ID and exact AES-256 key."""
        if (
            not _strict_context_text(self.key_id)
            or any(
                not (character.isascii() and (character.isalnum() or character in "_-")) for character in self.key_id
            )
            or self.key.__class__ is not bytes
            or len(self.key) != _AES_256_KEY_BYTES
        ):
            msg = "Refresh receipt key requires a safe ID and 32-byte key"
            raise ImproperlyConfiguredException(detail=msg)


def _require_receipt_key(value: object) -> RefreshReceiptKey:
    if not isinstance(value, RefreshReceiptKey) or value.__class__ is not RefreshReceiptKey:
        msg = "Refresh receipt keys must be RefreshReceiptKey values"
        raise ImproperlyConfiguredException(detail=msg)
    return value


@dataclass(frozen=True, slots=True)
class RefreshReceiptSealer:
    """Seal exact refresh responses with rotating AES-GCM keys and bound AAD."""

    active_key: RefreshReceiptKey = field(repr=False)
    retained_keys: tuple[RefreshReceiptKey, ...] = field(default=(), repr=False)
    entropy: Callable[[int], bytes] = field(default=token_bytes, repr=False, compare=False)
    _keys: Mapping[str, RefreshReceiptKey] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Compile active and retained receipt keys by unique ID."""
        active_key_value: object = self.active_key
        retained_values: tuple[object, ...] = tuple(self.retained_keys)
        entropy_value: object = self.entropy
        keys = (_require_receipt_key(active_key_value), *(_require_receipt_key(key) for key in retained_values))
        if len({key.key_id for key in keys}) != len(keys):
            msg = "Refresh receipt key IDs must be unique"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(entropy_value):
            msg = "Refresh receipt entropy source must be callable"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(self, "retained_keys", tuple(self.retained_keys))
        object.__setattr__(self, "_keys", MappingProxyType({key.key_id: key for key in keys}))

    def seal(self, response: RefreshTokenResponse, context: RefreshReceiptContext, *, expires_at: datetime) -> bytes:
        """Seal one exact response and authenticate all replay decision fields."""
        expiry = _receipt_expiry(expires_at)
        nonce = self.entropy(_RECEIPT_NONCE_BYTES)
        if nonce.__class__ is not bytes or len(nonce) != _RECEIPT_NONCE_BYTES:
            msg = "Refresh receipt entropy source returned an invalid nonce"
            raise RuntimeError(msg)
        plaintext = json.dumps(
            {
                "access_token": response.access_token,
                "expires_in": response.expires_in,
                "refresh_token": response.refresh_token,
                "token_type": response.token_type,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        ciphertext = AESGCM(self.active_key.key).encrypt(
            nonce, plaintext, _receipt_aad(context, expiry, self.active_key.key_id)
        )
        return ".".join((
            _REFRESH_RECEIPT_VERSION,
            self.active_key.key_id,
            str(expiry),
            _encode_random(nonce),
            _encode_random(ciphertext),
        )).encode("ascii")

    def unseal(  # noqa: PLR0911 - each malformed receipt boundary fails closed explicitly
        self, sealed_receipt: bytes, context: RefreshReceiptContext, *, now: datetime
    ) -> RefreshTokenResponse | InvalidCredentials:
        """Recover one response only while its bound receipt and key remain valid."""
        try:
            current = _aware_utc(now)
        except (AttributeError, ValueError):
            return InvalidCredentials()
        parsed = _parse_receipt_envelope(sealed_receipt)
        if parsed is None:
            return InvalidCredentials()
        key_id, expiry, nonce, ciphertext = parsed
        key = self._keys.get(key_id)
        if key is None or _timestamp_microseconds(current) >= expiry:
            return InvalidCredentials()
        try:
            plaintext = AESGCM(key.key).decrypt(nonce, ciphertext, _receipt_aad(context, expiry, key_id))
            payload_value: object = json.loads(plaintext)
            if not isinstance(payload_value, dict):
                return InvalidCredentials()
            payload = cast("Mapping[str, object]", payload_value)
            if frozenset(payload) != frozenset({"access_token", "expires_in", "refresh_token", "token_type"}):
                return InvalidCredentials()
            access_token = payload.get("access_token")
            refresh_token = payload.get("refresh_token")
            expires_in = payload.get("expires_in")
            if (
                payload.get("token_type") != "Bearer"
                or access_token.__class__ is not str
                or refresh_token.__class__ is not str
                or expires_in.__class__ is not int
            ):
                return InvalidCredentials()
            return RefreshTokenResponse(
                access_token=cast("str", access_token),  # type: ignore[redundant-cast]
                refresh_token=cast("str", refresh_token),  # type: ignore[redundant-cast]
                expires_in=cast("int", expires_in),  # type: ignore[redundant-cast]
            )
        except (InvalidTag, KeyError, TypeError, UnicodeDecodeError, ValueError):
            return InvalidCredentials()


def _receipt_expiry(value: datetime) -> int:
    try:
        normalized = _aware_utc(value)
    except (AttributeError, ValueError):
        msg = "Refresh receipt expiry must be timezone-aware"
        raise ValueError(msg) from None
    expiry = _timestamp_microseconds(normalized)
    if expiry < 1:
        msg = "Refresh receipt expiry is invalid"
        raise ValueError(msg)
    return expiry


def _timestamp_microseconds(value: datetime) -> int:
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value - epoch
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def _receipt_aad(context: RefreshReceiptContext, expiry: int, key_id: str) -> bytes:
    return json.dumps(
        {
            "account_id": context.account_id,
            "expiry": expiry,
            "family_id": context.family_id,
            "idempotency": (None if context.idempotency_digest is None else context.idempotency_digest.hex()),
            "key_id": key_id,
            "security_epoch": context.security_epoch,
            "token_id": context.token_id,
            "version": _REFRESH_RECEIPT_VERSION,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _parse_receipt_envelope(value: object) -> tuple[str, int, bytes, bytes] | None:
    if value.__class__ is not bytes:
        return None
    receipt = cast("bytes", value)  # type: ignore[redundant-cast]
    if not receipt or len(receipt) > _MAXIMUM_RECEIPT_BYTES:
        return None
    try:
        version, key_id, expiry_text, nonce_text, ciphertext_text = receipt.decode("ascii").split(".")
        if (
            version != _REFRESH_RECEIPT_VERSION
            or not _strict_context_text(key_id)
            or any(not (character.isascii() and (character.isalnum() or character in "_-")) for character in key_id)
            or not expiry_text.isascii()
            or not expiry_text.isdecimal()
            or str(expiry := int(expiry_text)) != expiry_text
        ):
            return None
        nonce = _decode_random(nonce_text, _RECEIPT_NONCE_BYTES)
        ciphertext = _decode_random_unbounded(ciphertext_text)
    except (BinasciiError, UnicodeDecodeError, UnicodeEncodeError, ValueError):
        return None
    if nonce is None or not ciphertext:
        return None
    return key_id, expiry, nonce, ciphertext


def _decode_random_unbounded(value: str) -> bytes:
    decoded = urlsafe_b64decode(f"{value}{'=' * (-len(value) % 4)}".encode("ascii"))
    if _encode_random(decoded) != value:
        raise ValueError
    return decoded


@dataclass(frozen=True, slots=True)
class RefreshFamilyContext:
    """Secret-free preflight state revalidated by the atomic rotation call."""

    account_id: str
    family_id: str
    security_epoch: int
    token_expires_at: "datetime"
    family_expires_at: "datetime"
    scopes: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        """Validate proof-checked preflight metadata and preserved scopes."""
        try:
            token_expires_at = _aware_utc(self.token_expires_at)
            family_expires_at = _aware_utc(self.family_expires_at)
        except (AttributeError, ValueError):
            msg = "Refresh family expiry must be timezone-aware"
            raise ValueError(msg) from None
        if (
            not _strict_context_text(self.account_id)
            or not _valid_identifier(self.family_id, prefix=_REFRESH_FAMILY_PREFIX)
            or not _valid_security_epoch(self.security_epoch)
            or token_expires_at > family_expires_at
            or any(not _valid_refresh_scope(scope) for scope in self.scopes)
        ):
            msg = "Refresh family context is invalid"
            raise ValueError(msg)
        object.__setattr__(self, "token_expires_at", token_expires_at)
        object.__setattr__(self, "family_expires_at", family_expires_at)
        object.__setattr__(self, "scopes", frozenset(self.scopes))


@dataclass(frozen=True, slots=True)
class RefreshReceiptReplay:
    """Proof-checked same-key replay recoverable without speculative crypto."""

    context: RefreshFamilyContext
    sealed_receipt: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Validate bounded ciphertext and exact replay context."""
        if (
            self.context.__class__ is not RefreshFamilyContext
            or self.sealed_receipt.__class__ is not bytes
            or not self.sealed_receipt
            or len(self.sealed_receipt) > _MAXIMUM_RECEIPT_BYTES
        ):
            msg = "Refresh receipt replay is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class CreateRefreshFamilyCommand:
    """Initial opaque refresh token committed atomically with its family."""

    token_id: str
    token_digest: bytes = field(repr=False)
    account_id: str
    family_id: str
    security_epoch: int
    created_at: "datetime"
    token_expires_at: "datetime"
    family_expires_at: "datetime"
    scopes: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        """Validate one complete atomic family creation candidate."""
        try:
            created_at = _aware_utc(self.created_at)
            token_expires_at = _aware_utc(self.token_expires_at)
            family_expires_at = _aware_utc(self.family_expires_at)
        except (AttributeError, ValueError):
            msg = "Refresh family timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if (
            not _valid_identifier(self.token_id, prefix=_REFRESH_TOKEN_PREFIX)
            or self.token_digest.__class__ is not bytes
            or len(self.token_digest) != _DIGEST_BYTES
            or not _strict_context_text(self.account_id)
            or not _valid_identifier(self.family_id, prefix=_REFRESH_FAMILY_PREFIX)
            or not _valid_security_epoch(self.security_epoch)
            or not created_at < token_expires_at <= family_expires_at
            or any(not _valid_refresh_scope(scope) for scope in self.scopes)
        ):
            msg = "Refresh family creation command is invalid"
            raise ValueError(msg)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "token_expires_at", token_expires_at)
        object.__setattr__(self, "family_expires_at", family_expires_at)
        object.__setattr__(self, "scopes", frozenset(self.scopes))


@dataclass(frozen=True, slots=True)
class RotateRefreshCommand:
    """Candidate one-time refresh rotation passed to an atomic store."""

    token_id: str
    token_digest: bytes = field(repr=False)
    account_id: str
    family_id: str
    security_epoch: int
    successor_id: str
    successor_digest: bytes = field(repr=False)
    successor_expires_at: "datetime"
    family_expires_at: "datetime"
    sealed_receipt: bytes = field(repr=False)
    receipt_expires_at: "datetime"
    idempotency_digest: bytes | None = field(default=None, repr=False)
    scopes: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        """Reject malformed storage material and contradictory deadlines."""
        try:
            successor_expires_at = _aware_utc(self.successor_expires_at)
            family_expires_at = _aware_utc(self.family_expires_at)
            receipt_expires_at = _aware_utc(self.receipt_expires_at)
        except (AttributeError, ValueError):
            msg = "Refresh rotation timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if (
            not _valid_identifier(self.token_id, prefix=_REFRESH_TOKEN_PREFIX)
            or self.token_digest.__class__ is not bytes
            or len(self.token_digest) != _DIGEST_BYTES
            or not _strict_context_text(self.account_id)
            or not _valid_identifier(self.family_id, prefix=_REFRESH_FAMILY_PREFIX)
            or not _valid_security_epoch(self.security_epoch)
            or not _valid_identifier(self.successor_id, prefix=_REFRESH_TOKEN_PREFIX)
            or self.successor_id == self.token_id
            or self.successor_digest.__class__ is not bytes
            or len(self.successor_digest) != _DIGEST_BYTES
            or not successor_expires_at <= family_expires_at
            or receipt_expires_at > family_expires_at
            or self.sealed_receipt.__class__ is not bytes
            or not self.sealed_receipt
            or len(self.sealed_receipt) > _MAXIMUM_RECEIPT_BYTES
            or (
                self.idempotency_digest is not None
                and (self.idempotency_digest.__class__ is not bytes or len(self.idempotency_digest) != _DIGEST_BYTES)
            )
            or any(not _valid_refresh_scope(scope) for scope in self.scopes)
        ):
            msg = "Refresh rotation command or security epoch is invalid"
            raise ValueError(msg)
        object.__setattr__(self, "successor_expires_at", successor_expires_at)
        object.__setattr__(self, "family_expires_at", family_expires_at)
        object.__setattr__(self, "receipt_expires_at", receipt_expires_at)
        object.__setattr__(self, "scopes", frozenset(self.scopes))


@dataclass(frozen=True, slots=True)
class RotateRefreshResult:
    """Atomic strict rotation, idempotent receipt, or replay outcome."""

    status: RefreshRotationStatus
    sealed_receipt: bytes | None = field(default=None, repr=False)
    family_revoked: bool = False

    def __post_init__(self) -> None:
        """Reject contradictory receipt and revocation outcomes."""
        if self.status.__class__ is not RefreshRotationStatus or self.family_revoked.__class__ is not bool:
            msg = "Refresh rotation result is invalid"
            raise ValueError(msg)
        receipt_status = self.status in {RefreshRotationStatus.ROTATED, RefreshRotationStatus.IDEMPOTENT_REPLAY}
        if (
            receipt_status != (self.sealed_receipt is not None)
            or (receipt_status and self.family_revoked)
            or (
                self.sealed_receipt is not None
                and (
                    self.sealed_receipt.__class__ is not bytes
                    or not self.sealed_receipt
                    or len(self.sealed_receipt) > _MAXIMUM_RECEIPT_BYTES
                )
            )
        ):
            msg = "Successful refresh rotation results require exactly one sealed receipt"
            raise ValueError(msg)
        revoked_status = self.status in {RefreshRotationStatus.REPLAY_DETECTED, RefreshRotationStatus.REVOKED}
        if revoked_status != self.family_revoked:
            msg = "Replay or revoked refresh results must report family revocation"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class PrepareRefreshResult:
    """Proof-checked negative preflight outcome with exact revocation evidence."""

    status: RefreshRotationStatus
    family_revoked: bool = False

    def __post_init__(self) -> None:
        """Reject success statuses and unproven revocation claims."""
        allowed = {
            RefreshRotationStatus.REPLAY_DETECTED,
            RefreshRotationStatus.EXPIRED,
            RefreshRotationStatus.REVOKED,
            RefreshRotationStatus.EPOCH_MISMATCH,
            RefreshRotationStatus.INVALID,
        }
        if self.status.__class__ is not RefreshRotationStatus or self.status not in allowed:
            msg = "Refresh preparation result requires a negative status"
            raise ValueError(msg)
        revoked_status = self.status in {RefreshRotationStatus.REPLAY_DETECTED, RefreshRotationStatus.REVOKED}
        if self.family_revoked.__class__ is not bool or revoked_status != self.family_revoked:
            msg = "Refresh preparation revocation status is invalid"
            raise ValueError(msg)


@runtime_checkable
class RefreshTokenFamilyStore(Protocol):
    """Atomic strict refresh-family rotation and revocation boundary."""

    async def create_family(self, command: CreateRefreshFamilyCommand, *, event: "SecurityEvent") -> bool:
        """Create one family only if its account epoch is still current, atomically."""
        ...  # pragma: no cover

    async def prepare_rotation(
        self, proof: RefreshTokenProof, idempotency_digest: bytes | None, *, now: "datetime", event: "SecurityEvent"
    ) -> RefreshFamilyContext | RefreshReceiptReplay | PrepareRefreshResult:
        """Atomically return active state, recover a receipt, or revoke and record consumed reuse."""
        ...  # pragma: no cover

    async def rotate(
        self, command: RotateRefreshCommand, *, now: "datetime", event: "SecurityEvent"
    ) -> RotateRefreshResult:
        """Atomically revalidate context/current epoch and rotate or revoke."""
        ...  # pragma: no cover

    async def revoke_family(self, family_id: str, *, event: "SecurityEvent") -> bool:
        """Revoke one refresh-token family."""
        ...  # pragma: no cover

    async def revoke_token(self, token_id: str, token_digest: bytes, *, event: "SecurityEvent") -> bool:
        """Revoke the family owning one exact presented token."""
        ...  # pragma: no cover

    async def revoke_for_account(self, account_id: str, *, event: "SecurityEvent") -> int:
        """Revoke every refresh family for an account."""
        ...  # pragma: no cover


def _new_refresh_family_id() -> str:
    return f"{_REFRESH_FAMILY_PREFIX}{_encode_random(token_bytes(_LOOKUP_BYTES))}"


def _new_refresh_event_id() -> str:
    return f"event_{_encode_random(token_bytes(_LOOKUP_BYTES))}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class RefreshTokenService(Generic[UserT]):
    """Issue, strictly rotate, and revoke opaque local refresh families."""

    accounts: object = field(repr=False)
    store: RefreshTokenFamilyStore = field(repr=False)
    codec: RefreshTokenCodec = field(repr=False)
    receipts: RefreshReceiptSealer = field(repr=False)
    access_tokens: "LocalAccessTokenIssuer[UserT]" = field(repr=False)
    idle_lifetime: timedelta = _DEFAULT_REFRESH_IDLE_LIFETIME
    absolute_lifetime: timedelta = _DEFAULT_REFRESH_ABSOLUTE_LIFETIME
    receipt_window: timedelta = _DEFAULT_REFRESH_RECEIPT_WINDOW
    clock: Callable[[], datetime] = field(default=_utc_now, repr=False, compare=False)
    family_ids: Callable[[], str] = field(default=_new_refresh_family_id, repr=False, compare=False)
    event_ids: Callable[[], str] = field(default=_new_refresh_event_id, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate structural ports, lifetimes, and customization hooks."""
        accounts_value = object.__getattribute__(self, "accounts")
        access_tokens_value = object.__getattribute__(self, "access_tokens")
        if not callable(getattr(accounts_value, "get_by_id", None)) or not callable(
            getattr(accounts_value, "current_epoch", None)
        ):
            msg = "Refresh token accounts must provide account and epoch lookup"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(object.__getattribute__(self, "store"), RefreshTokenFamilyStore):
            msg = "Refresh token store must implement RefreshTokenFamilyStore"
            raise ImproperlyConfiguredException(detail=msg)
        if self.codec.__class__ is not RefreshTokenCodec:
            msg = "Refresh token codec must be RefreshTokenCodec"
            raise ImproperlyConfiguredException(detail=msg)
        if self.receipts.__class__ is not RefreshReceiptSealer:
            msg = "Refresh token receipts must be RefreshReceiptSealer"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(getattr(access_tokens_value, "issue", None)):
            msg = "Refresh access-token issuer must provide issue()"
            raise ImproperlyConfiguredException(detail=msg)
        if (
            self.idle_lifetime.__class__ is not timedelta
            or self.absolute_lifetime.__class__ is not timedelta
            or self.receipt_window.__class__ is not timedelta
            or self.idle_lifetime <= timedelta(0)
            or self.absolute_lifetime < self.idle_lifetime
            or not timedelta(0) < self.receipt_window <= _MAXIMUM_REFRESH_RECEIPT_WINDOW
        ):
            msg = "Refresh token lifetimes are invalid"
            raise ImproperlyConfiguredException(detail=msg)
        if not all(callable(value) for value in (self.clock, self.family_ids, self.event_ids)):
            msg = "Refresh token clock and ID factories must be callable"
            raise ImproperlyConfiguredException(detail=msg)

    async def issue(  # noqa: PLR0911 - preserve explicit sanitized outcomes
        self, account: "LocalAccount[UserT]", *, scopes: AbstractSet[str] = frozenset(), now: datetime | None = None
    ) -> RefreshTokenResponse | InvalidCredentials | VerificationUnavailable:
        """Create the initial family before revealing either credential."""
        from litestar_security.accounts.local import LocalAccessToken, LocalAccount  # noqa: PLC0415

        account_value: object = account
        if (
            not isinstance(account_value, LocalAccount)  # pyright: ignore[reportUnnecessaryIsInstance]
            or not account_value.active
            or not account_value.verified
        ):
            return InvalidCredentials()
        try:
            issued_at = _aware_utc(self.clock() if now is None else now)
            current_epoch = await cast("Any", self.accounts).current_epoch(account_value.account_id)
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if not _valid_security_epoch(current_epoch) or current_epoch != account_value.security_epoch:
            return InvalidCredentials()
        normalized_scopes = _normalize_refresh_scopes(scopes)
        if normalized_scopes is None:
            return InvalidCredentials()
        try:
            access: object = await self.access_tokens.issue(account_value, scopes=normalized_scopes, now=issued_at)
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if not isinstance(access, LocalAccessToken):
            return (
                access
                if isinstance(  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
                    access, (InvalidCredentials, VerificationUnavailable)
                )
                else VerificationUnavailable()
            )
        try:
            refresh = self.codec.issue()
            family_id = self.family_ids()
            if not _valid_identifier(family_id, prefix=_REFRESH_FAMILY_PREFIX):
                raise ValueError  # noqa: TRY301 - customization failure is sanitized below
            family_expires_at = issued_at + self.absolute_lifetime
            token_expires_at = min(issued_at + self.idle_lifetime, family_expires_at)
            command = CreateRefreshFamilyCommand(
                token_id=refresh.token_id,
                token_digest=refresh.digest,
                account_id=account_value.account_id,
                family_id=family_id,
                security_epoch=account_value.security_epoch,
                created_at=issued_at,
                token_expires_at=token_expires_at,
                family_expires_at=family_expires_at,
                scopes=normalized_scopes,
            )
            created = await self.store.create_family(
                command,
                event=self._event(
                    issued_at,
                    operation="local.refresh.create",
                    outcome="created",
                    account_id=account_value.account_id,
                    family_id=family_id,
                ),
            )
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if created is not True:
            return VerificationUnavailable()
        return RefreshTokenResponse(
            access_token=access.access_token, refresh_token=refresh.refresh_token, expires_in=access.expires_in
        )

    async def rotate(  # noqa: C901, PLR0911, PLR0912 - security state machine remains explicit
        self, refresh_token: str, *, idempotency_key: str | None = None, now: datetime | None = None
    ) -> RefreshTokenResponse | InvalidCredentials | VerificationUnavailable:
        """Return exactly the store-accepted sealed response or one safe failure."""
        from litestar_security.accounts.local import LocalAccessToken, LocalAccount  # noqa: PLC0415

        proof = self.codec.verify(refresh_token)
        if not isinstance(proof, RefreshTokenProof):
            return proof
        idempotency_digest: bytes | None = None
        invalid_idempotency = False
        if idempotency_key is not None:
            digest_result = self.codec.digest_idempotency_key(proof.token_id, idempotency_key)
            if isinstance(digest_result, InvalidCredentials):
                invalid_idempotency = True
            else:
                idempotency_digest = digest_result
        try:
            rotated_at = _aware_utc(self.clock() if now is None else now)
            prepared: object = await self.store.prepare_rotation(
                proof,
                idempotency_digest,
                now=rotated_at,
                event=self._event(
                    rotated_at, operation="local.refresh.prepare", outcome="attempted", account_id=None, family_id=None
                ),
            )
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if isinstance(prepared, RefreshReceiptReplay):
            account_result = await self._resolve_account(prepared.context)
            if not isinstance(account_result, LocalAccount):
                return account_result
            return await self._recover_receipt(
                prepared.context,
                prepared.sealed_receipt,
                token_id=proof.token_id,
                idempotency_digest=idempotency_digest,
                occurred_at=rotated_at,
            )
        if isinstance(prepared, PrepareRefreshResult):
            return InvalidCredentials()
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
            prepared, RefreshFamilyContext
        ):
            return VerificationUnavailable()
        if invalid_idempotency:
            return InvalidCredentials()
        if prepared.token_expires_at <= rotated_at or prepared.family_expires_at <= rotated_at:
            return InvalidCredentials()
        account_result = await self._resolve_account(prepared)
        if not isinstance(account_result, LocalAccount):
            return account_result
        account = account_result
        try:
            successor = self.codec.issue()
            access: object = await self.access_tokens.issue(account, scopes=prepared.scopes, now=rotated_at)
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if not isinstance(access, LocalAccessToken):
            return (
                access
                if isinstance(  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
                    access, (InvalidCredentials, VerificationUnavailable)
                )
                else VerificationUnavailable()
            )
        response = RefreshTokenResponse(
            access_token=access.access_token, refresh_token=successor.refresh_token, expires_in=access.expires_in
        )
        successor_expires_at = min(rotated_at + self.idle_lifetime, prepared.family_expires_at)
        receipt_expires_at = min(rotated_at + self.receipt_window, prepared.family_expires_at)
        context = RefreshReceiptContext(
            token_id=proof.token_id,
            family_id=prepared.family_id,
            account_id=prepared.account_id,
            security_epoch=prepared.security_epoch,
            idempotency_digest=idempotency_digest,
        )
        try:
            sealed_receipt = self.receipts.seal(response, context, expires_at=receipt_expires_at)
            command = RotateRefreshCommand(
                token_id=proof.token_id,
                token_digest=proof.digest,
                account_id=prepared.account_id,
                family_id=prepared.family_id,
                security_epoch=prepared.security_epoch,
                successor_id=successor.token_id,
                successor_digest=successor.digest,
                successor_expires_at=successor_expires_at,
                family_expires_at=prepared.family_expires_at,
                sealed_receipt=sealed_receipt,
                receipt_expires_at=receipt_expires_at,
                idempotency_digest=idempotency_digest,
                scopes=prepared.scopes,
            )
            result_value: object = await self.store.rotate(
                command,
                now=rotated_at,
                event=self._event(
                    rotated_at,
                    operation="local.refresh.rotate",
                    outcome="attempted",
                    account_id=prepared.account_id,
                    family_id=prepared.family_id,
                ),
            )
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if not isinstance(result_value, RotateRefreshResult):  # pyright: ignore[reportUnnecessaryIsInstance]
            return VerificationUnavailable()
        result = result_value
        if result.status not in {RefreshRotationStatus.ROTATED, RefreshRotationStatus.IDEMPOTENT_REPLAY}:
            return InvalidCredentials()
        return await self._recover_receipt(
            prepared,
            cast("bytes", result.sealed_receipt),
            token_id=proof.token_id,
            idempotency_digest=idempotency_digest,
            occurred_at=rotated_at,
        )

    async def revoke(
        self, refresh_token: str, *, now: datetime | None = None
    ) -> bool | InvalidCredentials | VerificationUnavailable:
        """Revoke the family owning one exact presented opaque token."""
        proof = self.codec.verify(refresh_token)
        if not isinstance(proof, RefreshTokenProof):
            return proof
        try:
            occurred_at = _aware_utc(self.clock() if now is None else now)
            revoked = await self.store.revoke_token(
                proof.token_id,
                proof.digest,
                event=self._event(
                    occurred_at, operation="local.refresh.revoke", outcome="revoked", account_id=None, family_id=None
                ),
            )
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        return revoked if revoked.__class__ is bool else VerificationUnavailable()

    async def _resolve_account(
        self, context: RefreshFamilyContext
    ) -> "LocalAccount[UserT] | InvalidCredentials | VerificationUnavailable":
        from litestar_security.accounts.local import LocalAccount  # noqa: PLC0415

        try:
            account = await cast("Any", self.accounts).get_by_id(context.account_id)
            current_epoch = await cast("Any", self.accounts).current_epoch(context.account_id)
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if (
            not isinstance(account, LocalAccount)
            or account.account_id != context.account_id
            or not account.active
            or not account.verified
            or account.security_epoch != context.security_epoch
            or not _valid_security_epoch(current_epoch)
            or current_epoch != context.security_epoch
        ):
            return InvalidCredentials()
        return cast("LocalAccount[UserT]", account)

    async def _fail_closed_receipt(
        self, context: RefreshFamilyContext, occurred_at: datetime
    ) -> InvalidCredentials | VerificationUnavailable:
        try:
            revoked = await self.store.revoke_family(
                context.family_id,
                event=self._event(
                    occurred_at,
                    operation="local.refresh.receipt",
                    outcome="revoked",
                    account_id=context.account_id,
                    family_id=context.family_id,
                ),
            )
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        return InvalidCredentials() if revoked is True else VerificationUnavailable()

    async def _recover_receipt(
        self,
        context: RefreshFamilyContext,
        sealed_receipt: bytes,
        *,
        token_id: str,
        idempotency_digest: bytes | None,
        occurred_at: datetime,
    ) -> RefreshTokenResponse | InvalidCredentials | VerificationUnavailable:
        receipt_context = RefreshReceiptContext(
            token_id=token_id,
            family_id=context.family_id,
            account_id=context.account_id,
            security_epoch=context.security_epoch,
            idempotency_digest=idempotency_digest,
        )
        accepted = self.receipts.unseal(sealed_receipt, receipt_context, now=occurred_at)
        return (
            accepted
            if isinstance(accepted, RefreshTokenResponse)
            else await self._fail_closed_receipt(context, occurred_at)
        )

    def _event(
        self, occurred_at: datetime, *, operation: str, outcome: str, account_id: str | None, family_id: str | None
    ) -> "SecurityEvent":
        from litestar_security.accounts.local import SecurityEvent  # noqa: PLC0415

        event_id = self.event_ids()
        if not _strict_context_text(event_id):
            raise ValueError
        return SecurityEvent(
            event_id=event_id,
            occurred_at=occurred_at,
            operation=operation,
            outcome=outcome,
            account_id=account_id,
            family_id=family_id,
            mechanism="refresh",
        )


def _normalize_refresh_scopes(scopes: object) -> frozenset[str] | None:
    if not isinstance(scopes, AbstractSet):
        return None
    try:
        normalized = frozenset(cast("AbstractSet[object]", scopes))
    except TypeError:
        return None
    return cast("frozenset[str]", normalized) if all(_valid_refresh_scope(scope) for scope in normalized) else None
