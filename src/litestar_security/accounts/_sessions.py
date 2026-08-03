"""Native session records, binding proofs, and the session authentication backend.

This module owns the browser-facing half of local authentication. It reads and
writes Litestar's native session, so it never imports the refresh-token modules;
callers that need both profiles compose them at the configuration layer.
"""

from collections.abc import Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from hmac import compare_digest
from hmac import digest as hmac_digest
from logging import getLogger
from secrets import token_bytes
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Generic, Literal, Protocol, TypeVar, cast, runtime_checkable

from litestar.connection import ASGIConnection
from litestar.datastructures import Cookie
from litestar.enums import ScopeType
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._internal import (
    DIGEST_BYTES,
    LOOKUP_BYTES,
    MINIMUM_PEPPER_BYTES,
    SECRET_BYTES,
    SECRET_CHARACTERS,
    SESSION_ID_BYTES,
    aware_utc_time,
    decode_random,
    encode_random,
    strict_text,
    valid_identifier,
    valid_security_epoch,
)
from litestar_security.accounts._operations import (
    OUTCOME_CREATED,
    OUTCOME_REVOKED,
    SESSION_LOGOUT,
    SESSION_REBIND,
    SESSION_REVOKE,
)
from litestar_security.accounts._records import SecurityEvent
from litestar_security.authentication import (
    Authenticated,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
    VerificationUnavailable,
    queue_security_response_header,
)
from litestar_security.context import AuthenticationEvidence, Principal

if TYPE_CHECKING:
    from litestar.types import Scope

    from litestar_security.accounts._records import LocalAccount

__all__ = (
    "CreateSessionCommand",
    "NativeSessionAuth",
    "NativeSessionStore",
    "SessionAuthentication",
    "SessionBindingConfig",
    "SessionBindingProof",
    "SessionRebindPlan",
    "SessionRecord",
    "SessionRegistry",
    "SessionSummary",
)


UserT = TypeVar("UserT")


_EMPTY_DISPLAY_METADATA: "Mapping[str, str]" = MappingProxyType({})


_SESSION_AUTHENTICATION_KEY = "_litestar_security"


_SESSION_PAYLOAD_VERSION = 2


_SESSION_BINDING_PREFIX = "sb_"


_SESSION_BINDING_DOMAIN = b"session-binding\x00"


_LOOKUP_CHARACTERS = 22


_DEFAULT_SESSION_MAX_AGE = 60 * 60 * 24 * 14


_DEFAULT_TOUCH_INTERVAL = timedelta(minutes=5)


_MAXIMUM_DISPLAY_METADATA = 32


_MAXIMUM_DISPLAY_METADATA_ITEM_BYTES = 256


_MAXIMUM_DISPLAY_METADATA_BYTES = 4_096


_ASCII_CONTROL_LIMIT = 32


_LOGGER = getLogger(__name__)


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
        if self.pepper.__class__ is not bytes or len(self.pepper) < MINIMUM_PEPPER_BYTES:
            msg = "Session binding pepper must contain at least 32 bytes"
            raise ImproperlyConfiguredException(detail=msg)
        _validate_binding_cookie_config(self)
        _validate_binding_lifetime_config(self)
        _validate_preserved_session_keys(self.preserve_session_keys)


@dataclass(frozen=True, slots=True)
class SessionAuthentication:
    """Authentication state stored inside the native Litestar session."""

    session_id: str
    binding_id: str
    account_id: str
    security_epoch: int
    authenticated_at: "datetime"
    expires_at: "datetime"
    methods: frozenset[str] = frozenset({"password"})
    traits: frozenset[str] = frozenset({"session"})
    amr: tuple[str, ...] = ("pwd",)

    def __post_init__(self) -> None:
        """Reject malformed or contradictory native authentication payloads."""
        try:
            authenticated_at = aware_utc_time(self.authenticated_at)
            expires_at = aware_utc_time(self.expires_at)
        except (AttributeError, ValueError):
            msg = "Session authentication timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if not valid_security_epoch(self.security_epoch):
            msg = "Session authentication security epoch is invalid"
            raise ValueError(msg)
        if (
            not valid_identifier(self.session_id)
            or not valid_identifier(self.binding_id, prefix=_SESSION_BINDING_PREFIX)
            or not strict_text(self.account_id)
            or expires_at <= authenticated_at
        ):
            msg = "Session authentication payload is invalid"
            raise ValueError(msg)
        try:
            evidence = AuthenticationEvidence(
                mechanism="local",
                slot="session",
                authenticated_at=authenticated_at,
                expires_at=expires_at,
                methods=self.methods,
                traits=self.traits,
                amr=self.amr,
            )
        except (AttributeError, TypeError, ValueError):
            msg = "Session authentication assurance is invalid"
            raise ValueError(msg) from None
        object.__setattr__(self, "authenticated_at", authenticated_at)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "methods", evidence.methods)
        object.__setattr__(self, "traits", evidence.traits)
        object.__setattr__(self, "amr", evidence.amr)


@dataclass(frozen=True, slots=True)
class SessionBindingProof:
    """Parsed binding lookup and domain-separated digest without the raw secret."""

    binding_id: str
    digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Require canonical binding lookup and fixed-size digest."""
        if (
            not valid_identifier(self.binding_id, prefix=_SESSION_BINDING_PREFIX)
            or self.digest.__class__ is not bytes
            or len(self.digest) != DIGEST_BYTES
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
    display_metadata: "Mapping[str, str]" = field(default_factory=lambda: _EMPTY_DISPLAY_METADATA)

    def __post_init__(self) -> None:
        """Validate authoritative record state and freeze safe display metadata."""
        try:
            created_at = aware_utc_time(self.created_at)
            last_seen_at = aware_utc_time(self.last_seen_at)
            expires_at = aware_utc_time(self.expires_at)
        except (AttributeError, ValueError):
            msg = "Session record timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if not valid_security_epoch(self.security_epoch):
            msg = "Session record security epoch is invalid"
            raise ValueError(msg)
        if (
            not valid_identifier(self.session_id)
            or not valid_identifier(self.binding_id, prefix=_SESSION_BINDING_PREFIX)
            or self.binding_digest.__class__ is not bytes
            or len(self.binding_digest) != DIGEST_BYTES
            or not strict_text(self.account_id)
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
    display_metadata: "Mapping[str, str]" = field(default_factory=lambda: _EMPTY_DISPLAY_METADATA)

    def __post_init__(self) -> None:
        """Validate atomic creation material and freeze safe display metadata."""
        try:
            created_at = aware_utc_time(self.created_at)
            expires_at = aware_utc_time(self.expires_at)
        except (AttributeError, ValueError):
            msg = "Session creation timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if not valid_security_epoch(self.security_epoch):
            msg = "Session creation security epoch is invalid"
            raise ValueError(msg)
        if (
            not valid_identifier(self.session_id)
            or not valid_identifier(self.binding_id, prefix=_SESSION_BINDING_PREFIX)
            or self.binding_digest.__class__ is not bytes
            or len(self.binding_digest) != DIGEST_BYTES
            or not strict_text(self.account_id)
            or expires_at <= created_at
        ):
            msg = "Session creation command is invalid"
            raise ValueError(msg)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "display_metadata", _freeze_display_metadata(self.display_metadata))


@dataclass(frozen=True, slots=True)
class SessionRebindPlan:
    """Reveal-once browser state prepared for an atomic password-session rebind."""

    prior_session_id: str
    command: "CreateSessionCommand"
    binding_token: str = field(repr=False)
    authenticated_at: datetime

    def __post_init__(self) -> None:
        """Require one canonical prior identity and matching replacement material."""
        authenticated_at = aware_utc_time(self.authenticated_at)
        if (
            not valid_identifier(self.prior_session_id)
            or self.command.__class__ is not CreateSessionCommand
            or self.command.session_id == self.prior_session_id
            or self.binding_token.__class__ is not str
            or self.command.binding_id != self.binding_token.partition(".")[0]
            or self.command.created_at != authenticated_at
        ):
            msg = "Session rebind plan is invalid"
            raise ValueError(msg)
        object.__setattr__(self, "authenticated_at", authenticated_at)


@dataclass(frozen=True, slots=True)
class SessionSummary:
    """Safe authenticated-session inventory projection."""

    session_id: str
    current: bool
    created_at: "datetime"
    last_seen_at: "datetime"
    expires_at: "datetime"
    display_metadata: "Mapping[str, str]" = field(default_factory=lambda: _EMPTY_DISPLAY_METADATA)

    def __post_init__(self) -> None:
        """Validate safe listing state without accepting binding material."""
        try:
            created_at = aware_utc_time(self.created_at)
            last_seen_at = aware_utc_time(self.last_seen_at)
            expires_at = aware_utc_time(self.expires_at)
        except (AttributeError, ValueError):
            msg = "Session summary timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if (
            not valid_identifier(self.session_id)
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
        """Create a registry record with its durable event.

        Args:
            command: The session identifier, account binding, epoch, and lifetime to store.
            event: The audit event to commit with the record. Rejecting it must
                fail the creation.

        Returns:
            The stored record.
        """
        ...  # pragma: no cover

    async def get(self, session_id: str) -> SessionRecord | None:
        """Load one current session record.

        Args:
            session_id: The session to load.

        Returns:
            The record, or ``None`` when the session is absent, expired, or revoked.
        """
        ...  # pragma: no cover

    async def list_for_account(self, account_id: str) -> "Sequence[SessionRecord]":
        """List safe session metadata for one account.

        Args:
            account_id: The account whose sessions to list.

        Returns:
            The account's active session records, which may be empty.
        """
        ...  # pragma: no cover

    async def touch(self, session_id: str, *, now: "datetime") -> SessionRecord | None:
        """Apply the implementation's bounded last-seen write policy.

        Called on every authenticated request, so throttling the write is the
        implementation's decision rather than the caller's.

        Args:
            session_id: The session that was just used.
            now: The observation timestamp.

        Returns:
            The current record, or ``None`` when the session is no longer valid.
        """
        ...  # pragma: no cover

    async def revoke_session_for_account(self, account_id: str, session_id: str, *, event: "SecurityEvent") -> bool:
        """Revoke one session only when atomically owned by the account.

        Check ownership inside this operation. A caller must not be able to
        revoke another account's session by naming its identifier.

        Args:
            account_id: The authenticated caller's account.
            session_id: The session to revoke.
            event: The audit event to commit with the revocation. Rejecting it
                must fail the revocation.

        Returns:
            ``True`` when the caller owned an active session that was revoked.
        """
        ...  # pragma: no cover

    async def revoke_sessions_for_account(self, account_id: str, *, event: "SecurityEvent") -> int:
        """Revoke every authenticated session for an account.

        Args:
            account_id: The account whose sessions to revoke.
            event: The audit event to commit with the revocations. Rejecting it
                must fail them.

        Returns:
            The number of active sessions revoked.
        """
        ...  # pragma: no cover

    async def revoke_other_sessions(self, account_id: str, session_id: str, *, event: "SecurityEvent") -> int:
        """Revoke all account sessions except the named current session.

        Args:
            account_id: The account whose sessions to revoke.
            session_id: The one session to keep, normally the caller's own.
            event: The audit event to commit with the revocations. Rejecting it
                must fail them.

        Returns:
            The number of other active sessions revoked.
        """
        ...  # pragma: no cover

    async def rebind(
        self, prior_session_id: str, command: CreateSessionCommand, *, event: "SecurityEvent"
    ) -> SessionRecord | None:
        """Revoke a prior record and create its replacement atomically.

        Both halves commit together. A window in which neither or both sessions
        are valid is what session fixation exploits.

        Args:
            prior_session_id: The session being replaced.
            command: The replacement session to create.
            event: The audit event to commit with the rebind. Rejecting it must
                fail the rebind.

        Returns:
            The replacement record, or ``None`` when the prior session was already gone.
        """
        ...  # pragma: no cover


@runtime_checkable
class NativeSessionStore(SessionRegistry, Protocol[UserT]):
    """Combined account, epoch, and session capabilities for native authentication."""

    async def get_by_id(self, account_id: str) -> "LocalAccount[UserT] | None":
        """Load one local account projection.

        Args:
            account_id: The account named by the session.

        Returns:
            The account projection, or ``None`` when the account no longer exists.
        """
        ...  # pragma: no cover

    async def current_epoch(self, account_id: str) -> int | None:
        """Load the authoritative account security epoch.

        Args:
            account_id: The account whose epoch to read.

        Returns:
            The current epoch, or ``None`` when the account does not exist.
        """
        ...  # pragma: no cover


@dataclass(slots=True)
class NativeSessionAuth(Generic[UserT]):
    """Native Litestar session mechanism and fixation-resistant lifecycle service."""

    accounts: NativeSessionStore[UserT] = field(repr=False)
    binding: SessionBindingConfig = field(repr=False)
    clock: "Callable[[], datetime]" = field(default=lambda: datetime.now(timezone.utc), repr=False, compare=False)
    entropy: "Callable[[int], bytes]" = field(default=token_bytes, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=lambda: encode_random(token_bytes(16)), repr=False, compare=False)
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
    ) -> NoCredentials | PresentedCredential["_SessionCredential"] | InvalidCredentials:
        """Extract the native authentication payload and independent binding proof once.

        Args:
            connection: The incoming connection.

        Returns:
            The presented session credential, ``NoCredentials`` when the connection
            carries no session, or ``InvalidCredentials`` when what it carries is
            malformed.
        """
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
        self, credential: "_SessionCredential", connection: ASGIConnection[Any, Any, Any, Any]
    ) -> Authenticated["LocalAccount[UserT]"] | InvalidCredentials | VerificationUnavailable:
        """Verify registry, binding, account, and exact epoch state.

        Args:
            credential: The session identifier and binding proof taken from the connection.
            connection: The incoming connection.

        Returns:
            The authenticated account, ``InvalidCredentials`` when any check fails,
            or ``VerificationUnavailable`` when a dependency failed.
        """
        if credential.__class__ is not _SessionCredential:
            self._clear_local_state(connection.scope)
            return InvalidCredentials()
        authentication = credential.authentication
        try:
            now = aware_utc_time(self.clock())
            record = await self.accounts.get(authentication.session_id)
            account = await self.accounts.get_by_id(authentication.account_id)
            current_epoch = await self.accounts.current_epoch(authentication.account_id)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
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
            except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
                _LOGGER.error("Session last-seen update failed")  # noqa: TRY400 - omit untrusted exception details
        return Authenticated(
            claims=account,
            evidence=AuthenticationEvidence(
                mechanism=self.name,
                slot=self.slot,
                authenticated_at=authentication.authenticated_at,
                expires_at=authentication.expires_at,
                methods=authentication.methods,
                traits=authentication.traits,
                amr=authentication.amr,
            ),
        )

    async def resolve(self, claims: "LocalAccount[UserT]") -> Principal[UserT]:
        """Resolve an already validated local account without another store call.

        Args:
            claims: The account projection produced by authentication.

        Returns:
            The principal for the request.
        """
        return Principal(id=claims.account_id, display_name=claims.display_name, user=claims.user)

    async def establish(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        account: "LocalAccount[UserT]",
        *,
        evidence: AuthenticationEvidence | None = None,
        display_metadata: Mapping[str, str] = _EMPTY_DISPLAY_METADATA,
        now: datetime | None = None,
    ) -> SessionAuthentication | VerificationUnavailable:
        """Create or atomically rebind authenticated state and reveal one binding cookie.

        A caller that already holds a session gets a new identifier rather than
        keeping the one it arrived with, which is what defeats session fixation.

        Args:
            connection: The connection whose session state to write.
            account: The authenticated account to bind the session to.
            evidence: Verified method and trait evidence used to create the session.
            display_metadata: Application-supplied fields to show in the session list.
            now: Override the clock, for tests and replayable establishment.

        Returns:
            The established session and its reveal-once binding token, or
            ``VerificationUnavailable`` when a dependency failed.
        """
        session = self._writable_http_session(connection.scope)
        if session is None or not self._valid_login_account(account):
            return VerificationUnavailable()
        try:
            occurred_at = aware_utc_time(self.clock() if now is None else now)
            expires_at = occurred_at + timedelta(seconds=self.binding.max_age)
            token, proof = self._issue_binding()
            command = CreateSessionCommand(
                session_id=encode_random(self._entropy(SESSION_ID_BYTES)),
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
                operation=SESSION_REBIND if prior is not None else "local.session.create",
                outcome=OUTCOME_CREATED,
                account_id=account.account_id,
            )
            record = (
                await self.accounts.rebind(prior.session_id, command, event=event)
                if prior is not None
                else await self.accounts.create(command, event=event)
            )
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if record is None or not self._record_matches_command(record, command):
            return VerificationUnavailable()
        authentication = SessionAuthentication(
            session_id=command.session_id,
            binding_id=command.binding_id,
            account_id=command.account_id,
            security_epoch=command.security_epoch,
            authenticated_at=evidence.authenticated_at if evidence is not None else occurred_at,
            expires_at=expires_at,
            methods=evidence.methods if evidence is not None else frozenset({"password"}),
            traits=(evidence.traits | {"session"}) if evidence is not None else frozenset({"session"}),
            amr=evidence.amr or tuple(sorted(evidence.methods)) if evidence is not None else ("pwd",),
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
        """Clear local browser state and atomically revoke the current account-owned record.

        Args:
            connection: The connection whose session state to clear.
            now: Override the clock, for tests and replayable logout.

        Returns:
            Whether an active session was revoked, or ``VerificationUnavailable``
            when a dependency failed.
        """
        session = self._writable_http_session(connection.scope)
        if session is None:
            return VerificationUnavailable()
        authentication = self._decode_authentication(session.get(_SESSION_AUTHENTICATION_KEY))
        self._clear_local_state(connection.scope)
        if authentication is None:
            return False
        try:
            occurred_at = aware_utc_time(self.clock() if now is None else now)
            return bool(
                await self.accounts.revoke_session_for_account(
                    authentication.account_id,
                    authentication.session_id,
                    event=self._event(
                        occurred_at,
                        operation=SESSION_LOGOUT,
                        outcome=OUTCOME_REVOKED,
                        account_id=authentication.account_id,
                    ),
                )
            )
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()

    async def revoke_session(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        account_id: str,
        session_id: str,
        *,
        now: datetime | None = None,
    ) -> bool | VerificationUnavailable:
        """Atomically revoke one caller-owned session and clear it when current.

        Args:
            connection: The connection whose session state to clear if it is the target.
            account_id: The authenticated caller's account.
            session_id: The session to revoke.
            now: Override the clock, for tests and replayable revocation.

        Returns:
            Whether an active session was revoked, or ``VerificationUnavailable``
            when a dependency failed. A session owned by another account is
            reported as not revoked rather than as a distinct failure.
        """
        session = self._writable_http_session(connection.scope)
        if session is None:
            return VerificationUnavailable()
        if not strict_text(account_id) or not valid_identifier(session_id):
            return False
        try:
            occurred_at = aware_utc_time(self.clock() if now is None else now)
            revoked = await self.accounts.revoke_session_for_account(
                account_id,
                session_id,
                event=self._event(
                    occurred_at, operation=SESSION_REVOKE, outcome=OUTCOME_REVOKED, account_id=account_id
                ),
            )
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
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
        """Return only safe account-session inventory projections.

        Args:
            account_id: The account whose sessions to list.
            current_session_id: The caller's own session, flagged as current in the result.

        Returns:
            Summaries carrying no binding material, filtered to the named account.
        """
        if not strict_text(account_id):
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

    def current_authentication(self, connection: ASGIConnection[Any, Any, Any, Any]) -> SessionAuthentication | None:
        """Return the strictly decoded current local-session projection.

        Args:
            connection: The connection to read session state from.

        Returns:
            The current session projection, or ``None`` when the connection carries
            no session or a malformed one.
        """
        session = self._session_mapping(connection.scope)
        return self._decode_authentication(session.get(_SESSION_AUTHENTICATION_KEY)) if session is not None else None

    def prepare_password_rebind(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        account: "LocalAccount[UserT]",
        *,
        now: datetime | None = None,
    ) -> SessionRebindPlan | VerificationUnavailable:
        """Prepare reveal-once browser material without mutating registry or session state.

        Preparation is deliberately separate from activation: the replacement
        session must not exist until the password mutation it accompanies has
        committed.

        Args:
            connection: The connection whose session is being replaced.
            account: The account the replacement session will bind to.
            now: Override the clock, for tests and replayable preparation.

        Returns:
            The plan to hand to :meth:`activate_password_rebind`, or
            ``VerificationUnavailable`` when the caller has no usable session.
        """
        session = self._writable_http_session(connection.scope)
        current = self.current_authentication(connection)
        if (
            session is None
            or current is None
            or not self._valid_login_account(account)
            or current.account_id != account.account_id
        ):
            return VerificationUnavailable()
        try:
            occurred_at = aware_utc_time(self.clock() if now is None else now)
            binding_token, proof = self._issue_binding()
            command = CreateSessionCommand(
                session_id=encode_random(self._entropy(SESSION_ID_BYTES)),
                binding_id=proof.binding_id,
                binding_digest=proof.digest,
                account_id=account.account_id,
                security_epoch=account.security_epoch,
                created_at=occurred_at,
                expires_at=occurred_at + timedelta(seconds=self.binding.max_age),
            )
            return SessionRebindPlan(
                prior_session_id=current.session_id,
                command=command,
                binding_token=binding_token,
                authenticated_at=occurred_at,
            )
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()

    async def activate_password_rebind(
        self, connection: ASGIConnection[Any, Any, Any, Any], plan: SessionRebindPlan, security_epoch: int
    ) -> bool:
        """Activate only a replacement record already accepted by the atomic password mutation.

        Args:
            connection: The connection whose session state to rewrite.
            plan: The plan returned by :meth:`prepare_password_rebind`.
            security_epoch: The epoch the password mutation committed at.

        Returns:
            ``True`` when the replacement session became the connection's session.
        """
        session = self._writable_http_session(connection.scope)
        if session is None or plan.__class__ is not SessionRebindPlan or not valid_security_epoch(security_epoch):
            self._clear_local_state(connection.scope)
            return False
        command = replace(plan.command, security_epoch=security_epoch)
        try:
            record = await self.accounts.get(command.session_id)
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            record = None
        if record is None or not self._record_matches_command(record, command):
            self._clear_local_state(connection.scope)
            return False
        authentication = SessionAuthentication(
            session_id=command.session_id,
            binding_id=command.binding_id,
            account_id=command.account_id,
            security_epoch=command.security_epoch,
            authenticated_at=plan.authenticated_at,
            expires_at=command.expires_at,
        )
        session[_SESSION_AUTHENTICATION_KEY] = self._encode_authentication(authentication)
        self._queue_binding_cookie(connection.scope, plan.binding_token)
        return True

    def _issue_binding(self) -> tuple[str, SessionBindingProof]:
        lookup = self._entropy(LOOKUP_BYTES)
        secret = self._entropy(SECRET_BYTES)
        if lookup.__class__ is not bytes or len(lookup) != LOOKUP_BYTES:
            raise ValueError
        if secret.__class__ is not bytes or len(secret) != SECRET_BYTES:
            raise ValueError
        binding_id = f"{_SESSION_BINDING_PREFIX}{encode_random(lookup)}"
        token = f"{binding_id}.{encode_random(secret)}"
        return token, SessionBindingProof(binding_id, self._binding_digest(binding_id, secret))

    def _binding_proof(self, token: object) -> SessionBindingProof | None:
        if (
            not isinstance(token, str)
            or token.__class__ is not str
            or len(token) != len(_SESSION_BINDING_PREFIX) + _LOOKUP_CHARACTERS + 1 + SECRET_CHARACTERS
        ):
            return None
        binding_id, separator, encoded_secret = token.partition(".")
        secret = decode_random(encoded_secret, SECRET_BYTES)
        if separator != "." or not valid_identifier(binding_id, prefix=_SESSION_BINDING_PREFIX) or secret is None:
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
            "methods": sorted(authentication.methods),
            "traits": sorted(authentication.traits),
            "amr": list(authentication.amr),
        }

    @staticmethod
    def _decode_authentication(value: object) -> SessionAuthentication | None:
        if not isinstance(value, Mapping):
            return None
        payload = cast("Mapping[str, object]", value)
        legacy_keys = {
            "version",
            "session_id",
            "binding_id",
            "account_id",
            "security_epoch",
            "authenticated_at",
            "expires_at",
        }
        version = payload.get("version")
        current_keys = legacy_keys | {"methods", "traits", "amr"}
        if (version == 1 and set(payload) != legacy_keys) or (
            version == _SESSION_PAYLOAD_VERSION and set(payload) != current_keys
        ):
            return None
        if version.__class__ is not int or version not in {1, _SESSION_PAYLOAD_VERSION}:
            return None
        try:
            return SessionAuthentication(
                session_id=cast("str", payload["session_id"]),
                binding_id=cast("str", payload["binding_id"]),
                account_id=cast("str", payload["account_id"]),
                security_epoch=cast("int", payload["security_epoch"]),
                authenticated_at=datetime.fromisoformat(cast("str", payload["authenticated_at"])),
                expires_at=datetime.fromisoformat(cast("str", payload["expires_at"])),
                methods=(
                    frozenset(cast("list[str]", payload["methods"]))
                    if version == _SESSION_PAYLOAD_VERSION
                    else frozenset()
                ),
                traits=(
                    frozenset(cast("list[str]", payload["traits"]))
                    if version == _SESSION_PAYLOAD_VERSION
                    else frozenset({"session"})
                ),
                amr=(tuple(cast("list[str]", payload["amr"])) if version == _SESSION_PAYLOAD_VERSION else ()),
            )
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _valid_login_account(account: object) -> bool:
        return (
            strict_text(getattr(account, "account_id", None))
            and getattr(account, "active", None) is True
            and getattr(account, "verified", None) is True
            and valid_security_epoch(getattr(account, "security_epoch", None))
        )

    @classmethod
    def _valid_current_state(  # noqa: PLR0913 - explicit configuration surface; every input is named
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
            queue_security_response_header(scope, cookie.to_encoded_header())

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
        queue_security_response_header(scope, cookie.to_encoded_header())

    def _entropy(self, length: int) -> bytes:
        return self.entropy(length)

    def _event(self, occurred_at: datetime, *, operation: str, outcome: str, account_id: str) -> "SecurityEvent":

        event_id = self.event_ids()
        if not strict_text(event_id):
            raise ValueError
        return SecurityEvent(
            event_id=event_id.strip(),
            occurred_at=occurred_at,
            operation=operation,
            outcome=outcome,
            account_id=account_id,
            mechanism=self.name,
        )


def _freeze_display_metadata(value: Mapping[str, str]) -> "Mapping[str, str]":
    if len(value) > _MAXIMUM_DISPLAY_METADATA:
        msg = "Session display metadata must contain bounded non-blank text"
        raise ValueError(msg)
    total_bytes = 0
    for key, item in value.items():
        if not strict_text(key) or not strict_text(item):
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


def _validate_binding_cookie_config(config: SessionBindingConfig) -> None:
    secure_value: object = config.secure
    allow_insecure_value: object = config.allow_insecure
    if (
        not strict_text(config.cookie_name)
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
        not strict_text(config.path)
        or not config.path.startswith("/")
        or any(character.isspace() or ord(character) < _ASCII_CONTROL_LIMIT for character in config.path)
    ):
        msg = "Session binding cookie path must be an absolute printable path"
        raise ImproperlyConfiguredException(detail=msg)
    if config.domain is not None and (
        not strict_text(config.domain)
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
        or any(not strict_text(key) for key in keys)
    ):
        msg = "Preserved session keys must be unique non-security text"
        raise ImproperlyConfiguredException(detail=msg)


@dataclass(frozen=True, slots=True)
class _SessionCredential:
    authentication: SessionAuthentication
    binding: SessionBindingProof
