"""Strict refresh-family rotation: commands, family store contract, and service.

This is the top of the refresh stack and the only module here that talks to a
store. It depends on the token value types and the receipt sealer; nothing in this
package depends back on it.
"""

from collections.abc import Callable, Mapping
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from secrets import token_bytes
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Generic, Protocol, TypeVar, cast, runtime_checkable

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._internal import (
    DIGEST_BYTES,
    LOOKUP_BYTES,
    aware_utc_time,
    encode_random,
    strict_context_text,
    utc_now,
    valid_identifier,
    valid_security_epoch,
)
from litestar_security.accounts._operations import (
    OUTCOME_ATTEMPTED,
    OUTCOME_CREATED,
    OUTCOME_REVOKED,
    REFRESH_CREATE,
    REFRESH_PREPARE,
    REFRESH_RECEIPT,
    REFRESH_REVOKE,
    REFRESH_ROTATE,
)
from litestar_security.accounts._rate_limits import RateLimited, RateLimitGuard, validate_rate_limits
from litestar_security.accounts._receipts import RefreshReceiptContext, RefreshReceiptReplay, RefreshReceiptSealer
from litestar_security.accounts._refresh_tokens import (
    RefreshFamilyContext,
    RefreshRotationStatus,
    RefreshTokenCodec,
    RefreshTokenProof,
    RefreshTokenResponse,
    normalize_refresh_scopes,
    valid_refresh_scope,
)
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable

if TYPE_CHECKING:
    from litestar_security.accounts._access_tokens import LocalAccessTokenIssuer
    from litestar_security.accounts._records import LocalAccount, SecurityEvent

__all__ = (
    "REFRESH_RESPONSE_HEADERS",
    "CreateRefreshFamilyCommand",
    "PrepareRefreshResult",
    "RefreshTokenFamilyStore",
    "RefreshTokenService",
    "RotateRefreshCommand",
    "RotateRefreshResult",
)

UserT = TypeVar("UserT")
_REFRESH_TOKEN_PREFIX = "rt_"  # noqa: S105 - public token namespace, not a credential
_REFRESH_FAMILY_PREFIX = "rf_"
_DEFAULT_REFRESH_IDLE_LIFETIME = timedelta(days=7)
_DEFAULT_REFRESH_ABSOLUTE_LIFETIME = timedelta(days=30)
_DEFAULT_REFRESH_RECEIPT_WINDOW = timedelta(seconds=30)
_MAXIMUM_REFRESH_RECEIPT_WINDOW = timedelta(seconds=30)
_MAXIMUM_RECEIPT_BYTES = 32_768
REFRESH_RESPONSE_HEADERS: "Mapping[str, str]" = MappingProxyType({"Cache-Control": "no-store", "Pragma": "no-cache"})


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
            created_at = aware_utc_time(self.created_at)
            token_expires_at = aware_utc_time(self.token_expires_at)
            family_expires_at = aware_utc_time(self.family_expires_at)
        except (AttributeError, ValueError):
            msg = "Refresh family timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if (
            not valid_identifier(self.token_id, prefix=_REFRESH_TOKEN_PREFIX)
            or self.token_digest.__class__ is not bytes
            or len(self.token_digest) != DIGEST_BYTES
            or not strict_context_text(self.account_id)
            or not valid_identifier(self.family_id, prefix=_REFRESH_FAMILY_PREFIX)
            or not valid_security_epoch(self.security_epoch)
            or not created_at < token_expires_at <= family_expires_at
            or any(not valid_refresh_scope(scope) for scope in self.scopes)
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
            successor_expires_at = aware_utc_time(self.successor_expires_at)
            family_expires_at = aware_utc_time(self.family_expires_at)
            receipt_expires_at = aware_utc_time(self.receipt_expires_at)
        except (AttributeError, ValueError):
            msg = "Refresh rotation timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if (
            not valid_identifier(self.token_id, prefix=_REFRESH_TOKEN_PREFIX)
            or self.token_digest.__class__ is not bytes
            or len(self.token_digest) != DIGEST_BYTES
            or not strict_context_text(self.account_id)
            or not valid_identifier(self.family_id, prefix=_REFRESH_FAMILY_PREFIX)
            or not valid_security_epoch(self.security_epoch)
            or not valid_identifier(self.successor_id, prefix=_REFRESH_TOKEN_PREFIX)
            or self.successor_id == self.token_id
            or self.successor_digest.__class__ is not bytes
            or len(self.successor_digest) != DIGEST_BYTES
            or not successor_expires_at <= family_expires_at
            or receipt_expires_at > family_expires_at
            or self.sealed_receipt.__class__ is not bytes
            or not self.sealed_receipt
            or len(self.sealed_receipt) > _MAXIMUM_RECEIPT_BYTES
            or (
                self.idempotency_digest is not None
                and (self.idempotency_digest.__class__ is not bytes or len(self.idempotency_digest) != DIGEST_BYTES)
            )
            or any(not valid_refresh_scope(scope) for scope in self.scopes)
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
        """Create one family only if its account epoch is still current, atomically.

        Args:
            command: The family identifier, account binding, epoch, and first token digest.
            event: The audit event to commit with the family. Rejecting it must
                fail the creation.

        Returns:
            ``True`` when the family was created, ``False`` when the account epoch
            had already moved on.
        """
        ...  # pragma: no cover

    async def prepare_rotation(
        self, proof: RefreshTokenProof, idempotency_digest: bytes | None, *, now: "datetime", event: "SecurityEvent"
    ) -> RefreshFamilyContext | RefreshReceiptReplay | PrepareRefreshResult:
        """Atomically return active state, recover a receipt, or revoke and record consumed reuse.

        This is where reuse detection lives. A token that was already consumed
        means the token leaked, so the whole family must be revoked in the same
        operation that observes the reuse.

        Args:
            proof: The verified identifier and digest of the presented token.
            idempotency_digest: The digest of the caller's ``Idempotency-Key``, or
                ``None`` when the caller sent none.
            now: The timestamp to evaluate expiry against.
            event: The audit event to commit with the outcome. Rejecting it must
                fail the preparation.

        Returns:
            The active family context to rotate from, a stored receipt when the
            caller is retrying with a matching idempotency key, or a result
            describing why rotation cannot proceed.
        """
        ...  # pragma: no cover

    async def rotate(
        self, command: RotateRefreshCommand, *, now: "datetime", event: "SecurityEvent"
    ) -> RotateRefreshResult:
        """Atomically revalidate context/current epoch and rotate or revoke.

        Revalidate rather than trusting the prepared context: the epoch can move
        between preparation and rotation.

        Args:
            command: The family, expected prior token, replacement digest, and receipt to store.
            now: The commit timestamp.
            event: The audit event to commit with the rotation. Rejecting it must
                fail the rotation.

        Returns:
            The outcome, distinguishing a committed rotation from a revocation.
        """
        ...  # pragma: no cover

    async def revoke_family(self, family_id: str, *, event: "SecurityEvent") -> bool:
        """Revoke one refresh-token family.

        Args:
            family_id: The family to revoke.
            event: The audit event to commit with the revocation. Rejecting it
                must fail the revocation.

        Returns:
            ``True`` when an active family was revoked.
        """
        ...  # pragma: no cover

    async def revoke_token(self, token_id: str, token_digest: bytes, *, event: "SecurityEvent") -> bool:
        """Revoke the family owning one exact presented token.

        Args:
            token_id: The identifier carried by the presented token.
            token_digest: The digest that must match the stored one.
            event: The audit event to commit with the revocation. Rejecting it
                must fail the revocation.

        Returns:
            ``True`` when the digest matched and the family was revoked.
        """
        ...  # pragma: no cover

    async def revoke_token_for_account(
        self, account_id: str, token_id: str, token_digest: bytes, *, event: "SecurityEvent"
    ) -> bool:
        """Revoke one exact token only when its family belongs to the caller account.

        Check ownership inside this operation. A caller must not be able to
        revoke another account's token by presenting its identifier.

        Args:
            account_id: The authenticated caller's account.
            token_id: The identifier carried by the presented token.
            token_digest: The digest that must match the stored one.
            event: The audit event to commit with the revocation. Rejecting it
                must fail the revocation.

        Returns:
            ``True`` when the caller owned the family and it was revoked.
        """
        ...  # pragma: no cover

    async def revoke_for_account(self, account_id: str, *, event: "SecurityEvent") -> int:
        """Revoke every refresh family for an account.

        Args:
            account_id: The account whose families to revoke.
            event: The audit event to commit with the revocations. Rejecting it
                must fail them.

        Returns:
            The number of active families revoked.
        """
        ...  # pragma: no cover


def _new_refresh_family_id() -> str:
    return f"{_REFRESH_FAMILY_PREFIX}{encode_random(token_bytes(LOOKUP_BYTES))}"


def _new_refresh_event_id() -> str:
    return f"event_{encode_random(token_bytes(LOOKUP_BYTES))}"


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
    clock: Callable[[], datetime] = field(default=utc_now, repr=False, compare=False)
    family_ids: Callable[[], str] = field(default=_new_refresh_family_id, repr=False, compare=False)
    event_ids: Callable[[], str] = field(default=_new_refresh_event_id, repr=False, compare=False)
    rate_limits: RateLimitGuard | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate structural ports, lifetimes, and customization hooks."""
        validate_rate_limits(self.rate_limits, name="Refresh token service")
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
        """Create the initial family before revealing either credential.

        Args:
            account: The authenticated account to issue for. It must be active and verified.
            scopes: The scopes to bind into the access token.
            now: Override the clock, for tests and replayable issuance.

        Returns:
            The token pair, ``InvalidCredentials`` when the account may not be
            issued for, or ``VerificationUnavailable`` when a dependency failed.
        """
        from litestar_security.accounts._access_tokens import LocalAccessToken  # noqa: PLC0415 - breaks an import cycle
        from litestar_security.accounts._records import LocalAccount  # noqa: PLC0415 - breaks an import cycle

        account_value: object = account
        if (
            not isinstance(account_value, LocalAccount)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
            or not account_value.active
            or not account_value.verified
        ):
            return InvalidCredentials()
        try:
            issued_at = aware_utc_time(self.clock() if now is None else now)
            current_epoch = await cast("Any", self.accounts).current_epoch(account_value.account_id)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if not valid_security_epoch(current_epoch) or current_epoch != account_value.security_epoch:
            return InvalidCredentials()
        normalized_scopes = normalize_refresh_scopes(scopes)
        if normalized_scopes is None:
            return InvalidCredentials()
        try:
            access: object = await self.access_tokens.issue(account_value, scopes=normalized_scopes, now=issued_at)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
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
            if not valid_identifier(family_id, prefix=_REFRESH_FAMILY_PREFIX):
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
                    operation=REFRESH_CREATE,
                    outcome=OUTCOME_CREATED,
                    account_id=account_value.account_id,
                    family_id=family_id,
                ),
            )
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if created is not True:
            return VerificationUnavailable()
        return RefreshTokenResponse(
            access_token=access.access_token, refresh_token=refresh.refresh_token, expires_in=access.expires_in
        )

    async def rotate(  # noqa: C901, PLR0911, PLR0912 - security state machine remains explicit
        self,
        refresh_token: str,
        *,
        idempotency_key: str | None = None,
        now: datetime | None = None,
        client_key: str | None = None,
    ) -> RefreshTokenResponse | RateLimited | InvalidCredentials | VerificationUnavailable:
        """Return exactly the store-accepted sealed response or one safe failure.

        Only the client bucket applies: the presented value is a refresh token,
        and digesting it into a bucket key would let a limiter backend become a
        record of which tokens were attempted.

        Args:
            refresh_token: The opaque token presented by the client.
            idempotency_key: Replays a lost response instead of tripping reuse
                detection, when it matches the key sent with the original request.
            now: Override the clock, for tests and replayable rotation.
            client_key: The caller identity for the rate-limit bucket, or ``None``
                to skip client-keyed limiting.

        Returns:
            The rotated pair, ``RateLimited`` when the budget is spent,
            ``InvalidCredentials`` when the token is rejected or was reused, or
            ``VerificationUnavailable`` when a dependency failed.
        """
        from litestar_security.accounts._access_tokens import LocalAccessToken  # noqa: PLC0415 - breaks an import cycle
        from litestar_security.accounts._records import LocalAccount  # noqa: PLC0415 - breaks an import cycle

        if self.rate_limits is not None:
            limited = await self.rate_limits.check(REFRESH_ROTATE, client_key=client_key)
            if limited is not None:
                return limited
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
            rotated_at = aware_utc_time(self.clock() if now is None else now)
            prepared: object = await self.store.prepare_rotation(
                proof,
                idempotency_digest,
                now=rotated_at,
                event=self._event(
                    rotated_at, operation=REFRESH_PREPARE, outcome=OUTCOME_ATTEMPTED, account_id=None, family_id=None
                ),
            )
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
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
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
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
                    operation=REFRESH_ROTATE,
                    outcome=OUTCOME_ATTEMPTED,
                    account_id=prepared.account_id,
                    family_id=prepared.family_id,
                ),
            )
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if not isinstance(result_value, RotateRefreshResult):  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
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
        """Revoke the family owning one exact presented opaque token.

        Args:
            refresh_token: The opaque token whose family to revoke.
            now: Override the clock, for tests and replayable revocation.

        Returns:
            Whether an active family was revoked, ``InvalidCredentials`` when the
            token is rejected, or ``VerificationUnavailable`` when the store failed.
        """
        proof = self.codec.verify(refresh_token)
        if not isinstance(proof, RefreshTokenProof):
            return proof
        try:
            occurred_at = aware_utc_time(self.clock() if now is None else now)
            revoked = await self.store.revoke_token(
                proof.token_id,
                proof.digest,
                event=self._event(
                    occurred_at, operation=REFRESH_REVOKE, outcome=OUTCOME_REVOKED, account_id=None, family_id=None
                ),
            )
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        return revoked if revoked.__class__ is bool else VerificationUnavailable()

    async def revoke_for_account(
        self, account_id: str, refresh_token: str, *, now: datetime | None = None
    ) -> bool | InvalidCredentials | VerificationUnavailable:
        """Revoke one caller-owned refresh family without exposing cross-account state.

        Args:
            account_id: The authenticated caller's account.
            refresh_token: The opaque token whose family to revoke.
            now: Override the clock, for tests and replayable revocation.

        Returns:
            Whether an active family was revoked, ``InvalidCredentials`` when the
            token is rejected, or ``VerificationUnavailable`` when the store failed.
            A token owned by another account is reported as not revoked rather than
            as a distinct failure.
        """
        proof = self.codec.verify(refresh_token)
        if not strict_context_text(account_id) or not isinstance(proof, RefreshTokenProof):
            return InvalidCredentials()
        try:
            occurred_at = aware_utc_time(self.clock() if now is None else now)
            revoked = await self.store.revoke_token_for_account(
                account_id,
                proof.token_id,
                proof.digest,
                event=self._event(
                    occurred_at,
                    operation=REFRESH_REVOKE,
                    outcome=OUTCOME_REVOKED,
                    account_id=account_id,
                    family_id=None,
                ),
            )
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        return revoked if revoked.__class__ is bool else VerificationUnavailable()

    async def _resolve_account(
        self, context: RefreshFamilyContext
    ) -> "LocalAccount[UserT] | InvalidCredentials | VerificationUnavailable":
        from litestar_security.accounts._records import LocalAccount  # noqa: PLC0415 - breaks an import cycle

        try:
            account = await cast("Any", self.accounts).get_by_id(context.account_id)
            current_epoch = await cast("Any", self.accounts).current_epoch(context.account_id)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if (
            not isinstance(account, LocalAccount)
            or account.account_id != context.account_id
            or not account.active
            or not account.verified
            or account.security_epoch != context.security_epoch
            or not valid_security_epoch(current_epoch)
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
                    operation=REFRESH_RECEIPT,
                    outcome=OUTCOME_REVOKED,
                    account_id=context.account_id,
                    family_id=context.family_id,
                ),
            )
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
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
        from litestar_security.accounts._records import SecurityEvent  # noqa: PLC0415 - breaks an import cycle

        event_id = self.event_ids()
        if not strict_context_text(event_id):
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
