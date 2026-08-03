"""Unit tests for the framework-neutral public conformance kit."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Protocol

import pytest
from anyio import Event, Lock, fail_after

import litestar_security.testing as testing_module
from litestar_security.accounts import (
    ConsumeResult,
    ConsumeStatus,
    CreateRefreshFamilyCommand,
    CreateSessionCommand,
    LocalAccount,
    LocalAccountCapabilities,
    LoginMethod,
    NotificationCommand,
    PasswordChangeResult,
    PasswordChangeStatus,
    PasswordCredentialState,
    PasswordResetResult,
    PasswordResetStatus,
    PrepareRefreshResult,
    PurposeTokenDelivery,
    RefreshFamilyContext,
    RefreshReceiptReplay,
    RefreshRotationStatus,
    RefreshTokenFamilyStore,
    RefreshTokenProof,
    RegistrationCommand,
    RegistrationResult,
    RegistrationStatus,
    RegistrationStore,
    RevokeLoginMethodResult,
    RevokeLoginMethodStatus,
    RotateRefreshCommand,
    RotateRefreshResult,
    SecurityEvent,
    SessionRecord,
    SessionRegistry,
    TokenIssue,
)
from litestar_security.providers.api_key import APIKeyRecord, APIKeyStore
from litestar_security.testing import (
    InMemorySecurityBackend,
    StoreConformanceFactories,
    _single_winner,  # pyright: ignore[reportPrivateUsage] - T1 verifies the private contender harness directly
    assert_api_key_store_conformance,
    assert_local_account_store_conformance,
    assert_refresh_family_store_conformance,
    assert_security_backend_conformance,
    assert_session_registry_conformance,
)

_NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)
_CONFORMANCE_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


@dataclass
class _ControlledStore:
    records: dict[str, APIKeyRecord]
    persist_successor: bool = True
    revoke_current: bool = True
    rotated: bool = False

    async def get(self, key_id: str) -> APIKeyRecord | None:
        return self.records.get(key_id)

    async def create(self, record: APIKeyRecord) -> None:
        self.records[record.key_id] = record

    async def rotate(
        self, *, current_key_id: str, replacement: APIKeyRecord, overlap_until: datetime | None, now: datetime
    ) -> None:
        if self.rotated:
            raise ValueError
        self.rotated = True
        if self.revoke_current:
            self.records[current_key_id] = replace(
                self.records[current_key_id], revoked_at=now, overlap_until=overlap_until
            )
        if self.persist_successor:
            self.records[replacement.key_id] = replacement

    async def revoke(self, *, key_id: str, now: datetime) -> None:
        self.records[key_id] = replace(self.records[key_id], revoked_at=now)


class _AccountStore(LocalAccountCapabilities[object], RegistrationStore[object], Protocol):
    """Combined account-store surface used by the conformance self-tests."""


@dataclass
class _BrokenAccountStore:
    """Reference-backed store with one deliberately violated invariant at a time."""

    delegate: _AccountStore
    register_is_atomic: bool = True
    register_consumes_invitation: bool = True
    registration_partial_raises: bool = False
    password_cas_is_atomic: bool = True
    cas_persists_winner: bool = True
    cas_preserves_non_password: bool = True
    bump_epoch_is_atomic: bool = True
    bump_epoch_is_exact: bool = True
    bump_persists_winner: bool = True
    verification_is_single_use: bool = True
    verification_rejects_expired: bool = True
    verification_burns_attempts: bool = True
    recovery_checks_epoch: bool = True
    recovery_rejects_expired: bool = True
    recovery_burns_attempts: bool = True
    preserves_final_method: bool = True
    _consumed_verifications: set[str] = field(default_factory=set[str])
    _invalid_verifications: set[str] = field(default_factory=set[str])
    _invalid_recoveries: set[str] = field(default_factory=set[str])
    _cas_attempts: int = 0
    _bump_attempts: int = 0

    async def find_for_login(self, normalized_identifier: str) -> LocalAccount[object] | None:
        return await self.delegate.find_for_login(normalized_identifier)

    async def get_by_id(self, account_id: str) -> LocalAccount[object] | None:
        return await self.delegate.get_by_id(account_id)

    async def current_epoch(self, account_id: str) -> int | None:
        epoch = await self.delegate.current_epoch(account_id)
        if not self.bump_epoch_is_exact and self._bump_attempts >= 2 and epoch is not None:
            return epoch + 1
        return epoch

    async def get_password_state(self, account_id: str) -> PasswordCredentialState | None:
        state = await self.delegate.get_password_state(account_id)
        if state is None or self._cas_attempts < 2:
            return state
        if not self.cas_persists_winner:
            unpersisted_hash = "unpersisted-conformance-password"
            return replace(state, password_hash=unpersisted_hash)
        if not self.cas_preserves_non_password:
            return replace(state, active=not state.active)
        if not self.bump_persists_winner and self._bump_attempts >= 2:
            unpersisted_hash = "unpersisted-epoch-password"
            return replace(state, password_hash=unpersisted_hash)
        return state

    async def register(  # noqa: PLR0913 - mirrors the explicit public registration protocol
        self,
        command: RegistrationCommand,
        password_hash: str,
        *,
        invitation_digest: bytes | None,
        verification: PurposeTokenDelivery | None,
        now: datetime,
        event: SecurityEvent,
    ) -> RegistrationResult[object]:
        if self.registration_partial_raises and command.normalized_identifier == "partial-write@example.com":
            message = "injected partial registration failure"
            raise RuntimeError(message)
        result = await self.delegate.register(
            command, password_hash, invitation_digest=invitation_digest, verification=verification, now=now, event=event
        )
        if not self.register_is_atomic and result.status is RegistrationStatus.DUPLICATE:
            existing = await self.delegate.find_for_login(command.normalized_identifier)
            return RegistrationResult(RegistrationStatus.CREATED, existing)
        if not self.register_consumes_invitation and result.status is RegistrationStatus.DUPLICATE:
            await self.delegate.register(
                RegistrationCommand(normalized_identifier="partial-write@example.com"),
                password_hash,
                invitation_digest=invitation_digest,
                verification=verification,
                now=now,
                event=event,
            )
            return result
        return result

    async def compare_and_replace_password(
        self, account_id: str, expected_hash: str, password_hash: str, *, event: SecurityEvent
    ) -> bool:
        self._cas_attempts += 1
        result = await self.delegate.compare_and_replace_password(account_id, expected_hash, password_hash, event=event)
        return result or not self.password_cas_is_atomic

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: SecurityEvent
    ) -> PasswordChangeResult:
        self._bump_attempts += 1
        result = await self.delegate.replace_password_and_bump_epoch(
            account_id, password_hash, expected_epoch=expected_epoch, event=event
        )
        if not self.bump_epoch_is_atomic and result.status is PasswordChangeStatus.CONFLICT:
            return PasswordChangeResult(PasswordChangeStatus.CHANGED, expected_epoch + 1)
        return result

    async def register_login_method(self, account_id: str, method: LoginMethod, *, event: SecurityEvent) -> None:
        await self.delegate.register_login_method(account_id, method, event=event)

    async def consume_and_verify(
        self, token_id: str, digest: bytes, *, now: datetime, event: SecurityEvent
    ) -> ConsumeResult:
        result = await self.delegate.consume_and_verify(token_id, digest, now=now, event=event)
        if result.status is ConsumeStatus.CONSUMED:
            self._consumed_verifications.add(token_id)
        elif result.status is ConsumeStatus.INVALID:
            self._invalid_verifications.add(token_id)
        if not self.verification_rejects_expired and result.status is ConsumeStatus.EXPIRED:
            return ConsumeResult(ConsumeStatus.CONSUMED, "expired-account", 1)
        if (
            not self.verification_burns_attempts
            and result.status is ConsumeStatus.USED
            and token_id in self._invalid_verifications
        ):
            return ConsumeResult(ConsumeStatus.CONSUMED, "burned-account", 1)
        if not self.verification_is_single_use and token_id in self._consumed_verifications:
            return ConsumeResult(ConsumeStatus.CONSUMED, "replayed-account", 1)
        return result

    async def issue(self, issue: TokenIssue, notification: NotificationCommand, *, event: SecurityEvent) -> None:
        await self.delegate.issue(issue, notification, event=event)

    async def issue_absent(self) -> None:
        await self.delegate.issue_absent()

    async def consume_and_reset(
        self, token_id: str, digest: bytes, new_password_hash: str, *, now: datetime, event: SecurityEvent
    ) -> PasswordResetResult:
        result = await self.delegate.consume_and_reset(token_id, digest, new_password_hash, now=now, event=event)
        if result.status is PasswordResetStatus.INVALID:
            self._invalid_recoveries.add(token_id)
        if not self.recovery_rejects_expired and result.status is PasswordResetStatus.EXPIRED:
            return PasswordResetResult(PasswordResetStatus.RESET, "expired-account", 2)
        if (
            not self.recovery_burns_attempts
            and result.status is PasswordResetStatus.USED
            and token_id in self._invalid_recoveries
        ):
            return PasswordResetResult(PasswordResetStatus.RESET, "burned-account", 2)
        if not self.recovery_checks_epoch and result.status is PasswordResetStatus.CONFLICT:
            return PasswordResetResult(PasswordResetStatus.RESET, "stale-account", 2)
        return result

    async def revoke_login_method(
        self, account_id: str, method_id: str, *, require_remaining: bool = True, event: SecurityEvent
    ) -> RevokeLoginMethodResult:
        result = await self.delegate.revoke_login_method(
            account_id, method_id, require_remaining=require_remaining, event=event
        )
        if not self.preserves_final_method and result.status is RevokeLoginMethodStatus.FINAL_METHOD:
            return RevokeLoginMethodResult(RevokeLoginMethodStatus.REVOKED)
        return result


class _YieldingPasswordCASStore(_BrokenAccountStore):
    """Lose an update by yielding after the caller's expected hash was read."""

    def __init__(self, delegate: _AccountStore) -> None:
        super().__init__(delegate)
        self._release = Event()
        self._started = 0

    async def compare_and_replace_password(
        self, account_id: str, expected_hash: str, password_hash: str, *, event: SecurityEvent
    ) -> bool:
        snapshot = await self.delegate.get_password_state(account_id)
        if snapshot is None or snapshot.password_hash != expected_hash:
            return False
        self._started += 1
        if self._started == 2:
            self._release.set()
        await self._release.wait()
        current = await self.delegate.get_password_state(account_id)
        if current is None:
            return False
        await self.delegate.compare_and_replace_password(account_id, current.password_hash, password_hash, event=event)
        return True


class _YieldingRegistrationStore(_BrokenAccountStore):
    """Create duplicate logical identifiers after a non-atomic uniqueness read."""

    def __init__(self, delegate: _AccountStore) -> None:
        super().__init__(delegate)
        self._release = Event()
        self._started = 0

    async def register(  # noqa: PLR0913 - mirrors the explicit public registration protocol
        self,
        command: RegistrationCommand,
        password_hash: str,
        *,
        invitation_digest: bytes | None,
        verification: PurposeTokenDelivery | None,
        now: datetime,
        event: SecurityEvent,
    ) -> RegistrationResult[object]:
        if command.normalized_identifier != "atomic-registration@example.com":
            return await super().register(
                command,
                password_hash,
                invitation_digest=invitation_digest,
                verification=verification,
                now=now,
                event=event,
            )
        if await self.delegate.find_for_login(command.normalized_identifier) is not None:
            return RegistrationResult(RegistrationStatus.DUPLICATE)
        self._started += 1
        contender = self._started
        if contender == 2:
            self._release.set()
        await self._release.wait()
        storage_command = replace(command, normalized_identifier=f"{command.normalized_identifier}-{contender}")
        return await self.delegate.register(
            storage_command,
            password_hash,
            invitation_digest=invitation_digest,
            verification=verification,
            now=now,
            event=event,
        )


class _YieldingEpochBumpStore(_BrokenAccountStore):
    """Advance twice after separating the expected-epoch read from the write."""

    def __init__(self, delegate: _AccountStore) -> None:
        super().__init__(delegate)
        self._release = Event()
        self._mutation_lock = Lock()
        self._started = 0

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: SecurityEvent
    ) -> PasswordChangeResult:
        if not password_hash.startswith("conformance-epoch-"):
            return await super().replace_password_and_bump_epoch(
                account_id, password_hash, expected_epoch=expected_epoch, event=event
            )
        snapshot = await self.delegate.current_epoch(account_id)
        if snapshot != expected_epoch:
            return PasswordChangeResult(PasswordChangeStatus.CONFLICT)
        self._started += 1
        if self._started == 2:
            self._release.set()
        await self._release.wait()
        async with self._mutation_lock:
            current = await self.delegate.current_epoch(account_id)
            if current is None:
                return PasswordChangeResult(PasswordChangeStatus.NOT_FOUND)
            return await self.delegate.replace_password_and_bump_epoch(
                account_id, password_hash, expected_epoch=current, event=event
            )


@dataclass
class _BrokenSessionStore:
    """Session-registry delegate with one optional violated invariant."""

    delegate: SessionRegistry
    rebind_is_atomic: bool = True
    rebind_commits: bool = True
    checks_ownership: bool = True
    keeps_current: bool = True

    async def create(self, command: CreateSessionCommand, *, event: SecurityEvent) -> SessionRecord:
        return await self.delegate.create(command, event=event)

    async def get(self, session_id: str) -> SessionRecord | None:
        return await self.delegate.get(session_id)

    async def list_for_account(self, account_id: str) -> tuple[SessionRecord, ...]:
        return tuple(await self.delegate.list_for_account(account_id))

    async def touch(self, session_id: str, *, now: datetime) -> SessionRecord | None:
        return await self.delegate.touch(session_id, now=now)

    async def revoke_session_for_account(self, account_id: str, session_id: str, *, event: SecurityEvent) -> bool:
        if not self.checks_ownership:
            return await self.delegate.revoke_session_for_account("conformance-session-other", session_id, event=event)
        return await self.delegate.revoke_session_for_account(account_id, session_id, event=event)

    async def revoke_sessions_for_account(self, account_id: str, *, event: SecurityEvent) -> int:
        return await self.delegate.revoke_sessions_for_account(account_id, event=event)

    async def revoke_other_sessions(self, account_id: str, session_id: str, *, event: SecurityEvent) -> int:
        if not self.keeps_current:
            return 0
        return await self.delegate.revoke_other_sessions(account_id, session_id, event=event)

    async def rebind(
        self, prior_session_id: str, command: CreateSessionCommand, *, event: SecurityEvent
    ) -> SessionRecord | None:
        result = await self.delegate.rebind(prior_session_id, command, event=event)
        if not self.rebind_is_atomic and result is None:
            return await self.delegate.create(command, event=event)
        if not self.rebind_commits and result is not None:
            await self.delegate.revoke_session_for_account(command.account_id, command.session_id, event=event)
        return result


class _YieldingSessionStore(_BrokenSessionStore):
    """Split a rebind read from its write so both contenders can win."""

    def __init__(self, delegate: SessionRegistry) -> None:
        super().__init__(delegate)
        self._release = Event()
        self._started = 0

    async def rebind(
        self, prior_session_id: str, command: CreateSessionCommand, *, event: SecurityEvent
    ) -> SessionRecord | None:
        snapshot = await self.delegate.get(prior_session_id)
        if snapshot is None:
            return None
        self._started += 1
        if self._started == 2:
            self._release.set()
        await self._release.wait()
        result = await self.delegate.rebind(prior_session_id, command, event=event)
        return result if result is not None else await self.delegate.create(command, event=event)


class _RefreshRegistrationStore(RegistrationStore[object], RefreshTokenFamilyStore, Protocol):
    """Combined test-only setup surface for refresh-family conformance."""

    async def get_password_state(self, account_id: str) -> PasswordCredentialState | None:
        """Return state required to advance a registered account's epoch."""
        ...

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: SecurityEvent
    ) -> PasswordChangeResult:
        """Advance the epoch used to invalidate a prepared refresh context."""
        ...


@dataclass
class _BrokenRefreshStore:
    """Refresh-family delegate with one optional violated invariant."""

    delegate: _RefreshRegistrationStore
    create_rejects_collisions: bool = True
    rejects_expiry: bool = True
    rotate_is_atomic: bool = True
    rotate_commits: bool = True
    rotate_revalidates_epoch: bool = True
    rotate_rejects_expiry: bool = True
    idempotency_receipt: bool = True
    replays_revoke: bool = True
    checks_ownership: bool = True
    _commands: dict[str, CreateRefreshFamilyCommand] = field(default_factory=dict[str, CreateRefreshFamilyCommand])
    _rotations: dict[str, RotateRefreshCommand] = field(default_factory=dict[str, RotateRefreshCommand])

    async def register(  # noqa: PLR0913 - mirrors the public registration protocol
        self,
        command: RegistrationCommand,
        password_hash: str,
        *,
        invitation_digest: bytes | None,
        verification: PurposeTokenDelivery | None,
        now: datetime,
        event: SecurityEvent,
    ) -> RegistrationResult[object]:
        return await self.delegate.register(
            command, password_hash, invitation_digest=invitation_digest, verification=verification, now=now, event=event
        )

    async def create_family(self, command: CreateRefreshFamilyCommand, *, event: SecurityEvent) -> bool:
        result = await self.delegate.create_family(command, event=event)
        if result:
            self._commands[command.token_id] = command
        return result or not self.create_rejects_collisions

    async def get_password_state(self, account_id: str) -> PasswordCredentialState | None:
        return await self.delegate.get_password_state(account_id)

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: SecurityEvent
    ) -> PasswordChangeResult:
        return await self.delegate.replace_password_and_bump_epoch(
            account_id, password_hash, expected_epoch=expected_epoch, event=event
        )

    async def prepare_rotation(
        self, proof: RefreshTokenProof, idempotency_digest: bytes | None, *, now: datetime, event: SecurityEvent
    ) -> RefreshFamilyContext | RefreshReceiptReplay | PrepareRefreshResult:
        rotation = self._rotations.get(proof.token_id)
        if rotation is not None:
            if (
                not self.idempotency_receipt
                and rotation.token_digest == bytes((8,)) * 32
                and idempotency_digest == rotation.idempotency_digest
            ):
                return PrepareRefreshResult(RefreshRotationStatus.INVALID)
            if not self.replays_revoke and idempotency_digest != rotation.idempotency_digest:
                return PrepareRefreshResult(RefreshRotationStatus.REPLAY_DETECTED, family_revoked=True)
        result = await self.delegate.prepare_rotation(proof, idempotency_digest, now=now, event=event)
        command = self._commands.get(proof.token_id)
        if (
            not self.rejects_expiry
            and isinstance(result, PrepareRefreshResult)
            and result.status is RefreshRotationStatus.EXPIRED
        ):
            if command is None:  # pragma: no cover - controlled test setup always records the command
                return result
            return RefreshFamilyContext(
                account_id=command.account_id,
                family_id=command.family_id,
                security_epoch=command.security_epoch,
                token_expires_at=command.token_expires_at,
                family_expires_at=command.family_expires_at,
                scopes=command.scopes,
            )
        return result

    async def rotate(
        self, command: RotateRefreshCommand, *, now: datetime, event: SecurityEvent
    ) -> RotateRefreshResult:
        if not self.rotate_commits and command.successor_digest == bytes((7,)) * 32:
            return RotateRefreshResult(RefreshRotationStatus.ROTATED, command.sealed_receipt)
        source = self._commands.get(command.token_id)
        if not self.rotate_rejects_expiry and source is not None and now >= source.token_expires_at:
            return RotateRefreshResult(RefreshRotationStatus.ROTATED, command.sealed_receipt)
        result = await self.delegate.rotate(command, now=now, event=event)
        if result.status is RefreshRotationStatus.ROTATED:
            self._rotations[command.token_id] = command
        if not self.rotate_is_atomic and result.status is not RefreshRotationStatus.ROTATED:
            return RotateRefreshResult(RefreshRotationStatus.ROTATED, command.sealed_receipt)
        if (
            not self.rotate_revalidates_epoch
            and command.token_digest == bytes((13,)) * 32
            and result.status is not RefreshRotationStatus.ROTATED
        ):
            return RotateRefreshResult(RefreshRotationStatus.ROTATED, command.sealed_receipt)
        return result

    async def revoke_family(self, family_id: str, *, event: SecurityEvent) -> bool:
        return await self.delegate.revoke_family(family_id, event=event)

    async def revoke_token(self, token_id: str, token_digest: bytes, *, event: SecurityEvent) -> bool:
        return await self.delegate.revoke_token(token_id, token_digest, event=event)

    async def revoke_token_for_account(
        self, account_id: str, token_id: str, token_digest: bytes, *, event: SecurityEvent
    ) -> bool:
        if not self.checks_ownership:
            return await self.delegate.revoke_token(token_id, token_digest, event=event)
        return await self.delegate.revoke_token_for_account(account_id, token_id, token_digest, event=event)

    async def revoke_for_account(self, account_id: str, *, event: SecurityEvent) -> int:
        return await self.delegate.revoke_for_account(account_id, event=event)


@pytest.mark.anyio
async def test_single_winner_counts_only_successful_contenders() -> None:
    release = Event()
    started = 0

    def contender(*, outcome: bool) -> Callable[[], Awaitable[bool]]:
        async def attempt() -> bool:
            nonlocal started
            started += 1
            if started == 3:
                release.set()
            await release.wait()
            return outcome

        return attempt

    with fail_after(1):
        assert await _single_winner((contender(outcome=True), contender(outcome=False), contender(outcome=True))) == 2


@pytest.mark.anyio
async def test_api_key_conformance_accepts_the_reference_store_in_isolation() -> None:
    await assert_api_key_store_conformance(lambda: InMemorySecurityBackend(clock=lambda: _NOW).api_keys)


@pytest.mark.anyio
async def test_local_account_store_conformance_accepts_the_reference_store_in_isolation() -> None:
    await assert_local_account_store_conformance(lambda: InMemorySecurityBackend(clock=lambda: _NOW).accounts)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("toggle", "invariant"),
    [
        ("register_is_atomic", r"RegistrationStore\.register atomicity invariant"),
        ("register_consumes_invitation", r"RegistrationStore\.register partial-write invariant"),
        ("password_cas_is_atomic", r"PasswordCredentialStore\.compare_and_replace_password atomicity invariant"),
        ("cas_persists_winner", r"PasswordCredentialStore\.compare_and_replace_password state invariant"),
        ("cas_preserves_non_password", r"PasswordCredentialStore\.compare_and_replace_password state invariant"),
        ("bump_epoch_is_atomic", r"PasswordCredentialStore\.replace_password_and_bump_epoch epoch invariant"),
        ("bump_epoch_is_exact", r"PasswordCredentialStore\.replace_password_and_bump_epoch epoch invariant"),
        ("bump_persists_winner", r"PasswordCredentialStore\.replace_password_and_bump_epoch state invariant"),
        ("verification_is_single_use", r"VerificationTokenStore\.consume_and_verify replay invariant"),
        ("verification_rejects_expired", r"VerificationTokenStore\.consume_and_verify expiry invariant"),
        ("verification_burns_attempts", r"VerificationTokenStore\.consume_and_verify attempt invariant"),
        ("recovery_checks_epoch", r"RecoveryTokenStore\.consume_and_reset epoch invariant"),
        ("recovery_rejects_expired", r"RecoveryTokenStore\.consume_and_reset expiry invariant"),
        ("recovery_burns_attempts", r"RecoveryTokenStore\.consume_and_reset attempt invariant"),
        ("preserves_final_method", r"LoginMethodStore\.revoke_login_method final-method invariant"),
    ],
)
async def test_local_account_store_conformance_names_each_broken_invariant(toggle: str, invariant: str) -> None:
    def factory() -> _BrokenAccountStore:
        store = _BrokenAccountStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)
        setattr(store, toggle, False)
        return store

    with pytest.raises(AssertionError, match=invariant):
        await assert_local_account_store_conformance(factory)


@pytest.mark.anyio
async def test_local_account_store_conformance_names_partial_registration_exceptions() -> None:
    def factory() -> _BrokenAccountStore:
        return _BrokenAccountStore(
            InMemorySecurityBackend(clock=lambda: _NOW).accounts, registration_partial_raises=True
        )

    with pytest.raises(AssertionError, match=r"RegistrationStore\.register partial-write invariant"):
        await assert_local_account_store_conformance(factory)


@pytest.mark.anyio
async def test_local_account_store_conformance_detects_a_yielding_password_lost_update() -> None:
    def factory() -> _YieldingPasswordCASStore:
        return _YieldingPasswordCASStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)

    with pytest.raises(
        AssertionError, match=r"PasswordCredentialStore\.compare_and_replace_password atomicity invariant"
    ):
        await assert_local_account_store_conformance(factory)


@pytest.mark.anyio
async def test_local_account_store_conformance_detects_a_yielding_registration_lost_update() -> None:
    def factory() -> _YieldingRegistrationStore:
        return _YieldingRegistrationStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)

    with pytest.raises(AssertionError, match=r"RegistrationStore\.register atomicity invariant"):
        await assert_local_account_store_conformance(factory)


@pytest.mark.anyio
async def test_local_account_store_conformance_detects_a_yielding_epoch_lost_update() -> None:
    def factory() -> _YieldingEpochBumpStore:
        return _YieldingEpochBumpStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)

    with pytest.raises(
        AssertionError, match=r"PasswordCredentialStore\.replace_password_and_bump_epoch epoch invariant"
    ):
        await assert_local_account_store_conformance(factory)


@pytest.mark.anyio
async def test_local_account_store_conformance_names_shared_factory_state() -> None:
    shared = InMemorySecurityBackend(clock=lambda: _NOW).accounts

    with pytest.raises(AssertionError, match=r"LocalAccountCapabilities factory invariant"):
        await assert_local_account_store_conformance(lambda: shared)


@pytest.mark.anyio
async def test_local_account_store_conformance_detects_distinct_wrappers_over_shared_storage() -> None:
    shared = InMemorySecurityBackend(clock=lambda: _NOW).accounts

    with pytest.raises(AssertionError, match=r"LocalAccountCapabilities factory isolation invariant"):
        await assert_local_account_store_conformance(lambda: _BrokenAccountStore(shared))


@pytest.mark.anyio
async def test_api_key_conformance_names_a_non_atomic_rotation_invariant() -> None:
    @dataclass
    class BrokenStore:
        records: dict[str, APIKeyRecord]

        async def get(self, key_id: str) -> APIKeyRecord | None:
            return self.records.get(key_id)

        async def create(self, record: APIKeyRecord) -> None:
            self.records[record.key_id] = record

        async def rotate(
            self, *, current_key_id: str, replacement: APIKeyRecord, overlap_until: datetime | None, now: datetime
        ) -> None:
            del current_key_id, overlap_until, now
            self.records[replacement.key_id] = replacement

        async def revoke(self, *, key_id: str, now: datetime) -> None:
            del now
            self.records.pop(key_id, None)

    with pytest.raises(AssertionError, match=r"APIKeyStore\.rotate.*one atomic winner"):
        await assert_api_key_store_conformance(lambda: BrokenStore({}))


@pytest.mark.anyio
async def test_session_registry_conformance_accepts_the_reference_store_in_isolation() -> None:
    await assert_session_registry_conformance(
        lambda: InMemorySecurityBackend(clock=lambda: _CONFORMANCE_NOW).accounts, now=_CONFORMANCE_NOW
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("toggle", "invariant"),
    [
        ("rebind_is_atomic", r"SessionRegistry\.rebind atomicity invariant"),
        ("rebind_commits", r"SessionRegistry\.rebind partial-write invariant"),
        ("checks_ownership", r"SessionRegistry\.revoke_session_for_account ownership invariant"),
        ("keeps_current", r"SessionRegistry\.revoke_other_sessions keep-current invariant"),
    ],
)
async def test_session_registry_conformance_names_each_broken_invariant(toggle: str, invariant: str) -> None:
    def factory() -> _BrokenSessionStore:
        store = _BrokenSessionStore(InMemorySecurityBackend(clock=lambda: _CONFORMANCE_NOW).accounts)
        setattr(store, toggle, False)
        return store

    with pytest.raises(AssertionError, match=invariant):
        await assert_session_registry_conformance(factory, now=_CONFORMANCE_NOW)


@pytest.mark.anyio
async def test_session_registry_conformance_detects_a_yielding_rebind_lost_update() -> None:
    with pytest.raises(AssertionError, match=r"SessionRegistry\.rebind atomicity invariant"):
        await assert_session_registry_conformance(
            lambda: _YieldingSessionStore(InMemorySecurityBackend(clock=lambda: _CONFORMANCE_NOW).accounts),
            now=_CONFORMANCE_NOW,
        )


@pytest.mark.anyio
async def test_refresh_family_store_conformance_accepts_the_reference_store_in_isolation() -> None:
    await assert_refresh_family_store_conformance(lambda: InMemorySecurityBackend(clock=lambda: _NOW).accounts)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("toggle", "invariant"),
    [
        ("create_rejects_collisions", r"RefreshTokenFamilyStore\.create_family collision invariant"),
        ("rejects_expiry", r"RefreshTokenFamilyStore\.prepare_rotation expiry invariant"),
        ("rotate_is_atomic", r"RefreshTokenFamilyStore\.rotate atomicity invariant"),
        ("rotate_commits", r"RefreshTokenFamilyStore\.rotate partial-write invariant"),
        ("rotate_rejects_expiry", r"RefreshTokenFamilyStore\.rotate late-expiry invariant"),
        ("rotate_revalidates_epoch", r"RefreshTokenFamilyStore\.rotate epoch invariant"),
        ("idempotency_receipt", r"RefreshTokenFamilyStore\.prepare_rotation idempotency invariant"),
        ("replays_revoke", r"RefreshTokenFamilyStore\.prepare_rotation replay invariant"),
        ("checks_ownership", r"RefreshTokenFamilyStore\.revoke_token_for_account ownership invariant"),
    ],
)
async def test_refresh_family_store_conformance_names_each_broken_invariant(toggle: str, invariant: str) -> None:
    def factory() -> _BrokenRefreshStore:
        store = _BrokenRefreshStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)
        setattr(store, toggle, False)
        return store

    with pytest.raises(AssertionError, match=invariant):
        await assert_refresh_family_store_conformance(factory)


@pytest.mark.anyio
async def test_aggregate_conformance_runs_only_supplied_feature_factories() -> None:
    calls: list[str] = []

    def api_keys() -> APIKeyStore:
        calls.append("api-key")
        return InMemorySecurityBackend(clock=lambda: _NOW).api_keys

    await assert_security_backend_conformance(StoreConformanceFactories(api_key_store=api_keys))

    assert calls
    assert set(calls) == {"api-key"}


def test_conformance_factories_are_frozen_and_slotted() -> None:
    factories = StoreConformanceFactories()

    with pytest.raises((AttributeError, TypeError)):
        factories.extra = lambda: None  # type: ignore[attr-defined]


def test_testing_surface_is_explicit_and_stable() -> None:
    assert testing_module.__all__ == (
        "BackendBarrier",
        "BackendEvent",
        "FakeClock",
        "FakeOAuthHTTPTransport",
        "FakeOAuthProvider",
        "InMemoryAPIKeyStore",
        "InMemoryLocalAccountStore",
        "InMemoryMFALoginChallengeStore",
        "InMemoryMFAStore",
        "InMemoryPasskeyStore",
        "InMemorySecurityBackend",
        "InMemoryStepUpStore",
        "InMemoryWebAuthnChallengeStore",
        "MemoryOAuthAccountStore",
        "MemoryOAuthTransactionStore",
        "MemoryTokenVault",
        "OAuthHTTPRequest",
        "StoreConformanceFactories",
        "assert_api_key_store_conformance",
        "assert_local_account_store_conformance",
        "assert_refresh_family_store_conformance",
        "assert_security_backend_conformance",
        "assert_session_registry_conformance",
    )


@pytest.mark.anyio
async def test_conformance_detects_shared_factory_state() -> None:
    shared = _ControlledStore({})

    with pytest.raises(AssertionError, match="factory invariant"):
        await assert_api_key_store_conformance(lambda: shared)


@pytest.mark.anyio
async def test_conformance_detects_non_isolated_factory_storage() -> None:
    shared_records: dict[str, APIKeyRecord] = {}

    with pytest.raises(AssertionError, match="create/get isolation invariant"):
        await assert_api_key_store_conformance(lambda: _ControlledStore(shared_records))


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("persist_successor", "revoke_current", "invariant"),
    [(False, True, "partial-write invariant"), (True, False, "current-state invariant")],
)
async def test_conformance_detects_partial_rotation_states(
    persist_successor: bool,  # noqa: FBT001 - parametrized broken-store control
    revoke_current: bool,  # noqa: FBT001 - parametrized broken-store control
    invariant: str,
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_api_key_store_conformance(
            lambda: _ControlledStore({}, persist_successor=persist_successor, revoke_current=revoke_current)
        )


@pytest.mark.anyio
async def test_empty_aggregate_conformance_requires_no_unrelated_store() -> None:
    await assert_security_backend_conformance(StoreConformanceFactories())
