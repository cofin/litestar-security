"""Deliberately non-conforming account stores used by conformance tests."""

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Protocol

from anyio import Event, Lock
from anyio.lowlevel import checkpoint

import litestar_security.testing as testing_module
from litestar_security.accounts import (
    CreateRefreshFamilyCommand,
    CreateSessionCommand,
    LocalAccountCapabilities,
    LocalAccountState,
    LoginMethod,
    MFALoginChallenge,
    NotificationCommand,
    PasskeyAssertionStatus,
    PasskeyCredential,
    PasswordChangeOutcome,
    PasswordChangeStatus,
    PasswordCredentialState,
    PasswordResetOutcome,
    PasswordResetStatus,
    ProtectedSecret,
    PurposeTokenDelivery,
    RateLimitAttempt,
    RateLimitDecision,
    RefreshFamilyContext,
    RefreshPreflightOutcome,
    RefreshReceiptReplay,
    RefreshRotationOutcome,
    RefreshRotationStatus,
    RefreshTokenFamilyStore,
    RefreshTokenProof,
    RegistrationCommand,
    RegistrationOutcome,
    RegistrationStatus,
    RegistrationStore,
    RevokeLoginMethodOutcome,
    RevokeLoginMethodStatus,
    RotateRefreshCommand,
    SecurityEvent,
    SessionRegistry,
    StepUpGrantState,
    TokenIssue,
    TOTPMethod,
    UserAuthSession,
    VerificationOutcome,
    VerificationStatus,
    WebAuthnChallenge,
)

_CONFORMANCE_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class _AADIgnoringSecretProtector:
    active_key_version: str = "test-v1"

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedSecret:
        del associated_data
        return ProtectedSecret(ciphertext=secret, key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedSecret, *, associated_data: bytes) -> bytes:
        del associated_data
        return protected.ciphertext


@dataclass(frozen=True, slots=True)
class _WrongSecretRoundTripProtector:
    active_key_version: str = "test-v1"

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedSecret:
        del secret, associated_data
        return ProtectedSecret(ciphertext=b"wrong", key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedSecret, *, associated_data: bytes) -> bytes:
        del associated_data
        return protected.ciphertext


@dataclass(frozen=True, slots=True)
class _WrongSecretVersionProtector(_AADIgnoringSecretProtector):
    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedSecret:
        envelope = await _AADIgnoringSecretProtector.protect(self, secret, associated_data=associated_data)
        return replace(envelope, key_version="retired")


@dataclass(frozen=True, slots=True)
class _DeterministicSecretProtector:
    active_key_version: str = "test-v1"

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedSecret:
        del associated_data
        return ProtectedSecret(ciphertext=secret, key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedSecret, *, associated_data: bytes) -> bytes:
        if associated_data != b"conformance|account=a|purpose=totp":
            raise ValueError
        return protected.ciphertext


class _BrokenMFAStore(testing_module.InMemoryMFAStore):
    """Accept a non-increasing TOTP counter."""

    async def advance_totp_counter(self, method_id: str, *, accepted_counter: int, now: datetime) -> bool:
        if accepted_counter <= 1:
            return True
        return await super().advance_totp_counter(method_id, accepted_counter=accepted_counter, now=now)


class _AlwaysAdvanceMFAStore(testing_module.InMemoryMFAStore):
    """Accept every TOTP advancement, including concurrent and stale values."""

    async def advance_totp_counter(self, method_id: str, *, accepted_counter: int, now: datetime) -> bool:
        del method_id, accepted_counter, now
        return True


class _AlwaysConsumeRecoveryStore(testing_module.InMemoryMFAStore):
    """Report duplicate recovery-code consumption as successful."""

    async def consume_recovery_code(self, account_id: str, digest: bytes, *, now: datetime) -> bool:
        await super().consume_recovery_code(account_id, digest, now=now)
        return True


class _RejectingMFAActivationStore(testing_module.InMemoryMFAStore):
    """Reject an otherwise valid fresh TOTP activation."""

    async def activate_totp(  # noqa: PLR0913 - mirrors the exact atomic public protocol
        self,
        account_id: str,
        enrollment_id: str,
        *,
        accepted_counter: int,
        login_method: LoginMethod,
        event: SecurityEvent,
        now: datetime,
    ) -> TOTPMethod | None:
        del account_id, enrollment_id, accepted_counter, login_method, event, now
        return None


class _EqualCounterMFAStore(testing_module.InMemoryMFAStore):
    """Accept the equal counter after the atomic contender probe completes."""

    calls: int = 0

    async def advance_totp_counter(self, method_id: str, *, accepted_counter: int, now: datetime) -> bool:
        self.calls += 1
        if self.calls > 2:
            return True
        return await super().advance_totp_counter(method_id, accepted_counter=accepted_counter, now=now)


class _BrokenMFALoginChallengeStore(testing_module.InMemoryMFALoginChallengeStore):
    """Leave a rejected account binding available for a later retry."""

    async def consume(
        self, challenge_digest: bytes, *, account_id: str, security_epoch: int, now: datetime
    ) -> MFALoginChallenge | None:
        challenge = self.challenges.get(challenge_digest)
        if challenge is not None and (challenge.account_id != account_id or challenge.security_epoch != security_epoch):
            return None
        return await super().consume(challenge_digest, account_id=account_id, security_epoch=security_epoch, now=now)


class _WrongMFAAccountStore(testing_module.InMemoryMFALoginChallengeStore):
    """Accept an otherwise rejected account binding."""

    async def consume(
        self, challenge_digest: bytes, *, account_id: str, security_epoch: int, now: datetime
    ) -> MFALoginChallenge | None:
        del account_id
        challenge = self.challenges.get(challenge_digest)
        if challenge is not None:
            return await super().consume(
                challenge_digest, account_id=challenge.account_id, security_epoch=security_epoch, now=now
            )
        return None


class _WrongMFAEpochStore(testing_module.InMemoryMFALoginChallengeStore):
    """Accept an otherwise rejected epoch binding."""

    async def consume(
        self, challenge_digest: bytes, *, account_id: str, security_epoch: int, now: datetime
    ) -> MFALoginChallenge | None:
        challenge = self.challenges.get(challenge_digest)
        if challenge is not None and account_id == challenge.account_id:
            return await super().consume(
                challenge_digest, account_id=account_id, security_epoch=challenge.security_epoch, now=now
            )
        return await super().consume(challenge_digest, account_id=account_id, security_epoch=security_epoch, now=now)


class _RetainedExpiredMFAStore(testing_module.InMemoryMFALoginChallengeStore):
    """Make an expired challenge appear valid."""

    async def consume(
        self, challenge_digest: bytes, *, account_id: str, security_epoch: int, now: datetime
    ) -> MFALoginChallenge | None:
        challenge = self.challenges.get(challenge_digest)
        if challenge is not None and challenge.expires_at <= now:
            return challenge
        return await super().consume(challenge_digest, account_id=account_id, security_epoch=security_epoch, now=now)


class _UnburnedMFAEpochStore(testing_module.InMemoryMFALoginChallengeStore):
    """Reject an epoch mismatch without burning its challenge."""

    async def consume(
        self, challenge_digest: bytes, *, account_id: str, security_epoch: int, now: datetime
    ) -> MFALoginChallenge | None:
        challenge = self.challenges.get(challenge_digest)
        if challenge is not None and challenge.account_id == account_id and challenge.security_epoch != security_epoch:
            return None
        return await super().consume(challenge_digest, account_id=account_id, security_epoch=security_epoch, now=now)


class _ReplayingMFAChallengeStore(testing_module.InMemoryMFALoginChallengeStore):
    """Return the winning challenge to both atomic contenders."""

    consumed: MFALoginChallenge | None = None

    async def consume(
        self, challenge_digest: bytes, *, account_id: str, security_epoch: int, now: datetime
    ) -> MFALoginChallenge | None:
        result = await super().consume(challenge_digest, account_id=account_id, security_epoch=security_epoch, now=now)
        if result is not None:
            self.consumed = result
        if result is None and challenge_digest == b"w" * 32:
            return self.consumed
        return result


class _UnburnedExpiredMFAStore(testing_module.InMemoryMFALoginChallengeStore):
    """Reject an expired challenge without removing it."""

    async def consume(
        self, challenge_digest: bytes, *, account_id: str, security_epoch: int, now: datetime
    ) -> MFALoginChallenge | None:
        challenge = self.challenges.get(challenge_digest)
        if challenge is not None and challenge.expires_at <= now:
            return None
        return await super().consume(challenge_digest, account_id=account_id, security_epoch=security_epoch, now=now)


class _BrokenWebAuthnChallengeStore(testing_module.InMemoryWebAuthnChallengeStore):
    """Leave rejected WebAuthn bindings available for a later retry."""

    async def consume(
        self, challenge_digest: bytes, *, binding_digest: bytes, purpose: str, now: datetime
    ) -> WebAuthnChallenge | None:
        challenge = self.challenges.get(challenge_digest)
        if challenge is not None and (challenge.binding_digest != binding_digest or challenge.purpose != purpose):
            return None
        return await super().consume(challenge_digest, binding_digest=binding_digest, purpose=purpose, now=now)


class _WrongWebAuthnBindingStore(testing_module.InMemoryWebAuthnChallengeStore):
    """Accept a challenge despite its binding mismatch."""

    async def consume(
        self, challenge_digest: bytes, *, binding_digest: bytes, purpose: str, now: datetime
    ) -> WebAuthnChallenge | None:
        del binding_digest
        challenge = self.challenges.get(challenge_digest)
        if challenge is not None:
            return await super().consume(
                challenge_digest, binding_digest=challenge.binding_digest, purpose=purpose, now=now
            )
        return None


class _WrongWebAuthnPurposeStore(testing_module.InMemoryWebAuthnChallengeStore):
    """Accept a challenge despite its purpose mismatch."""

    async def consume(
        self, challenge_digest: bytes, *, binding_digest: bytes, purpose: str, now: datetime
    ) -> WebAuthnChallenge | None:
        challenge = self.challenges.get(challenge_digest)
        if challenge is not None and binding_digest == challenge.binding_digest:
            return await super().consume(
                challenge_digest, binding_digest=binding_digest, purpose=challenge.purpose, now=now
            )
        return await super().consume(challenge_digest, binding_digest=binding_digest, purpose=purpose, now=now)


class _RetainedExpiredWebAuthnStore(testing_module.InMemoryWebAuthnChallengeStore):
    """Make an expired challenge appear valid."""

    async def consume(
        self, challenge_digest: bytes, *, binding_digest: bytes, purpose: str, now: datetime
    ) -> WebAuthnChallenge | None:
        challenge = self.challenges.get(challenge_digest)
        if challenge is not None and challenge.expires_at <= now:
            return challenge
        return await super().consume(challenge_digest, binding_digest=binding_digest, purpose=purpose, now=now)


class _UnburnedWebAuthnPurposeStore(testing_module.InMemoryWebAuthnChallengeStore):
    """Reject a purpose mismatch without burning its challenge."""

    async def consume(
        self, challenge_digest: bytes, *, binding_digest: bytes, purpose: str, now: datetime
    ) -> WebAuthnChallenge | None:
        challenge = self.challenges.get(challenge_digest)
        if challenge is not None and challenge.binding_digest == binding_digest and challenge.purpose != purpose:
            return None
        return await super().consume(challenge_digest, binding_digest=binding_digest, purpose=purpose, now=now)


class _ReplayingWebAuthnChallengeStore(testing_module.InMemoryWebAuthnChallengeStore):
    """Return the winning challenge to both atomic contenders."""

    consumed: WebAuthnChallenge | None = None

    async def consume(
        self, challenge_digest: bytes, *, binding_digest: bytes, purpose: str, now: datetime
    ) -> WebAuthnChallenge | None:
        result = await super().consume(challenge_digest, binding_digest=binding_digest, purpose=purpose, now=now)
        if result is not None:
            self.consumed = result
        if result is None and challenge_digest == b"w" * 32:
            return self.consumed
        return result


@dataclass
class _BrokenStepUpStore(testing_module.InMemoryStepUpStore):
    """Ignore one bound step-up value during consumption."""

    def __init__(self, *, ignored_binding: str) -> None:
        super().__init__()
        self.ignored_binding = ignored_binding

    async def consume(  # noqa: PLR0913 - mirrors the exact atomic public protocol
        self,
        grant_digest: bytes,
        *,
        principal_id: str,
        security_epoch: int,
        purpose: str,
        transport_digest: bytes,
        now: datetime,
    ) -> StepUpGrantState | None:
        record = self.grants.get(grant_digest)
        if record is None:
            return None
        if self.ignored_binding == "principal":
            principal_id = record.principal_id
        elif self.ignored_binding == "epoch":
            security_epoch = record.security_epoch
        elif self.ignored_binding == "purpose":
            purpose = record.purpose
        elif self.ignored_binding == "transport":
            transport_digest = record.transport_digest
        elif self.ignored_binding == "expiry":
            now = record.authenticated_at
        return await super().consume(
            grant_digest,
            principal_id=principal_id,
            security_epoch=security_epoch,
            purpose=purpose,
            transport_digest=transport_digest,
            now=now,
        )


@dataclass
class _YieldingStepUpStore:
    """Deliberately yield between reading and burning a step-up grant."""

    grants: dict[bytes, StepUpGrantState] = field(default_factory=dict[bytes, StepUpGrantState])
    release: Event = field(default_factory=Event)
    contenders: int = 0

    async def put(self, record: StepUpGrantState) -> None:
        self.grants[record.grant_digest] = record

    async def consume(  # noqa: PLR0913 - mirrors the exact atomic public protocol
        self,
        grant_digest: bytes,
        *,
        principal_id: str,
        security_epoch: int,
        purpose: str,
        transport_digest: bytes,
        now: datetime,
    ) -> StepUpGrantState | None:
        record = self.grants.get(grant_digest)
        if (
            record is None
            or record.principal_id != principal_id
            or record.security_epoch != security_epoch
            or record.purpose != purpose
            or record.transport_digest != transport_digest
            or record.expires_at <= now
        ):
            return None
        self.contenders += 1
        if self.contenders == 2:
            self.release.set()
        await self.release.wait()
        self.grants.pop(grant_digest, None)
        return record


class _ReplayStepUpStore(testing_module.InMemoryStepUpStore):
    """Return an already-consumed grant after the atomic contention probe."""

    calls: int = 0
    consumed: StepUpGrantState | None = None

    async def consume(  # noqa: PLR0913 - mirrors the exact atomic public protocol
        self,
        grant_digest: bytes,
        *,
        principal_id: str,
        security_epoch: int,
        purpose: str,
        transport_digest: bytes,
        now: datetime,
    ) -> StepUpGrantState | None:
        self.calls += 1
        if self.calls > 2:
            return self.consumed
        result = await super().consume(
            grant_digest,
            principal_id=principal_id,
            security_epoch=security_epoch,
            purpose=purpose,
            transport_digest=transport_digest,
            now=now,
        )
        if result is not None:
            self.consumed = result
        return result


@dataclass
class _NonAtomicLimiter:
    """Deliberately yield between reading and incrementing one shared bucket."""

    limit: int
    count: int = 0

    async def acquire(self, request: RateLimitAttempt) -> RateLimitDecision:
        """Race concurrent callers while producing an otherwise valid decision."""
        del request
        current = self.count
        await checkpoint()
        allowed = current < self.limit
        if allowed:
            self.count = current + 1
        return RateLimitDecision(allowed=allowed)


@dataclass
class _UnderAdmittingLimiter:
    """Deliberately deny one permitted attempt."""

    limit: int
    count: int = 0

    async def acquire(self, request: RateLimitAttempt) -> RateLimitDecision:
        """Return a valid decision while failing to spend the whole budget."""
        del request
        if self.count < self.limit - 1:
            self.count += 1
            return RateLimitDecision(allowed=True)
        return RateLimitDecision(allowed=False)


class _BrokenPasskeyStore(testing_module.InMemoryPasskeyStore):
    """Report a recorded assertion without preserving its durable version update."""

    calls: int = 0

    async def record_assertion(  # noqa: PLR0913 - mirrors the explicit atomic public protocol
        self,
        credential_id: bytes,
        *,
        expected_version: int,
        sign_count: int,
        backup_eligible: bool,
        backup_state: bool,
        clone_risk: bool,
        now: datetime,
    ) -> PasskeyAssertionStatus:
        result = await super().record_assertion(
            credential_id,
            expected_version=expected_version,
            sign_count=sign_count,
            backup_eligible=backup_eligible,
            backup_state=backup_state,
            clone_risk=clone_risk,
            now=now,
        )
        self.calls += 1
        if self.calls == 2:
            credential = self.credentials[credential_id]
            self.credentials[credential_id] = replace(credential, version=expected_version)
        return result


class _BrokenPasskeyCloneResultStore(testing_module.InMemoryPasskeyStore):
    """Lose the clone-risk result after persisting a clone-risk assertion."""

    async def record_assertion(  # noqa: PLR0913 - mirrors the explicit atomic public protocol
        self,
        credential_id: bytes,
        *,
        expected_version: int,
        sign_count: int,
        backup_eligible: bool,
        backup_state: bool,
        clone_risk: bool,
        now: datetime,
    ) -> PasskeyAssertionStatus:
        result = await super().record_assertion(
            credential_id,
            expected_version=expected_version,
            sign_count=sign_count,
            backup_eligible=backup_eligible,
            backup_state=backup_state,
            clone_risk=clone_risk,
            now=now,
        )
        return PasskeyAssertionStatus.RECORDED if clone_risk else result


class _BrokenPasskeyCloneStateStore(testing_module.InMemoryPasskeyStore):
    """Clear the durable clone-risk marker after reporting clone risk."""

    async def record_assertion(  # noqa: PLR0913 - mirrors the explicit atomic public protocol
        self,
        credential_id: bytes,
        *,
        expected_version: int,
        sign_count: int,
        backup_eligible: bool,
        backup_state: bool,
        clone_risk: bool,
        now: datetime,
    ) -> PasskeyAssertionStatus:
        result = await super().record_assertion(
            credential_id,
            expected_version=expected_version,
            sign_count=sign_count,
            backup_eligible=backup_eligible,
            backup_state=backup_state,
            clone_risk=clone_risk,
            now=now,
        )
        if clone_risk:
            self.credentials[credential_id] = replace(self.credentials[credential_id], suspect=False)
        return result


class _RejectingPasskeyStore(testing_module.InMemoryPasskeyStore):
    """Reject an otherwise fresh passkey credential."""

    async def add_credential(
        self, credential: PasskeyCredential, *, login_method: LoginMethod, event: SecurityEvent
    ) -> bool:
        del credential, login_method, event
        return False


class _NonAtomicPasskeyResultStore(testing_module.InMemoryPasskeyStore):
    """Report both optimistic assertion contenders as recorded."""

    async def record_assertion(  # noqa: PLR0913 - mirrors the explicit atomic public protocol
        self,
        credential_id: bytes,
        *,
        expected_version: int,
        sign_count: int,
        backup_eligible: bool,
        backup_state: bool,
        clone_risk: bool,
        now: datetime,
    ) -> PasskeyAssertionStatus:
        result = await super().record_assertion(
            credential_id,
            expected_version=expected_version,
            sign_count=sign_count,
            backup_eligible=backup_eligible,
            backup_state=backup_state,
            clone_risk=clone_risk,
            now=now,
        )
        if not clone_risk and result is PasskeyAssertionStatus.CONFLICT:
            return PasskeyAssertionStatus.RECORDED
        return result


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

    async def find_for_login(self, normalized_identifier: str) -> LocalAccountState[object] | None:
        return await self.delegate.find_for_login(normalized_identifier)

    async def get_by_id(self, account_id: str) -> LocalAccountState[object] | None:
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
    ) -> RegistrationOutcome[object]:
        if self.registration_partial_raises and command.normalized_identifier == "partial-write@example.com":
            message = "injected partial registration failure"
            raise RuntimeError(message)
        result = await self.delegate.register(
            command, password_hash, invitation_digest=invitation_digest, verification=verification, now=now, event=event
        )
        if not self.register_is_atomic and result.status is RegistrationStatus.DUPLICATE:
            existing = await self.delegate.find_for_login(command.normalized_identifier)
            return RegistrationOutcome(RegistrationStatus.CREATED, existing)
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
    ) -> PasswordChangeOutcome:
        self._bump_attempts += 1
        result = await self.delegate.replace_password_and_bump_epoch(
            account_id, password_hash, expected_epoch=expected_epoch, event=event
        )
        if not self.bump_epoch_is_atomic and result.status is PasswordChangeStatus.CONFLICT:
            return PasswordChangeOutcome(PasswordChangeStatus.CHANGED, expected_epoch + 1)
        return result

    async def list_methods(self, account_id: str) -> tuple[LoginMethod, ...]:
        return await self.delegate.list_methods(account_id)

    async def register_login_method(self, account_id: str, method: LoginMethod, *, event: SecurityEvent) -> None:
        await self.delegate.register_login_method(account_id, method, event=event)

    async def consume_and_verify(
        self, token_id: str, digest: bytes, *, now: datetime, event: SecurityEvent
    ) -> VerificationOutcome:
        result = await self.delegate.consume_and_verify(token_id, digest, now=now, event=event)
        if result.status is VerificationStatus.CONSUMED:
            self._consumed_verifications.add(token_id)
        elif result.status is VerificationStatus.INVALID:
            self._invalid_verifications.add(token_id)
        if not self.verification_rejects_expired and result.status is VerificationStatus.EXPIRED:
            return VerificationOutcome(VerificationStatus.CONSUMED, "expired-account", 1)
        if (
            not self.verification_burns_attempts
            and result.status is VerificationStatus.USED
            and token_id in self._invalid_verifications
        ):
            return VerificationOutcome(VerificationStatus.CONSUMED, "burned-account", 1)
        if not self.verification_is_single_use and token_id in self._consumed_verifications:
            return VerificationOutcome(VerificationStatus.CONSUMED, "replayed-account", 1)
        return result

    async def issue(self, issue: TokenIssue, notification: NotificationCommand, *, event: SecurityEvent) -> None:
        await self.delegate.issue(issue, notification, event=event)

    async def issue_absent(self) -> None:
        await self.delegate.issue_absent()

    async def consume_and_reset(
        self, token_id: str, digest: bytes, new_password_hash: str, *, now: datetime, event: SecurityEvent
    ) -> PasswordResetOutcome:
        result = await self.delegate.consume_and_reset(token_id, digest, new_password_hash, now=now, event=event)
        if result.status is PasswordResetStatus.INVALID:
            self._invalid_recoveries.add(token_id)
        if not self.recovery_rejects_expired and result.status is PasswordResetStatus.EXPIRED:
            return PasswordResetOutcome(PasswordResetStatus.RESET, "expired-account", 2)
        if (
            not self.recovery_burns_attempts
            and result.status is PasswordResetStatus.USED
            and token_id in self._invalid_recoveries
        ):
            return PasswordResetOutcome(PasswordResetStatus.RESET, "burned-account", 2)
        if not self.recovery_checks_epoch and result.status is PasswordResetStatus.CONFLICT:
            return PasswordResetOutcome(PasswordResetStatus.RESET, "stale-account", 2)
        return result

    async def revoke_login_method(
        self, account_id: str, method_id: str, *, require_remaining: bool = True, event: SecurityEvent
    ) -> RevokeLoginMethodOutcome:
        result = await self.delegate.revoke_login_method(
            account_id, method_id, require_remaining=require_remaining, event=event
        )
        if not self.preserves_final_method and result.status is RevokeLoginMethodStatus.FINAL_METHOD:
            return RevokeLoginMethodOutcome(RevokeLoginMethodStatus.REVOKED)
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
    ) -> RegistrationOutcome[object]:
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
            return RegistrationOutcome(RegistrationStatus.DUPLICATE)
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
    ) -> PasswordChangeOutcome:
        if not password_hash.startswith("conformance-epoch-"):
            return await super().replace_password_and_bump_epoch(
                account_id, password_hash, expected_epoch=expected_epoch, event=event
            )
        snapshot = await self.delegate.current_epoch(account_id)
        if snapshot != expected_epoch:
            return PasswordChangeOutcome(PasswordChangeStatus.CONFLICT)
        self._started += 1
        if self._started == 2:
            self._release.set()
        await self._release.wait()
        async with self._mutation_lock:
            current = await self.delegate.current_epoch(account_id)
            if current is None:
                return PasswordChangeOutcome(PasswordChangeStatus.NOT_FOUND)
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
    corrupt_created_record: bool = True
    returns_expired_record: bool = True
    rebind_returns_exact: bool = True
    expired_record: UserAuthSession | None = None

    async def create(self, command: CreateSessionCommand, *, event: SecurityEvent) -> UserAuthSession:
        record = await self.delegate.create(command, event=event)
        if record.expires_at <= _CONFORMANCE_NOW:
            self.expired_record = record
        if not self.corrupt_created_record:
            return replace(record, display_metadata={"corrupt": "true"})
        return record

    async def get(self, session_id: str) -> UserAuthSession | None:
        if (
            not self.returns_expired_record
            and self.expired_record is not None
            and session_id == self.expired_record.session_id
        ):
            return self.expired_record
        return await self.delegate.get(session_id)

    async def list_for_account(self, account_id: str) -> tuple[UserAuthSession, ...]:
        return tuple(await self.delegate.list_for_account(account_id))

    async def touch(self, session_id: str, *, now: datetime) -> UserAuthSession | None:
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
    ) -> UserAuthSession | None:
        result = await self.delegate.rebind(prior_session_id, command, event=event)
        if not self.rebind_is_atomic and result is None:
            return await self.delegate.create(command, event=event)
        if not self.rebind_commits and result is not None:
            await self.delegate.revoke_session_for_account(command.account_id, command.session_id, event=event)
        if not self.rebind_returns_exact and result is not None:
            return replace(result, display_metadata={"corrupt": "true"})
        return result


class _YieldingSessionStore(_BrokenSessionStore):
    """Split a rebind read from its write so both contenders can win."""

    def __init__(self, delegate: SessionRegistry) -> None:
        super().__init__(delegate)
        self._release = Event()
        self._started = 0

    async def rebind(
        self, prior_session_id: str, command: CreateSessionCommand, *, event: SecurityEvent
    ) -> UserAuthSession | None:
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
    ) -> PasswordChangeOutcome:
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
    rejected_create_marker: int | None = None
    corrupt_context_marker: int | None = None
    accepts_shared_expiry: bool = False
    durable_rotation_state: bool = True
    replay_revocation_is_durable: bool = True
    has_password_state: bool = True
    ownership_mutates_silently: bool = False
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
    ) -> RegistrationOutcome[object]:
        return await self.delegate.register(
            command, password_hash, invitation_digest=invitation_digest, verification=verification, now=now, event=event
        )

    async def create_family(self, command: CreateRefreshFamilyCommand, *, event: SecurityEvent) -> bool:
        if (
            self.rejected_create_marker is not None
            and command.token_digest == bytes((self.rejected_create_marker,)) * 32
        ):
            return False
        result = await self.delegate.create_family(command, event=event)
        if result:
            self._commands[command.token_id] = command
        return result or not self.create_rejects_collisions

    async def get_password_state(self, account_id: str) -> PasswordCredentialState | None:
        if not self.has_password_state:
            return None
        return await self.delegate.get_password_state(account_id)

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: SecurityEvent
    ) -> PasswordChangeOutcome:
        return await self.delegate.replace_password_and_bump_epoch(
            account_id, password_hash, expected_epoch=expected_epoch, event=event
        )

    async def prepare_rotation(  # noqa: PLR0911 - each selected failure remains explicit
        self, proof: RefreshTokenProof, idempotency_digest: bytes | None, *, now: datetime, event: SecurityEvent
    ) -> RefreshFamilyContext | RefreshReceiptReplay | RefreshPreflightOutcome:
        rotation = self._rotations.get(proof.token_id)
        if rotation is not None:
            if (
                not self.idempotency_receipt
                and rotation.token_digest == bytes((8,)) * 32
                and idempotency_digest == rotation.idempotency_digest
            ):
                return RefreshPreflightOutcome(RefreshRotationStatus.INVALID)
            if not self.replays_revoke and idempotency_digest != rotation.idempotency_digest:
                return RefreshPreflightOutcome(RefreshRotationStatus.REPLAY_DETECTED, family_revoked=True)
            if (
                not self.replay_revocation_is_durable
                and rotation.token_digest == bytes((8,)) * 32
                and idempotency_digest != rotation.idempotency_digest
            ):
                return RefreshPreflightOutcome(RefreshRotationStatus.REPLAY_DETECTED, family_revoked=True)
        result = await self.delegate.prepare_rotation(proof, idempotency_digest, now=now, event=event)
        command = self._commands.get(proof.token_id)
        if (
            command is not None
            and self.corrupt_context_marker is not None
            and command.token_digest == bytes((self.corrupt_context_marker,)) * 32
            and isinstance(result, RefreshFamilyContext)
        ):
            return replace(result, scopes=frozenset({"corrupt"}))
        if (
            command is not None
            and self.accepts_shared_expiry
            and command.token_digest == bytes((15,)) * 32
            and isinstance(result, RefreshPreflightOutcome)
            and result.status is RefreshRotationStatus.EXPIRED
        ):
            return RefreshFamilyContext(
                account_id=command.account_id,
                family_id=command.family_id,
                security_epoch=command.security_epoch,
                token_expires_at=command.token_expires_at,
                family_expires_at=command.family_expires_at,
                scopes=command.scopes,
            )
        if (
            not self.rejects_expiry
            and isinstance(result, RefreshPreflightOutcome)
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
    ) -> RefreshRotationOutcome:
        if not self.rotate_commits and command.successor_digest == bytes((7,)) * 32:
            return RefreshRotationOutcome(RefreshRotationStatus.ROTATED, command.sealed_receipt)
        source = self._commands.get(command.token_id)
        if not self.rotate_rejects_expiry and source is not None and now >= source.token_expires_at:
            return RefreshRotationOutcome(RefreshRotationStatus.ROTATED, command.sealed_receipt)
        result = await self.delegate.rotate(command, now=now, event=event)
        if result.status is RefreshRotationStatus.ROTATED:
            self._rotations[command.token_id] = command
        if (
            not self.durable_rotation_state
            and command.token_digest == bytes((3,)) * 32
            and result.status is RefreshRotationStatus.ROTATED
        ):
            return replace(result, sealed_receipt=b"corrupt")
        if not self.rotate_is_atomic and result.status is not RefreshRotationStatus.ROTATED:
            return RefreshRotationOutcome(RefreshRotationStatus.ROTATED, command.sealed_receipt)
        if (
            not self.rotate_revalidates_epoch
            and command.token_digest == bytes((13,)) * 32
            and result.status is not RefreshRotationStatus.ROTATED
        ):
            return RefreshRotationOutcome(RefreshRotationStatus.ROTATED, command.sealed_receipt)
        return result

    async def revoke_family(self, family_id: str, *, event: SecurityEvent) -> bool:
        return await self.delegate.revoke_family(family_id, event=event)

    async def revoke_token(self, token_id: str, token_digest: bytes, *, event: SecurityEvent) -> bool:
        return await self.delegate.revoke_token(token_id, token_digest, event=event)

    async def revoke_token_for_account(
        self, account_id: str, token_id: str, token_digest: bytes, *, event: SecurityEvent
    ) -> bool:
        if self.ownership_mutates_silently:
            await self.delegate.revoke_token(token_id, token_digest, event=event)
            return False
        if not self.checks_ownership:
            return await self.delegate.revoke_token(token_id, token_digest, event=event)
        return await self.delegate.revoke_token_for_account(account_id, token_id, token_digest, event=event)

    async def revoke_for_account(self, account_id: str, *, event: SecurityEvent) -> int:
        return await self.delegate.revoke_for_account(account_id, event=event)
