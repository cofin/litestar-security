"""Unit tests for the framework-neutral public conformance kit."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Protocol

import pytest
from anyio import Event, Lock, create_task_group, fail_after
from anyio.lowlevel import checkpoint
from litestar.stores.memory import MemoryStore

import litestar_security.testing as testing_module
from litestar_security.accounts import (
    AESGCMSecretProtector,
    AssertionRecordStatus,
    ConsumeOutcome,
    ConsumeStatus,
    CreateRefreshFamilyCommand,
    CreateSessionCommand,
    LocalAccountCapabilities,
    LocalAccountRecord,
    LoginMethod,
    MFALoginChallenge,
    NotificationCommand,
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
    RateLimiter,
    RateLimitPolicy,
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
    SecretProtectorKey,
    SecurityEvent,
    SessionRecord,
    SessionRegistry,
    StepUpRecord,
    StoreRateLimiter,
    TokenIssue,
    TOTPMethod,
    WebAuthnChallenge,
)
from litestar_security.providers.api_key import APIKeyRecord, APIKeyStore
from litestar_security.providers.oauth import (
    AESGCMOAuthTransactionProtector,
    MemoryOAuthAccountStore,
    MemoryOAuthTransactionStore,
    MemoryTokenVault,
    OAuthTransaction,
    OAuthTransactionProtectorKey,
    OIDCLogoutIdentity,
    ProtectedOAuthSecret,
    ProviderTokenSet,
    SecretStr,
    UnlinkOutcome,
    UnlinkStatus,
)
from litestar_security.testing import (
    InMemorySecurityBackend,
    StoreConformanceFactories,
    _single_winner,  # pyright: ignore[reportPrivateUsage] - T1 verifies the private contender harness directly
    assert_api_key_store_conformance,
    assert_local_account_store_conformance,
    assert_mfa_login_challenge_store_conformance,
    assert_mfa_store_conformance,
    assert_oauth_account_store_conformance,
    assert_oauth_transaction_protector_conformance,
    assert_oauth_transaction_store_conformance,
    assert_oidc_session_logout_store_conformance,
    assert_passkey_store_conformance,
    assert_rate_limiter_conformance,
    assert_refresh_family_store_conformance,
    assert_secret_protector_conformance,
    assert_security_backend_conformance,
    assert_session_registry_conformance,
    assert_step_up_store_conformance,
    assert_token_vault_conformance,
    assert_webauthn_challenge_store_conformance,
    assert_websocket_connect_token_store_conformance,
)
from litestar_security.websocket import InMemoryWebSocketConnectTokenStore, WebSocketConnectTokenRecord

_NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)
_CONFORMANCE_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class _ConformanceTransactionProtector:
    """Reversible test-only OAuth transaction protector."""

    active_key_version: str = "test-v1"

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedOAuthSecret:
        del associated_data
        return ProtectedOAuthSecret(ciphertext=secret, key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedOAuthSecret, *, associated_data: bytes) -> bytes:
        del associated_data
        return protected.ciphertext


@dataclass(frozen=True, slots=True)
class _AADIgnoringSecretProtector:
    """Deliberately fail to bind MFA ciphertext to its associated data."""

    active_key_version: str = "test-v1"

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedSecret:
        del associated_data
        return ProtectedSecret(ciphertext=secret, key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedSecret, *, associated_data: bytes) -> bytes:
        del associated_data
        return protected.ciphertext


@dataclass(frozen=True, slots=True)
class _WrongOAuthRoundTripProtector:
    """Return a valid envelope which cannot recover the submitted secret."""

    active_key_version: str = "test-v1"

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedOAuthSecret:
        del secret, associated_data
        return ProtectedOAuthSecret(ciphertext=b"wrong", key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedOAuthSecret, *, associated_data: bytes) -> bytes:
        del associated_data
        return protected.ciphertext


@dataclass(frozen=True, slots=True)
class _WrongOAuthVersionProtector(_ConformanceTransactionProtector):
    """Return ciphertext stamped with a non-active key version."""

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedOAuthSecret:
        envelope = await _ConformanceTransactionProtector.protect(self, secret, associated_data=associated_data)
        return replace(envelope, key_version="retired")


@dataclass(frozen=True, slots=True)
class _WrongSecretRoundTripProtector:
    """Return an MFA envelope that cannot recover its plaintext."""

    active_key_version: str = "test-v1"

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedSecret:
        del secret, associated_data
        return ProtectedSecret(ciphertext=b"wrong", key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedSecret, *, associated_data: bytes) -> bytes:
        del associated_data
        return protected.ciphertext


@dataclass(frozen=True, slots=True)
class _WrongSecretVersionProtector(_AADIgnoringSecretProtector):
    """Return an MFA envelope stamped with a non-active key version."""

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedSecret:
        envelope = await _AADIgnoringSecretProtector.protect(self, secret, associated_data=associated_data)
        return replace(envelope, key_version="retired")


@dataclass(frozen=True, slots=True)
class _DeterministicSecretProtector:
    """Authenticate the fixed conformance AAD while reusing ciphertext."""

    active_key_version: str = "test-v1"

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedSecret:
        del associated_data
        return ProtectedSecret(ciphertext=secret, key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedSecret, *, associated_data: bytes) -> bytes:
        if associated_data != b"conformance|account=a|purpose=totp":
            raise ValueError
        return protected.ciphertext


@dataclass
class _YieldingConnectTokenStore:
    """Deliberately non-atomic consume implementation for the conformance self-test."""

    records: dict[str, WebSocketConnectTokenRecord] = field(default_factory=dict[str, WebSocketConnectTokenRecord])
    release: Event = field(default_factory=Event)
    starters: int = 0
    first_record_id: str | None = None

    async def create(self, record: WebSocketConnectTokenRecord) -> None:
        if self.first_record_id is None:
            self.first_record_id = record.connect_token_id
        self.records[record.connect_token_id] = record

    async def consume(
        self, *, connect_token_id: str, digest: bytes, now: datetime
    ) -> WebSocketConnectTokenRecord | None:
        record = self.records.get(connect_token_id)
        if record is None or record.digest != digest or record.expires_at <= now:
            return None
        if connect_token_id == self.first_record_id:
            return self.records.pop(connect_token_id)
        self.starters += 1
        if self.starters == 2:
            self.release.set()
        await self.release.wait()
        self.records.pop(connect_token_id, None)
        return record


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
class _BrokenOAuthTransactionStore:
    """Ignore callback provider when consuming transaction state."""

    records: dict[bytes, OAuthTransaction] = field(default_factory=dict[bytes, OAuthTransaction])

    async def create(self, transaction: OAuthTransaction) -> None:
        self.records[transaction.state_digest] = transaction

    async def consume(
        self, *, state_digest: bytes, binding_digest: bytes, provider: str, now: datetime
    ) -> OAuthTransaction | None:
        del provider
        transaction = self.records.get(state_digest)
        if transaction is None or transaction.binding_digest != binding_digest or transaction.expires_at <= now:
            return None
        return self.records.pop(state_digest)


@dataclass
class _ConfigurableOAuthTransactionStore:
    """Raw transaction store with one selected conformance violation."""

    failure: str
    records: dict[bytes, OAuthTransaction] = field(default_factory=dict[bytes, OAuthTransaction])

    async def create(self, transaction: OAuthTransaction) -> None:
        self.records[transaction.state_digest] = transaction

    async def consume(  # noqa: PLR0911 - each selected failure remains explicit
        self, *, state_digest: bytes, binding_digest: bytes, provider: str, now: datetime
    ) -> OAuthTransaction | None:
        transaction = self.records.get(state_digest)
        if transaction is None:
            return None
        if transaction.binding_digest != binding_digest:
            return transaction if self.failure == "binding" else None
        if transaction.provider != provider:
            return None
        if transaction.expires_at <= now and self.failure != "expiry":
            return None
        if self.failure == "matching" and state_digest == b"s" * 32:
            self.records.pop(state_digest)
            return replace(transaction, provider="wrong-provider")
        if self.failure == "replay" and state_digest == b"s" * 32:
            return transaction
        if self.failure == "atomicity" and state_digest == b"c" * 32:
            return transaction
        return self.records.pop(state_digest)


class _BrokenWebSocketConnectTokenStore(InMemoryWebSocketConnectTokenStore):
    """Burn a connect token before validating the presented digest."""

    async def consume(
        self, *, connect_token_id: str, digest: bytes, now: datetime
    ) -> WebSocketConnectTokenRecord | None:
        record = await super().consume(connect_token_id=connect_token_id, digest=digest, now=now)
        if record is not None:
            return record
        self._records.pop(connect_token_id, None)  # pyright: ignore[reportPrivateUsage] - deliberately violates port contract
        return None


@dataclass
class _ConfigurableConnectTokenStore(InMemoryWebSocketConnectTokenStore):
    """Connect-token store with one selected lookup violation."""

    failure: str = "digest"

    async def consume(
        self, *, connect_token_id: str, digest: bytes, now: datetime
    ) -> WebSocketConnectTokenRecord | None:
        record = self._records.get(connect_token_id)  # pyright: ignore[reportPrivateUsage] - deliberate test corruption
        if record is not None and self.failure == "digest" and record.digest != digest:
            return record
        if record is not None and record.expires_at <= now:
            if self.failure == "expiry":
                return record
            if self.failure == "expiry_deletion":
                return None
        return await super().consume(connect_token_id=connect_token_id, digest=digest, now=now)


class _BrokenOIDCReplayStore(testing_module.InMemoryOIDCSessionLogoutStore):
    """Return a false successful result after a back-channel replay."""

    async def consume_backchannel(self, identity: OIDCLogoutIdentity, *, now: datetime) -> int | None:
        result = await super().consume_backchannel(identity, now=now)
        return 2 if result is None else result


class _BrokenOIDCBindingStore(testing_module.InMemoryOIDCSessionLogoutStore):
    """Ignore the browser binding during front-channel logout."""

    async def revoke_frontchannel(
        self, provider: str, issuer: str, session_id: str, *, binding: str, now: datetime
    ) -> int | None:
        del binding
        return await super().revoke_frontchannel(
            provider, issuer, session_id, binding="conformance-browser-binding", now=now
        )


class _BrokenOIDCBackchannelCountStore(testing_module.InMemoryOIDCSessionLogoutStore):
    """Report an incomplete exact back-channel revocation."""

    async def consume_backchannel(self, identity: OIDCLogoutIdentity, *, now: datetime) -> int | None:
        result = await super().consume_backchannel(identity, now=now)
        return 1 if result == 2 else result


class _BrokenOIDCMismatchStore(testing_module.InMemoryOIDCSessionLogoutStore):
    """Treat a mismatched provider as an owned mapping."""

    async def consume_backchannel(self, identity: OIDCLogoutIdentity, *, now: datetime) -> int | None:
        if identity.provider == "other-provider":
            return 1
        return await super().consume_backchannel(identity, now=now)


class _BrokenOIDCFrontchannelCountStore(testing_module.InMemoryOIDCSessionLogoutStore):
    """Report an incomplete exact front-channel revocation."""

    async def revoke_frontchannel(
        self, provider: str, issuer: str, session_id: str, *, binding: str, now: datetime
    ) -> int | None:
        result = await super().revoke_frontchannel(provider, issuer, session_id, binding=binding, now=now)
        return 1 if result == 2 else result


class _BrokenOIDCFrontchannelReplayStore(testing_module.InMemoryOIDCSessionLogoutStore):
    """Report a false successful result after a front-channel replay."""

    async def revoke_frontchannel(
        self, provider: str, issuer: str, session_id: str, *, binding: str, now: datetime
    ) -> int | None:
        result = await super().revoke_frontchannel(provider, issuer, session_id, binding=binding, now=now)
        return 2 if result is None and binding == "conformance-browser-binding" else result


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
    ) -> StepUpRecord | None:
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

    grants: dict[bytes, StepUpRecord] = field(default_factory=dict[bytes, StepUpRecord])
    release: Event = field(default_factory=Event)
    contenders: int = 0

    async def put(self, record: StepUpRecord) -> None:
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
    ) -> StepUpRecord | None:
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
    consumed: StepUpRecord | None = None

    async def consume(  # noqa: PLR0913 - mirrors the exact atomic public protocol
        self,
        grant_digest: bytes,
        *,
        principal_id: str,
        security_epoch: int,
        purpose: str,
        transport_digest: bytes,
        now: datetime,
    ) -> StepUpRecord | None:
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


class _BrokenTokenVault(MemoryTokenVault):
    """Report stale compare-and-swap attempts as successful."""

    def __init__(self, *, provider: str, client_id: str, protector: testing_module.OAuthTransactionProtector) -> None:
        super().__init__(provider=provider, client_id=client_id, protector=protector)
        self.replaced = False

    async def replace(
        self, provider_account_id: str, *, expected_version: int, tokens: ProviderTokenSet, now: datetime
    ) -> bool:
        if not self.replaced:
            self.replaced = await super().replace(
                provider_account_id, expected_version=expected_version, tokens=tokens, now=now
            )
            return self.replaced
        return True


class _BrokenTokenVaultFirstVersion(MemoryTokenVault):
    """Report a non-initial version for the first write."""

    async def put(self, provider_account_id: str, tokens: ProviderTokenSet, *, now: datetime):  # type: ignore[no-untyped-def]  # deliberately corrupts the reference result
        return replace(await super().put(provider_account_id, tokens, now=now), version=2)


class _BrokenTokenVaultRoundTrip(MemoryTokenVault):
    """Drop every retrieved token set."""

    async def get_for_refresh(self, provider_account_id: str, *, now: datetime):  # type: ignore[no-untyped-def]  # deliberately violates the vault port
        stored = await super().get_for_refresh(provider_account_id, now=now)
        return replace(stored, reference=replace(stored.reference, version=99)) if stored is not None else stored


class _BrokenTokenVaultCurrentCAS(MemoryTokenVault):
    """Reject a current compare-and-swap."""

    async def replace(
        self, provider_account_id: str, *, expected_version: int, tokens: ProviderTokenSet, now: datetime
    ) -> bool:
        del provider_account_id, expected_version, tokens, now
        return False


class _BrokenTokenVaultCASState(MemoryTokenVault):
    """Claim a successful replacement without writing it."""

    async def replace(
        self, provider_account_id: str, *, expected_version: int, tokens: ProviderTokenSet, now: datetime
    ) -> bool:
        del provider_account_id, expected_version, tokens, now
        return True


class _BrokenTokenVaultStaleState(MemoryTokenVault):
    """Let a stale compare-and-swap overwrite the current token set."""

    async def replace(
        self, provider_account_id: str, *, expected_version: int, tokens: ProviderTokenSet, now: datetime
    ) -> bool:
        current = await super().get_for_refresh(provider_account_id, now=now)
        if expected_version == 1 and current is not None and current.reference.version == 2:
            await super().replace(provider_account_id, expected_version=2, tokens=tokens, now=now)
            return False
        return await super().replace(provider_account_id, expected_version=expected_version, tokens=tokens, now=now)


class _BrokenTokenVaultDelete(MemoryTokenVault):
    """Retain tokens after deletion."""

    async def delete(self, provider_account_id: str) -> None:
        del provider_account_id


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
    ) -> AssertionRecordStatus:
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
    ) -> AssertionRecordStatus:
        result = await super().record_assertion(
            credential_id,
            expected_version=expected_version,
            sign_count=sign_count,
            backup_eligible=backup_eligible,
            backup_state=backup_state,
            clone_risk=clone_risk,
            now=now,
        )
        return AssertionRecordStatus.RECORDED if clone_risk else result


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
    ) -> AssertionRecordStatus:
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
    ) -> AssertionRecordStatus:
        result = await super().record_assertion(
            credential_id,
            expected_version=expected_version,
            sign_count=sign_count,
            backup_eligible=backup_eligible,
            backup_state=backup_state,
            clone_risk=clone_risk,
            now=now,
        )
        if not clone_risk and result is AssertionRecordStatus.CONFLICT:
            return AssertionRecordStatus.RECORDED
        return result


class _BrokenOAuthAccountStore(MemoryOAuthAccountStore):
    """Report the final identity as removable without changing the underlying link."""

    async def unlink_identity(
        self, account_id: str, provider_account_id: str, *, require_remaining: bool, now: datetime
    ) -> UnlinkOutcome:
        result = await super().unlink_identity(
            account_id, provider_account_id, require_remaining=require_remaining, now=now
        )
        if result.status is UnlinkStatus.FINAL_METHOD:
            return UnlinkOutcome(UnlinkStatus.UNLINKED, provider_account_id)
        return result


class _BrokenOAuthOwnershipStore(MemoryOAuthAccountStore):
    """Claim another account owns a provider link."""

    async def unlink_identity(
        self, account_id: str, provider_account_id: str, *, require_remaining: bool, now: datetime
    ) -> UnlinkOutcome:
        result = await super().unlink_identity(
            account_id, provider_account_id, require_remaining=require_remaining, now=now
        )
        return UnlinkOutcome(UnlinkStatus.UNLINKED, provider_account_id) if account_id == "other-account" else result


class _BrokenOAuthPreservationStore(MemoryOAuthAccountStore):
    """Delete a final provider link while reporting final-method protection."""

    async def unlink_identity(
        self, account_id: str, provider_account_id: str, *, require_remaining: bool, now: datetime
    ) -> UnlinkOutcome:
        result = await super().unlink_identity(
            account_id, provider_account_id, require_remaining=require_remaining, now=now
        )
        if result.status is UnlinkStatus.FINAL_METHOD:
            linked = self._links.pop(provider_account_id)  # pyright: ignore[reportPrivateUsage] - deliberately violates preservation
            del self._identity_index[(linked.provider, linked.issuer, linked.subject)]  # pyright: ignore[reportPrivateUsage] - deliberately violates preservation
        return result


class _BrokenOAuthAtomicUnlinkStore(MemoryOAuthAccountStore):
    """Report every post-unlink contender as a winner."""

    async def unlink_identity(
        self, account_id: str, provider_account_id: str, *, require_remaining: bool, now: datetime
    ) -> UnlinkOutcome:
        result = await super().unlink_identity(
            account_id, provider_account_id, require_remaining=require_remaining, now=now
        )
        if account_id == "conformance-account" and result.status is UnlinkStatus.NOT_FOUND:
            return UnlinkOutcome(UnlinkStatus.UNLINKED, provider_account_id)
        return result


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

    async def find_for_login(self, normalized_identifier: str) -> LocalAccountRecord[object] | None:
        return await self.delegate.find_for_login(normalized_identifier)

    async def get_by_id(self, account_id: str) -> LocalAccountRecord[object] | None:
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

    async def register_login_method(self, account_id: str, method: LoginMethod, *, event: SecurityEvent) -> None:
        await self.delegate.register_login_method(account_id, method, event=event)

    async def consume_and_verify(
        self, token_id: str, digest: bytes, *, now: datetime, event: SecurityEvent
    ) -> ConsumeOutcome:
        result = await self.delegate.consume_and_verify(token_id, digest, now=now, event=event)
        if result.status is ConsumeStatus.CONSUMED:
            self._consumed_verifications.add(token_id)
        elif result.status is ConsumeStatus.INVALID:
            self._invalid_verifications.add(token_id)
        if not self.verification_rejects_expired and result.status is ConsumeStatus.EXPIRED:
            return ConsumeOutcome(ConsumeStatus.CONSUMED, "expired-account", 1)
        if (
            not self.verification_burns_attempts
            and result.status is ConsumeStatus.USED
            and token_id in self._invalid_verifications
        ):
            return ConsumeOutcome(ConsumeStatus.CONSUMED, "burned-account", 1)
        if not self.verification_is_single_use and token_id in self._consumed_verifications:
            return ConsumeOutcome(ConsumeStatus.CONSUMED, "replayed-account", 1)
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
    expired_record: SessionRecord | None = None

    async def create(self, command: CreateSessionCommand, *, event: SecurityEvent) -> SessionRecord:
        record = await self.delegate.create(command, event=event)
        if record.expires_at <= _CONFORMANCE_NOW:
            self.expired_record = record
        if not self.corrupt_created_record:
            return replace(record, display_metadata={"corrupt": "true"})
        return record

    async def get(self, session_id: str) -> SessionRecord | None:
        if (
            not self.returns_expired_record
            and self.expired_record is not None
            and session_id == self.expired_record.session_id
        ):
            return self.expired_record
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


async def test_api_key_conformance_accepts_the_reference_store_in_isolation() -> None:
    await assert_api_key_store_conformance(lambda: InMemorySecurityBackend(clock=lambda: _NOW).api_keys)


async def test_secret_protector_conformance_accepts_the_reference_protector() -> None:
    await assert_secret_protector_conformance(
        lambda: AESGCMSecretProtector(active_key=SecretProtectorKey("v1", b"s" * 32))
    )


async def test_oauth_transaction_protector_conformance_accepts_the_reference_protector() -> None:
    await assert_oauth_transaction_protector_conformance(
        lambda: AESGCMOAuthTransactionProtector(active_key=OAuthTransactionProtectorKey("v1", b"o" * 32))
    )


async def test_oauth_transaction_protector_conformance_rejects_deterministic_protection() -> None:
    deterministic_protector = testing_module._DeterministicProtector  # noqa: SLF001  # pyright: ignore[reportPrivateUsage] - required private deterministic fixture
    with pytest.raises(AssertionError, match="non-determinism"):
        await assert_oauth_transaction_protector_conformance(deterministic_protector)


@pytest.mark.parametrize(
    ("factory", "invariant"),
    [
        (_WrongOAuthRoundTripProtector, r"OAuthTransactionProtector round-trip invariant"),
        (_WrongOAuthVersionProtector, r"OAuthTransactionProtector key-version invariant"),
        (_ConformanceTransactionProtector, r"OAuthTransactionProtector associated data invariant"),
    ],
)
async def test_oauth_transaction_protector_conformance_names_the_remaining_invariants(
    factory: Callable[[], testing_module.OAuthTransactionProtector], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_oauth_transaction_protector_conformance(factory)


async def test_secret_protector_conformance_rejects_ignored_associated_data() -> None:
    with pytest.raises(AssertionError, match="associated data"):
        await assert_secret_protector_conformance(_AADIgnoringSecretProtector)


@pytest.mark.parametrize(
    ("factory", "invariant"),
    [
        (_WrongSecretRoundTripProtector, r"SecretProtector round-trip invariant"),
        (_WrongSecretVersionProtector, r"SecretProtector key-version invariant"),
        (_DeterministicSecretProtector, r"SecretProtector non-determinism invariant"),
    ],
)
async def test_secret_protector_conformance_names_the_remaining_invariants(
    factory: Callable[[], testing_module.SecretProtector], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_secret_protector_conformance(factory)


async def test_local_account_store_conformance_accepts_the_reference_store_in_isolation() -> None:
    await assert_local_account_store_conformance(lambda: InMemorySecurityBackend(clock=lambda: _NOW).accounts)


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


async def test_local_account_store_conformance_names_partial_registration_exceptions() -> None:
    def factory() -> _BrokenAccountStore:
        return _BrokenAccountStore(
            InMemorySecurityBackend(clock=lambda: _NOW).accounts, registration_partial_raises=True
        )

    with pytest.raises(AssertionError, match=r"RegistrationStore\.register partial-write invariant"):
        await assert_local_account_store_conformance(factory)


async def test_local_account_store_conformance_detects_a_yielding_password_lost_update() -> None:
    def factory() -> _YieldingPasswordCASStore:
        return _YieldingPasswordCASStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)

    with pytest.raises(
        AssertionError, match=r"PasswordCredentialStore\.compare_and_replace_password atomicity invariant"
    ):
        await assert_local_account_store_conformance(factory)


async def test_local_account_store_conformance_detects_a_yielding_registration_lost_update() -> None:
    def factory() -> _YieldingRegistrationStore:
        return _YieldingRegistrationStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)

    with pytest.raises(AssertionError, match=r"RegistrationStore\.register atomicity invariant"):
        await assert_local_account_store_conformance(factory)


async def test_local_account_store_conformance_detects_a_yielding_epoch_lost_update() -> None:
    def factory() -> _YieldingEpochBumpStore:
        return _YieldingEpochBumpStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)

    with pytest.raises(
        AssertionError, match=r"PasswordCredentialStore\.replace_password_and_bump_epoch epoch invariant"
    ):
        await assert_local_account_store_conformance(factory)


async def test_local_account_store_conformance_names_shared_factory_state() -> None:
    shared = InMemorySecurityBackend(clock=lambda: _NOW).accounts

    with pytest.raises(AssertionError, match=r"LocalAccountCapabilities factory invariant"):
        await assert_local_account_store_conformance(lambda: shared)


async def test_local_account_store_conformance_detects_distinct_wrappers_over_shared_storage() -> None:
    shared = InMemorySecurityBackend(clock=lambda: _NOW).accounts

    with pytest.raises(AssertionError, match=r"LocalAccountCapabilities factory isolation invariant"):
        await assert_local_account_store_conformance(lambda: _BrokenAccountStore(shared))


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


async def test_session_registry_conformance_accepts_the_reference_store_in_isolation() -> None:
    await assert_session_registry_conformance(
        lambda: InMemorySecurityBackend(clock=lambda: _CONFORMANCE_NOW).accounts, now=_CONFORMANCE_NOW
    )


async def test_session_registry_conformance_rejects_a_shared_factory_instance() -> None:
    shared = InMemorySecurityBackend(clock=lambda: _CONFORMANCE_NOW).accounts

    with pytest.raises(AssertionError, match=r"SessionRegistry factory invariant"):
        await assert_session_registry_conformance(lambda: shared, now=_CONFORMANCE_NOW)


async def test_session_registry_conformance_rejects_distinct_wrappers_over_shared_storage() -> None:
    shared = InMemorySecurityBackend(clock=lambda: _CONFORMANCE_NOW).accounts
    with pytest.raises(AssertionError, match=r"SessionRegistry factory isolation invariant"):
        await assert_session_registry_conformance(lambda: _BrokenSessionStore(shared), now=_CONFORMANCE_NOW)


@pytest.mark.parametrize(
    ("toggle", "invariant"),
    [
        ("corrupt_created_record", r"SessionRegistry\.create/get state invariant"),
        ("returns_expired_record", r"SessionRegistry\.get expiry invariant"),
        ("rebind_is_atomic", r"SessionRegistry\.rebind atomicity invariant"),
        ("rebind_returns_exact", r"SessionRegistry\.rebind state invariant"),
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


async def test_session_registry_conformance_detects_a_yielding_rebind_lost_update() -> None:
    with pytest.raises(AssertionError, match=r"SessionRegistry\.rebind atomicity invariant"):
        await assert_session_registry_conformance(
            lambda: _YieldingSessionStore(InMemorySecurityBackend(clock=lambda: _CONFORMANCE_NOW).accounts),
            now=_CONFORMANCE_NOW,
        )


async def test_refresh_family_store_conformance_accepts_the_reference_store_in_isolation() -> None:
    await assert_refresh_family_store_conformance(lambda: InMemorySecurityBackend(clock=lambda: _NOW).accounts)


async def test_refresh_family_store_conformance_rejects_a_shared_factory_instance() -> None:
    shared = _BrokenRefreshStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)

    with pytest.raises(AssertionError, match=r"RefreshTokenFamilyStore factory invariant"):
        await assert_refresh_family_store_conformance(lambda: shared)


async def test_refresh_family_store_conformance_rejects_distinct_wrappers_over_shared_storage() -> None:
    shared = InMemorySecurityBackend(clock=lambda: _NOW).accounts

    with pytest.raises(AssertionError, match=r"RefreshTokenFamilyStore factory isolation invariant"):
        await assert_refresh_family_store_conformance(lambda: _BrokenRefreshStore(shared))


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


@pytest.mark.parametrize(
    ("attribute", "value", "invariant"),
    [
        ("rejected_create_marker", 1, r"create_family state invariant"),
        ("corrupt_context_marker", 1, r"prepare_rotation state invariant"),
        ("rejected_create_marker", 2, r"create_family expiry setup invariant"),
        ("rejected_create_marker", 15, r"prepare_rotation expiry setup invariant"),
        ("accepts_shared_expiry", True, r"prepare_rotation shared-expiry invariant"),
        ("rejected_create_marker", 3, r"rotate atomicity setup invariant"),
        ("durable_rotation_state", False, r"rotate durable-state invariant"),
        ("rejected_create_marker", 6, r"rotate partial-write setup invariant"),
        ("rejected_create_marker", 10, r"rotate late-expiry setup invariant"),
        ("corrupt_context_marker", 10, r"rotate late-expiry setup invariant"),
        ("rejected_create_marker", 13, r"rotate epoch setup invariant"),
        ("has_password_state", False, r"rotate epoch setup invariant"),
        ("rejected_create_marker", 8, r"prepare_rotation replay setup invariant"),
        ("replay_revocation_is_durable", False, r"prepare_rotation replay invariant"),
        ("rejected_create_marker", 11, r"revoke_token_for_account ownership setup invariant"),
        ("ownership_mutates_silently", True, r"revoke_token_for_account ownership invariant"),
    ],
)
async def test_refresh_family_store_conformance_names_setup_and_exact_state_invariants(
    attribute: str, value: object, invariant: str
) -> None:
    def factory() -> _BrokenRefreshStore:
        store = _BrokenRefreshStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)
        setattr(store, attribute, value)
        return store

    with pytest.raises(AssertionError, match=invariant):
        await assert_refresh_family_store_conformance(factory)


async def test_mfa_store_conformance_rejects_a_non_monotonic_store() -> None:
    with pytest.raises(AssertionError, match="monotonicity invariant"):
        await assert_mfa_store_conformance(_BrokenMFAStore)


@pytest.mark.parametrize(
    ("factory", "invariant"),
    [
        (_AlwaysAdvanceMFAStore, r"MFAStore\.advance_totp_counter atomicity invariant"),
        (_EqualCounterMFAStore, r"MFAStore\.advance_totp_counter monotonicity invariant"),
        (_AlwaysConsumeRecoveryStore, r"MFAStore\.consume_recovery_code atomicity invariant"),
    ],
)
async def test_mfa_store_conformance_names_atomic_invariants(
    factory: Callable[[], testing_module.MFAStore], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_mfa_store_conformance(factory)


async def test_mfa_store_conformance_names_activation_setup_invariant() -> None:
    with pytest.raises(AssertionError, match=r"MFAStore setup invariant"):
        await assert_mfa_store_conformance(_RejectingMFAActivationStore)


async def test_mfa_login_challenge_conformance_rejects_an_unburned_binding() -> None:
    with pytest.raises(AssertionError, match="account-binding burn invariant"):
        await assert_mfa_login_challenge_store_conformance(_BrokenMFALoginChallengeStore)


@pytest.mark.parametrize(
    ("factory", "invariant"),
    [
        (_WrongMFAAccountStore, r"MFALoginChallengeStore binding invariant"),
        (_WrongMFAEpochStore, r"MFALoginChallengeStore epoch invariant"),
        (_RetainedExpiredMFAStore, r"MFALoginChallengeStore expiry invariant"),
        (_UnburnedMFAEpochStore, r"MFALoginChallengeStore epoch-binding burn invariant"),
        (_ReplayingMFAChallengeStore, r"MFALoginChallengeStore atomicity invariant"),
        (_UnburnedExpiredMFAStore, r"MFALoginChallengeStore expiry burn invariant"),
    ],
)
async def test_mfa_login_challenge_conformance_names_rejected_value_invariants(
    factory: Callable[[], testing_module.MFALoginChallengeStore], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_mfa_login_challenge_store_conformance(factory)


async def test_webauthn_challenge_conformance_rejects_an_unburned_binding() -> None:
    with pytest.raises(AssertionError, match="binding burn invariant"):
        await assert_webauthn_challenge_store_conformance(_BrokenWebAuthnChallengeStore)


@pytest.mark.parametrize(
    ("factory", "invariant"),
    [
        (_WrongWebAuthnBindingStore, r"WebAuthnChallengeStore binding invariant"),
        (_WrongWebAuthnPurposeStore, r"WebAuthnChallengeStore purpose invariant"),
        (_RetainedExpiredWebAuthnStore, r"WebAuthnChallengeStore expiry invariant"),
        (_UnburnedWebAuthnPurposeStore, r"WebAuthnChallengeStore purpose burn invariant"),
        (_ReplayingWebAuthnChallengeStore, r"WebAuthnChallengeStore atomicity invariant"),
    ],
)
async def test_webauthn_challenge_conformance_names_rejected_value_invariants(
    factory: Callable[[], testing_module.WebAuthnChallengeStore], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_webauthn_challenge_store_conformance(factory)


async def test_oauth_transaction_conformance_rejects_a_provider_blind_store() -> None:
    with pytest.raises(AssertionError, match="provider invariant"):
        await assert_oauth_transaction_store_conformance(_BrokenOAuthTransactionStore)


@pytest.mark.parametrize(
    ("failure", "invariant"),
    [
        ("binding", r"OAuthTransactionStore binding invariant"),
        ("matching", r"OAuthTransactionStore matching invariant"),
        ("replay", r"OAuthTransactionStore consume-once invariant"),
        ("atomicity", r"OAuthTransactionStore atomicity invariant"),
        ("expiry", r"OAuthTransactionStore expiry invariant"),
    ],
)
async def test_oauth_transaction_conformance_names_each_remaining_invariant(failure: str, invariant: str) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_oauth_transaction_store_conformance(lambda: _ConfigurableOAuthTransactionStore(failure))


async def test_websocket_connect_token_conformance_rejects_digest_burn() -> None:
    with pytest.raises(AssertionError, match="digest preservation invariant"):
        await assert_websocket_connect_token_store_conformance(_BrokenWebSocketConnectTokenStore)


@pytest.mark.parametrize(
    ("failure", "invariant"),
    [
        ("digest", r"digest invariant"),
        ("expiry", r"expiry invariant"),
        ("expiry_deletion", r"expiry deletion invariant"),
    ],
)
async def test_websocket_connect_token_conformance_names_lookup_invariants(failure: str, invariant: str) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_websocket_connect_token_store_conformance(lambda: _ConfigurableConnectTokenStore(failure))


async def test_passkey_conformance_rejects_unpersisted_assertion_state() -> None:
    with pytest.raises(AssertionError, match="state invariant"):
        await assert_passkey_store_conformance(_BrokenPasskeyStore)


@pytest.mark.parametrize(
    ("store", "invariant"),
    [
        (_RejectingPasskeyStore, r"PasskeyStore setup invariant"),
        (_NonAtomicPasskeyResultStore, r"PasskeyStore\.record_assertion atomicity invariant"),
    ],
)
async def test_passkey_conformance_names_setup_and_atomicity_invariants(
    store: Callable[[], testing_module.InMemoryPasskeyStore], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_passkey_store_conformance(store)


@pytest.mark.parametrize(
    ("store", "invariant"),
    [
        (_BrokenPasskeyCloneResultStore, r"clone-risk invariant"),
        (_BrokenPasskeyCloneStateStore, r"clone-state invariant"),
    ],
)
async def test_passkey_conformance_names_clone_risk_invariants(
    store: Callable[[], testing_module.InMemoryPasskeyStore], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_passkey_store_conformance(store)


async def test_oauth_account_conformance_rejects_final_identity_removal() -> None:
    with pytest.raises(AssertionError, match="final-method invariant"):
        await assert_oauth_account_store_conformance(_BrokenOAuthAccountStore)


@pytest.mark.parametrize(
    ("store", "invariant"),
    [
        (_BrokenOAuthOwnershipStore, r"ownership invariant"),
        (_BrokenOAuthPreservationStore, r"ownership preservation invariant"),
        (_BrokenOAuthAtomicUnlinkStore, r"unlink_identity atomicity invariant"),
    ],
)
async def test_oauth_account_conformance_names_each_remaining_invariant(
    store: Callable[[], MemoryOAuthAccountStore], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_oauth_account_store_conformance(store)


def _oidc_logout_store(
    store_type: type[testing_module.InMemoryOIDCSessionLogoutStore] = testing_module.InMemoryOIDCSessionLogoutStore,
) -> testing_module.InMemoryOIDCSessionLogoutStore:
    """Return the fixed mapped-session fixture required by OIDC conformance."""
    return store_type(
        session_mappings=(
            ("conformance-provider", "https://issuer.example", "conformance-subject", "conformance-session"),
            ("conformance-provider", "https://issuer.example", "conformance-subject", "conformance-session"),
            ("conformance-provider", "https://issuer.example", "other-subject", "other-session"),
        ),
        frontchannel_bindings={
            ("conformance-provider", "https://issuer.example", "conformance-session"): "conformance-browser-binding"
        },
    )


async def test_oidc_session_logout_store_conformance_accepts_seeded_reference_store() -> None:
    await assert_oidc_session_logout_store_conformance(_oidc_logout_store)


async def test_oidc_session_logout_store_conformance_rejects_replay_and_wrong_binding() -> None:
    with pytest.raises(AssertionError, match=r"OIDCSessionLogoutStore\.consume_backchannel replay invariant"):
        await assert_oidc_session_logout_store_conformance(lambda: _oidc_logout_store(_BrokenOIDCReplayStore))
    with pytest.raises(AssertionError, match=r"OIDCSessionLogoutStore\.revoke_frontchannel binding invariant"):
        await assert_oidc_session_logout_store_conformance(lambda: _oidc_logout_store(_BrokenOIDCBindingStore))


@pytest.mark.parametrize(
    ("store_type", "invariant"),
    [
        (_BrokenOIDCBackchannelCountStore, r"consume_backchannel mapped-session invariant"),
        (_BrokenOIDCMismatchStore, r"consume_backchannel provider invariant"),
        (_BrokenOIDCFrontchannelCountStore, r"revoke_frontchannel mapped-session invariant"),
        (_BrokenOIDCFrontchannelReplayStore, r"revoke_frontchannel replay invariant"),
    ],
)
async def test_oidc_session_logout_store_conformance_names_each_remaining_invariant(
    store_type: type[testing_module.InMemoryOIDCSessionLogoutStore], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_oidc_session_logout_store_conformance(lambda: _oidc_logout_store(store_type))


async def test_oidc_session_logout_store_allows_exactly_one_backchannel_contender() -> None:
    store = _oidc_logout_store()
    identity = OIDCLogoutIdentity(
        provider="conformance-provider",
        issuer="https://issuer.example",
        subject="conformance-subject",
        session_id="conformance-session",
        token_id=f"conformance-token-{_CONFORMANCE_NOW.isoformat()}",
        expires_at=_CONFORMANCE_NOW + timedelta(minutes=5),
    )
    outcomes: list[int | None] = []

    async def consume() -> None:
        outcomes.append(await store.consume_backchannel(identity, now=_CONFORMANCE_NOW))

    async with create_task_group() as task_group:
        task_group.start_soon(consume)
        task_group.start_soon(consume)

    assert outcomes.count(2) == 1
    assert outcomes.count(None) == 1


async def test_oidc_reference_frontchannel_handles_missing_and_already_revoked_mappings() -> None:
    missing = testing_module.InMemoryOIDCSessionLogoutStore(
        session_mappings=(), frontchannel_bindings={("provider", "https://issuer.example", "session"): "binding"}
    )
    assert (
        await missing.revoke_frontchannel(
            "provider", "https://issuer.example", "session", binding="binding", now=_CONFORMANCE_NOW
        )
        is None
    )

    store = _oidc_logout_store()
    identity = OIDCLogoutIdentity(
        provider="conformance-provider",
        issuer="https://issuer.example",
        subject="conformance-subject",
        session_id="conformance-session",
        token_id="already-revoked",  # noqa: S106 - public replay identifier, not a secret
        expires_at=_CONFORMANCE_NOW + timedelta(minutes=5),
    )
    assert await store.consume_backchannel(identity, now=_CONFORMANCE_NOW) == 2
    assert (
        await store.revoke_frontchannel(
            identity.provider,
            identity.issuer,
            "conformance-session",
            binding="conformance-browser-binding",
            now=_CONFORMANCE_NOW,
        )
        == 0
    )


async def test_step_up_store_conformance_accepts_the_reference_store() -> None:
    await assert_step_up_store_conformance(testing_module.InMemoryStepUpStore)


@pytest.mark.parametrize("binding", ["principal", "epoch", "purpose", "transport", "expiry"])
async def test_step_up_store_conformance_names_each_bound_value(binding: str) -> None:
    with pytest.raises(AssertionError, match=rf"StepUpStore\.consume {binding} invariant"):
        await assert_step_up_store_conformance(lambda: _BrokenStepUpStore(ignored_binding=binding))


async def test_step_up_store_conformance_detects_yielding_double_consume() -> None:
    with pytest.raises(AssertionError, match=r"StepUpStore\.consume atomicity invariant"):
        await assert_step_up_store_conformance(_YieldingStepUpStore)


async def test_step_up_store_conformance_detects_a_replayed_grant() -> None:
    with pytest.raises(AssertionError, match=r"StepUpStore\.consume replay invariant"):
        await assert_step_up_store_conformance(_ReplayStepUpStore)


def _token_vault() -> MemoryTokenVault:
    return MemoryTokenVault(
        provider="conformance-provider", client_id="conformance-client", protector=_ConformanceTransactionProtector()
    )


async def test_token_vault_conformance_accepts_the_reference_vault() -> None:
    await assert_token_vault_conformance(_token_vault)


async def test_token_vault_conformance_rejects_stale_cas_success() -> None:
    with pytest.raises(AssertionError, match=r"TokenVault\.replace stale-CAS invariant"):
        await assert_token_vault_conformance(
            lambda: _BrokenTokenVault(
                provider="conformance-provider",
                client_id="conformance-client",
                protector=_ConformanceTransactionProtector(),
            )
        )


@pytest.mark.parametrize(
    ("factory", "invariant"),
    [
        (
            lambda: _BrokenTokenVaultFirstVersion(
                provider="conformance-provider",
                client_id="conformance-client",
                protector=_ConformanceTransactionProtector(),
            ),
            r"TokenVault\.put version invariant",
        ),
        (
            lambda: _BrokenTokenVaultRoundTrip(
                provider="conformance-provider",
                client_id="conformance-client",
                protector=_ConformanceTransactionProtector(),
            ),
            r"TokenVault\.get_for_refresh round-trip invariant",
        ),
        (
            lambda: _BrokenTokenVaultCurrentCAS(
                provider="conformance-provider",
                client_id="conformance-client",
                protector=_ConformanceTransactionProtector(),
            ),
            r"TokenVault\.replace CAS invariant",
        ),
        (
            lambda: _BrokenTokenVaultCASState(
                provider="conformance-provider",
                client_id="conformance-client",
                protector=_ConformanceTransactionProtector(),
            ),
            r"TokenVault\.replace state invariant",
        ),
        (
            lambda: _BrokenTokenVaultStaleState(
                provider="conformance-provider",
                client_id="conformance-client",
                protector=_ConformanceTransactionProtector(),
            ),
            r"TokenVault\.replace stale-CAS state invariant",
        ),
        (
            lambda: _BrokenTokenVaultDelete(
                provider="conformance-provider",
                client_id="conformance-client",
                protector=_ConformanceTransactionProtector(),
            ),
            r"TokenVault\.delete invariant",
        ),
    ],
)
async def test_token_vault_conformance_names_each_remaining_invariant(
    factory: Callable[[], MemoryTokenVault], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_token_vault_conformance(factory)


async def test_token_vault_conformance_rejects_factory_state_leakage() -> None:
    shared = _token_vault()
    await shared.put(
        "conformance-provider-account",
        ProviderTokenSet(
            access_token=SecretStr("access"),
            token_type="Bearer",  # noqa: S106 - OAuth bearer scheme, not a secret
            scopes=frozenset(),
            expires_at=_CONFORMANCE_NOW + timedelta(minutes=5),
            refresh_token=SecretStr("refresh"),
        ),
        now=_CONFORMANCE_NOW,
    )

    with pytest.raises(AssertionError, match=r"TokenVault factory isolation invariant"):
        await assert_token_vault_conformance(lambda: shared)


async def test_aggregate_conformance_runs_only_supplied_feature_factories(  # noqa: C901 - one complete dispatch matrix
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def api_keys() -> APIKeyStore:
        return InMemorySecurityBackend(clock=lambda: _NOW).api_keys

    def accounts() -> testing_module.InMemoryLocalAccountStore:
        return InMemorySecurityBackend(clock=lambda: _CONFORMANCE_NOW).accounts

    def mfa_login_challenges() -> testing_module.InMemoryMFALoginChallengeStore:
        return testing_module.InMemoryMFALoginChallengeStore()

    def mfa() -> testing_module.InMemoryMFAStore:
        return testing_module.InMemoryMFAStore()

    def oidc_session_logout_store() -> testing_module.InMemoryOIDCSessionLogoutStore:
        return _oidc_logout_store()

    def step_up_store() -> testing_module.InMemoryStepUpStore:
        return testing_module.InMemoryStepUpStore()

    def token_vault() -> MemoryTokenVault:
        return _token_vault()

    def oauth_accounts() -> MemoryOAuthAccountStore:
        return MemoryOAuthAccountStore()

    def oauth_transactions() -> MemoryOAuthTransactionStore:
        return MemoryOAuthTransactionStore(protector=_ConformanceTransactionProtector())

    def oauth_transaction_protector() -> AESGCMOAuthTransactionProtector:
        return AESGCMOAuthTransactionProtector(active_key=OAuthTransactionProtectorKey("v1", b"o" * 32))

    def passkeys() -> testing_module.InMemoryPasskeyStore:
        return testing_module.InMemoryPasskeyStore()

    def sessions() -> testing_module.InMemoryLocalAccountStore:
        return InMemorySecurityBackend(clock=lambda: _CONFORMANCE_NOW).accounts

    def secret_protector() -> AESGCMSecretProtector:
        return AESGCMSecretProtector(active_key=SecretProtectorKey("v1", b"s" * 32))

    def webauthn_challenges() -> testing_module.InMemoryWebAuthnChallengeStore:
        return testing_module.InMemoryWebAuthnChallengeStore()

    def websocket_connect_tokens() -> InMemoryWebSocketConnectTokenStore:
        return InMemoryWebSocketConnectTokenStore()

    def record(feature: str) -> Callable[..., Awaitable[None]]:
        async def assert_feature(*_args: object) -> None:
            calls.append(feature)

        return assert_feature

    for assertion, feature in (
        ("assert_api_key_store_conformance", "api_key_store"),
        ("assert_local_account_store_conformance", "local_account_store"),
        ("assert_mfa_login_challenge_store_conformance", "mfa_login_challenge_store"),
        ("assert_mfa_store_conformance", "mfa_store"),
        ("assert_oidc_session_logout_store_conformance", "oidc_session_logout_store"),
        ("assert_oauth_account_store_conformance", "oauth_account_store"),
        ("assert_oauth_transaction_protector_conformance", "oauth_transaction_protector"),
        ("assert_oauth_transaction_store_conformance", "oauth_transaction_store"),
        ("assert_passkey_store_conformance", "passkey_store"),
        ("assert_refresh_family_store_conformance", "refresh_family_store"),
        ("assert_secret_protector_conformance", "secret_protector"),
        ("assert_session_registry_conformance", "session_registry"),
        ("assert_step_up_store_conformance", "step_up_store"),
        ("assert_token_vault_conformance", "token_vault"),
        ("assert_webauthn_challenge_store_conformance", "webauthn_challenge_store"),
        ("assert_websocket_connect_token_store_conformance", "websocket_connect_token_store"),
    ):
        monkeypatch.setattr(testing_module, assertion, record(feature))

    await assert_security_backend_conformance(
        StoreConformanceFactories(
            api_key_store=api_keys,
            local_account_store=accounts,
            mfa_login_challenge_store=mfa_login_challenges,
            mfa_store=mfa,
            oidc_session_logout_store=oidc_session_logout_store,
            oauth_account_store=oauth_accounts,
            oauth_transaction_protector=oauth_transaction_protector,
            oauth_transaction_store=oauth_transactions,
            passkey_store=passkeys,
            refresh_family_store=accounts,
            secret_protector=secret_protector,
            session_registry=sessions,
            step_up_store=step_up_store,
            token_vault=token_vault,
            webauthn_challenge_store=webauthn_challenges,
            websocket_connect_token_store=websocket_connect_tokens,
        )
    )

    assert calls == [
        "api_key_store",
        "local_account_store",
        "mfa_login_challenge_store",
        "mfa_store",
        "oidc_session_logout_store",
        "oauth_account_store",
        "oauth_transaction_protector",
        "oauth_transaction_store",
        "passkey_store",
        "refresh_family_store",
        "secret_protector",
        "session_registry",
        "step_up_store",
        "token_vault",
        "webauthn_challenge_store",
        "websocket_connect_token_store",
    ]


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
        "InMemoryOAuthRevocationRetryStore",
        "InMemoryOIDCSessionLogoutStore",
        "InMemoryPasskeyStore",
        "InMemorySecurityBackend",
        "InMemoryStepUpStore",
        "InMemoryWebAuthnChallengeStore",
        "InMemoryWebSocketRevocationSource",
        "MemoryOAuthAccountStore",
        "MemoryOAuthTransactionStore",
        "MemoryTokenVault",
        "OAuthHTTPRequest",
        "StaticAuthorizationResolver",
        "StaticAuthorizationSnapshotRefresher",
        "StaticIdentityResolver",
        "StoreConformanceFactories",
        "assert_api_key_store_conformance",
        "assert_local_account_store_conformance",
        "assert_mfa_login_challenge_store_conformance",
        "assert_mfa_store_conformance",
        "assert_oauth_account_store_conformance",
        "assert_oauth_transaction_protector_conformance",
        "assert_oauth_transaction_store_conformance",
        "assert_oidc_session_logout_store_conformance",
        "assert_passkey_store_conformance",
        "assert_rate_limiter_conformance",
        "assert_refresh_family_store_conformance",
        "assert_secret_protector_conformance",
        "assert_security_backend_conformance",
        "assert_session_registry_conformance",
        "assert_step_up_store_conformance",
        "assert_token_vault_conformance",
        "assert_webauthn_challenge_store_conformance",
        "assert_websocket_connect_token_store_conformance",
    )


async def test_rate_limiter_conformance_accepts_the_reference_limiter() -> None:
    await assert_rate_limiter_conformance(
        lambda limit: StoreRateLimiter(
            policies={"conformance.rate_limit": RateLimitPolicy(limit=limit, window=timedelta(minutes=5))},
            store=MemoryStore(),
        )
    )


@pytest.mark.parametrize("limiter", [_NonAtomicLimiter, _UnderAdmittingLimiter])
async def test_rate_limiter_conformance_names_exact_admission_invariant(limiter: Callable[[int], RateLimiter]) -> None:
    with pytest.raises(AssertionError, match=r"RateLimiter\.acquire atomicity invariant: .*admit exactly k"):
        await assert_rate_limiter_conformance(limiter)


@pytest.mark.parametrize(("limit", "concurrency"), [(0, 20), (5, 0), (5, 4), (True, 20), (5, True)])
async def test_rate_limiter_conformance_rejects_invalid_scenario_bounds(limit: object, concurrency: object) -> None:
    with pytest.raises(ValueError, match="conformance"):
        await assert_rate_limiter_conformance(
            lambda valid_limit: StoreRateLimiter(
                policies={"conformance.rate_limit": RateLimitPolicy(limit=valid_limit, window=timedelta(minutes=5))},
                store=MemoryStore(),
            ),
            limit=limit,  # type: ignore[arg-type]  # parametrization proves runtime validation rejects non-integers
            concurrency=concurrency,  # type: ignore[arg-type]  # parametrization proves runtime validation rejects non-integers
        )


async def test_remaining_reference_store_conformance() -> None:
    await assert_mfa_store_conformance(testing_module.InMemoryMFAStore)
    await assert_mfa_login_challenge_store_conformance(testing_module.InMemoryMFALoginChallengeStore)
    await assert_webauthn_challenge_store_conformance(testing_module.InMemoryWebAuthnChallengeStore)
    await assert_passkey_store_conformance(testing_module.InMemoryPasskeyStore)
    await assert_websocket_connect_token_store_conformance(InMemoryWebSocketConnectTokenStore)
    await assert_oauth_account_store_conformance(MemoryOAuthAccountStore)
    await assert_oauth_transaction_store_conformance(
        lambda: MemoryOAuthTransactionStore(protector=_ConformanceTransactionProtector())
    )
    await assert_step_up_store_conformance(testing_module.InMemoryStepUpStore)
    await assert_token_vault_conformance(_token_vault)


async def test_websocket_connect_token_conformance_detects_yielding_double_consume() -> None:
    with pytest.raises(AssertionError, match="atomicity invariant"):
        await assert_websocket_connect_token_store_conformance(_YieldingConnectTokenStore)


async def test_conformance_detects_shared_factory_state() -> None:
    shared = _ControlledStore({})

    with pytest.raises(AssertionError, match="factory invariant"):
        await assert_api_key_store_conformance(lambda: shared)


async def test_conformance_detects_non_isolated_factory_storage() -> None:
    shared_records: dict[str, APIKeyRecord] = {}

    with pytest.raises(AssertionError, match="create/get isolation invariant"):
        await assert_api_key_store_conformance(lambda: _ControlledStore(shared_records))


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


async def test_empty_aggregate_conformance_requires_no_unrelated_store() -> None:
    await assert_security_backend_conformance(StoreConformanceFactories())
