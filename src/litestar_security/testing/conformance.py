"""Store conformance test suites and capability assertions."""

from base64 import urlsafe_b64encode
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Protocol, TypeVar, cast

from anyio import create_task_group

from litestar_security.accounts import (
    CreateRefreshFamilyCommand,
    CreateSessionCommand,
    LocalAccountCapabilities,
    LocalAccountState,
    LoginMethod,
    PasswordChangeOutcome,
    PasswordChangeStatus,
    PasswordCredentialState,
    PasswordResetOutcome,
    PasswordResetStatus,
    PurposeTokenCodec,
    PurposeTokenDelivery,
    RateLimitAttempt,
    RateLimiter,
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
    RevokeLoginMethodStatus,
    RotateRefreshCommand,
    SecurityEvent,
    SessionRegistry,
    TokenPurpose,
    UserAuthSession,
    VerificationStatus,
)

if TYPE_CHECKING:
    from litestar_security.accounts import (
        MFALoginChallenge,
        MFALoginChallengeStore,
        MFAStore,
        PasskeyCredential,
        PasskeyStore,
        ProtectedSecret,
        SecretProtector,
        StepUpGrantState,
        StepUpStore,
        WebAuthnChallenge,
        WebAuthnChallengeStore,
    )
from litestar_security.context import CredentialRestrictions
from litestar_security.providers.api_key import APIKeyState, APIKeyStore
from litestar_security.providers.oauth import (
    OAuthAccountStore,
    OAuthOperation,
    OAuthTransaction,
    OAuthTransactionProtector,
    OAuthTransactionStore,
    OIDCLogoutIdentity,
    OIDCSessionLogoutStore,
    ProtectedOAuthSecret,
    ProviderGrant,
    ProviderIdentity,
    ProviderTokenSet,
    SecretStr,
    UnlinkStatus,
)
from litestar_security.websocket import WebSocketConnectAuthorization, WebSocketConnectTokenStore

__all__ = (
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
    "assert_webauthn_challenge_store_conformance",
    "assert_websocket_connect_token_store_conformance",
)

ClaimsT = TypeVar("ClaimsT")
ResultT = TypeVar("ResultT")
UserT = TypeVar("UserT")


_DEFAULT_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_CONFORMANCE_ACCOUNT_IDS = (
    "account-1",
    "conformance-account",
    "conformance-principal",
    "conformance-session-other",
    "conformance-session-owner",
    "conformance-subject",
)
_DEFAULT_CREDENTIAL_HASH = "$litestar-security$deterministic-test-hash"


@dataclass(frozen=True, slots=True)
class _ConformanceAccountIds:
    """Account-scoped identifiers referenced by the conformance scenarios."""

    account: str = "conformance-account"
    principal: str = "conformance-principal"
    session_other: str = "conformance-session-other"
    session_owner: str = "conformance-session-owner"
    subject: str = "conformance-subject"

    def seeded(self) -> tuple[str, ...]:
        """Return every account identifier a referential backend must pre-create."""
        return (self.account, self.principal, self.session_other, self.session_owner, self.subject)


def _resolve_conformance_account_ids(identifiers: "Callable[[str, int], str] | None") -> _ConformanceAccountIds:
    """Derive account identifiers from the supplied factory, or keep the fixed defaults."""
    if identifiers is None:
        return _ConformanceAccountIds()
    return _ConformanceAccountIds(
        account=identifiers("conformance-account", 0),
        principal=identifiers("conformance-principal", 0),
        session_other=identifiers("conformance-session-other", 0),
        session_owner=identifiers("conformance-session-owner", 0),
        subject=identifiers("conformance-subject", 0),
    )


@dataclass(frozen=True, slots=True)
class StoreConformanceFactories:
    """Isolated zero-argument factories for explicitly enabled capabilities."""

    api_key_store: Callable[[], APIKeyStore] | None = None
    local_account_store: "Callable[[], _ConformanceLocalAccountStore] | None" = None
    mfa_login_challenge_store: "Callable[[], MFALoginChallengeStore] | None" = None
    mfa_store: "Callable[[], MFAStore] | None" = None
    oidc_session_logout_store: Callable[[], OIDCSessionLogoutStore] | None = None
    oauth_account_store: Callable[[], OAuthAccountStore] | None = None
    oauth_transaction_protector: Callable[[], OAuthTransactionProtector] | None = None
    oauth_transaction_store: Callable[[], OAuthTransactionStore] | None = None
    passkey_store: "Callable[[], PasskeyStore] | None" = None
    refresh_family_store: "Callable[[], _ConformanceRefreshFamilyStore] | None" = None
    secret_protector: "Callable[[], SecretProtector] | None" = None
    session_registry: Callable[[], SessionRegistry] | None = None
    step_up_store: "Callable[[], StepUpStore] | None" = None
    webauthn_challenge_store: "Callable[[], WebAuthnChallengeStore] | None" = None
    websocket_connect_token_store: Callable[[], WebSocketConnectTokenStore] | None = None


async def assert_oauth_transaction_protector_conformance(factory: Callable[[], OAuthTransactionProtector]) -> None:
    """Assert OAuth transaction protection preserves all required AEAD properties.

    Args:
        factory: Isolated zero-argument protector factory.

    Returns:
        None when the protector authenticates associated data and uses a fresh ciphertext.

    Raises:
        AssertionError: If the protector violates a round-trip, key-version,
            associated-data, or non-determinism invariant.
    """
    protector = factory()
    associated_data = b"conformance|transaction=a|purpose=pkce"
    other_associated_data = b"conformance|transaction=b|purpose=pkce"
    secret = b"conformance-secret-value"
    envelope: ProtectedOAuthSecret = await protector.protect(secret, associated_data=associated_data)
    if await protector.unprotect(envelope, associated_data=associated_data) != secret:
        message = (
            "OAuthTransactionProtector round-trip invariant: matching associated data must recover the original secret"
        )
        raise AssertionError(message)
    if not envelope.key_version or envelope.key_version != protector.active_key_version:
        message = (
            "OAuthTransactionProtector key-version invariant: envelope version must be the non-empty active key version"
        )
        raise AssertionError(message)
    try:
        await protector.unprotect(envelope, associated_data=other_associated_data)
    except Exception:  # noqa: BLE001, S110 - conforming protectors may raise implementation-specific authentication errors
        pass
    else:
        message = "OAuthTransactionProtector associated data invariant: altered associated data must fail closed"
        raise AssertionError(message)
    second_envelope = await protector.protect(secret, associated_data=associated_data)
    if second_envelope.ciphertext == envelope.ciphertext:
        message = (
            "OAuthTransactionProtector non-determinism invariant: equivalent protections require distinct ciphertext"
        )
        raise AssertionError(message)


async def assert_api_key_store_conformance(
    factory: Callable[[], APIKeyStore], *, identifiers: "Callable[[str, int], str] | None" = None
) -> None:
    """Assert API-key isolation and atomic rotation behavior.

    Args:
        factory: Isolated zero-argument store factory.

        identifiers: Optional deterministic ``(namespace, sequence)`` account
            identifier factory for typed referential backends; ``None`` keeps
            the fixed conformance constants.

    Returns:
        None when every invariant holds.

    Raises:
        AssertionError: If ``APIKeyStore`` isolation, lookup, or atomic rotation is violated.
    """
    store = factory()
    isolated = factory()
    if store is isolated:
        message = "APIKeyStore factory invariant: each call must return isolated state"
        raise AssertionError(message)
    ids = _resolve_conformance_account_ids(identifiers)
    current = _conformance_api_key_record("a2tra2tra2tra2tr", subject_id=ids.subject)
    replacements = (
        _conformance_api_key_record("ZmZmZmZmZmZmZmZm", subject_id=ids.subject),
        _conformance_api_key_record("Z2dnZ2dnZ2dnZ2dn", subject_id=ids.subject),
    )
    await store.create(current)
    if await store.get(current.key_id) != current or await isolated.get(current.key_id) is not None:
        message = "APIKeyStore.create/get isolation invariant: created records must be exact and factory-local"
        raise AssertionError(message)

    async def rotate(replacement: APIKeyState) -> bool:
        return await _won_unless_raised(
            lambda: store.rotate(
                current_key_id=current.key_id,
                replacement=replacement,
                overlap_until=_DEFAULT_NOW + timedelta(seconds=30),
                now=_DEFAULT_NOW,
            )
        )

    contenders = tuple(lambda replacement=replacement: rotate(replacement) for replacement in replacements)
    winners = await _single_winner(contenders)
    if winners != 1:
        message = (
            "APIKeyStore.rotate atomicity invariant: two contenders must produce one atomic winner "
            f"(observed {winners})"
        )
        raise AssertionError(message)
    persisted_records: list[APIKeyState | None] = []
    for replacement in replacements:
        persisted_records.append(  # noqa: PERF401 - sequential awaited protocol calls
            await store.get(replacement.key_id)
        )
    persisted = tuple(persisted_records)
    if sum(record is not None for record in persisted) != 1:
        message = "APIKeyStore.rotate partial-write invariant: exactly one successor must be persisted"
        raise AssertionError(message)
    current_after = await store.get(current.key_id)
    if current_after is None or current_after.revoked_at != _DEFAULT_NOW:
        message = "APIKeyStore.rotate current-state invariant: the winning transition must revoke the current key"
        raise AssertionError(message)


async def assert_secret_protector_conformance(factory: "Callable[[], SecretProtector]") -> None:
    """Assert MFA-secret protection preserves all required AEAD properties.

    Args:
        factory: Isolated zero-argument protector factory.

    Returns:
        None when the protector authenticates associated data and uses a fresh ciphertext.

    Raises:
        AssertionError: If the protector violates a round-trip, key-version,
            associated-data, or non-determinism invariant.
    """
    protector = factory()
    associated_data = b"conformance|account=a|purpose=totp"
    other_associated_data = b"conformance|account=b|purpose=totp"
    secret = b"conformance-secret-value"
    envelope: ProtectedSecret = await protector.protect(secret, associated_data=associated_data)
    if await protector.unprotect(envelope, associated_data=associated_data) != secret:
        message = "SecretProtector round-trip invariant: matching associated data must recover the original secret"
        raise AssertionError(message)
    if not envelope.key_version or envelope.key_version != protector.active_key_version:
        message = "SecretProtector key-version invariant: envelope version must be the non-empty active key version"
        raise AssertionError(message)
    try:
        await protector.unprotect(envelope, associated_data=other_associated_data)
    except Exception:  # noqa: BLE001, S110 - conforming protectors may raise implementation-specific authentication errors
        pass
    else:
        message = "SecretProtector associated data invariant: altered associated data must fail closed"
        raise AssertionError(message)
    second_envelope = await protector.protect(secret, associated_data=associated_data)
    if second_envelope.ciphertext == envelope.ciphertext:
        message = "SecretProtector non-determinism invariant: equivalent protections require distinct ciphertext"
        raise AssertionError(message)


class _ConformanceLocalAccountStore(LocalAccountCapabilities[object], RegistrationStore[object], Protocol):
    """Combined local-account protocol exercised by the conformance scenarios."""


async def assert_local_account_store_conformance(factory: Callable[[], _ConformanceLocalAccountStore]) -> None:
    """Assert local-account isolation and atomic security transitions.

    Args:
        factory: Isolated zero-argument local-account store factory.

    Returns:
        None when every local-account capability invariant holds.

    Raises:
        AssertionError: If a local-account capability violates an atomicity, replay, or final-method invariant.
    """
    store = factory()
    await _assert_local_account_factory_isolation(factory, store)
    account = await _conformance_register_account(store, "conformance@example.com")
    verification, verification_account = await _assert_registration_scenarios(store)
    await _assert_password_cas(store, account)
    await _assert_password_epoch_bump(store, account)
    await _assert_verification_scenarios(store, verification, verification_account)
    await _assert_recovery_epoch(store, account)
    await _assert_recovery_expiry(store, account)
    await _assert_recovery_attempt_exhaustion(store, account)
    await _assert_final_login_method(store, account)


async def _assert_local_account_factory_isolation(
    factory: Callable[[], _ConformanceLocalAccountStore], store: _ConformanceLocalAccountStore
) -> None:
    isolated = factory()
    if store is isolated:
        message = "LocalAccountCapabilities factory invariant: each call must return isolated state"
        raise AssertionError(message)
    account = await _conformance_register_account(store, "factory-isolation@example.com")
    if await isolated.get_by_id(account.account_id) is not None:
        message = "LocalAccountCapabilities factory isolation invariant: state must not cross factory calls"
        raise AssertionError(message)


async def _assert_registration_scenarios(
    store: _ConformanceLocalAccountStore,
) -> tuple[PurposeTokenDelivery, LocalAccountState[object]]:
    command = _conformance_registration_command("atomic-registration@example.com")
    outcomes: list[RegistrationOutcome[object]] = []

    async def register() -> None:
        outcomes.append(
            await store.register(
                command,
                "conformance-password-hash",
                invitation_digest=None,
                verification=None,
                now=_DEFAULT_NOW,
                event=_conformance_event("register"),
            )
        )

    async with create_task_group() as task_group:
        task_group.start_soon(register)
        task_group.start_soon(register)
    statuses = tuple(result.status for result in outcomes)
    if statuses.count(RegistrationStatus.CREATED) != 1 or statuses.count(RegistrationStatus.DUPLICATE) != 1:
        message = (
            "RegistrationStore.register atomicity invariant: two contenders must return exactly CREATED and DUPLICATE"
        )
        raise AssertionError(message)

    invitation_delivery = _conformance_token_delivery(TokenPurpose.INVITATION, marker=1)
    invitation, notification = invitation_delivery.bind("conformance-invitation")
    await store.issue(invitation, notification, event=_conformance_event("issue-invitation"))
    duplicate_verification = _conformance_verification_delivery(_DEFAULT_NOW, marker=2)
    duplicate = await store.register(
        _conformance_registration_command("conformance@example.com"),
        "conformance-password-hash",
        invitation_digest=invitation.digest,
        verification=duplicate_verification,
        now=_DEFAULT_NOW,
        event=_conformance_event("duplicate-registration"),
    )
    duplicate_probe = await store.consume_and_verify(
        duplicate_verification.issue.token_id,
        duplicate_verification.issue.digest,
        now=_DEFAULT_NOW,
        event=_conformance_event("probe-duplicate-verification"),
    )
    verification = _conformance_verification_delivery(_DEFAULT_NOW, marker=3)
    try:
        after_duplicate = await store.register(
            _conformance_registration_command("partial-write@example.com"),
            "conformance-password-hash",
            invitation_digest=invitation.digest,
            verification=verification,
            now=_DEFAULT_NOW,
            event=_conformance_event("partial-write-registration"),
        )
    except Exception as exc:
        message = (
            "RegistrationStore.register partial-write invariant: duplicate outcomes must not consume invitation "
            "or issue verification"
        )
        raise AssertionError(message) from exc
    if (
        duplicate.status is not RegistrationStatus.DUPLICATE
        or duplicate_probe.status is not VerificationStatus.INVALID
        or after_duplicate.status is not RegistrationStatus.CREATED
        or after_duplicate.account is None
    ):
        message = (
            "RegistrationStore.register partial-write invariant: duplicate outcomes must not consume invitation "
            "or issue verification"
        )
        raise AssertionError(message)
    return verification, after_duplicate.account


async def _assert_password_cas(store: _ConformanceLocalAccountStore, account: LocalAccountState[object]) -> None:
    account_before = await store.get_by_id(account.account_id)
    password_state = await store.get_password_state(account.account_id)
    if account_before is None or password_state is None:  # pragma: no cover - account was just registered
        message = (
            "PasswordCredentialStore.get_password_state invariant: registered accounts must retain their password state"
        )
        raise AssertionError(message)
    replacement_hashes = ("conformance-password-a", "conformance-password-b")

    async def replace_password(replacement_hash: str) -> bool:
        return await store.compare_and_replace_password(
            account.account_id,
            password_state.password_hash,
            replacement_hash,
            event=_conformance_event("compare-and-replace-password"),
        )

    outcomes: list[bool] = []

    async def record(replacement_hash: str) -> None:
        outcomes.append(await replace_password(replacement_hash))

    async with create_task_group() as task_group:
        for replacement_hash in replacement_hashes:
            task_group.start_soon(record, replacement_hash)
    if outcomes.count(True) != 1 or outcomes.count(False) != 1:
        message = (
            "PasswordCredentialStore.compare_and_replace_password atomicity invariant: two contenders must "
            "return exactly True and False"
        )
        raise AssertionError(message)
    password_after = await store.get_password_state(account.account_id)
    account_after = await store.get_by_id(account.account_id)
    if password_after is None or password_after.password_hash not in replacement_hashes:
        message = (
            "PasswordCredentialStore.compare_and_replace_password state invariant: stored password must be "
            "exactly one winner"
        )
        raise AssertionError(message)
    before_non_password = (password_state.security_epoch, password_state.active, password_state.verified)
    after_non_password = (password_after.security_epoch, password_after.active, password_after.verified)
    if account_after != account_before or after_non_password != before_non_password:
        message = (
            "PasswordCredentialStore.compare_and_replace_password state invariant: non-password account state "
            "must remain unchanged"
        )
        raise AssertionError(message)


async def _assert_password_epoch_bump(store: _ConformanceLocalAccountStore, account: LocalAccountState[object]) -> None:
    password_state = await store.get_password_state(account.account_id)
    if password_state is None:  # pragma: no cover - preceding CAS guarantees it
        message = "PasswordCredentialStore.get_password_state invariant: password state must remain readable"
        raise AssertionError(message)
    replacement_hashes = ("conformance-epoch-a", "conformance-epoch-b")

    outcomes: list[PasswordChangeOutcome] = []

    async def bump_epoch(replacement_hash: str) -> None:
        outcomes.append(
            await store.replace_password_and_bump_epoch(
                account.account_id,
                replacement_hash,
                expected_epoch=password_state.security_epoch,
                event=_conformance_event("replace-password-and-bump-epoch"),
            )
        )

    async with create_task_group() as task_group:
        for replacement_hash in replacement_hashes:
            task_group.start_soon(bump_epoch, replacement_hash)
    statuses = tuple(result.status for result in outcomes)
    if statuses.count(PasswordChangeStatus.CHANGED) != 1 or statuses.count(PasswordChangeStatus.CONFLICT) != 1:
        message = (
            "PasswordCredentialStore.replace_password_and_bump_epoch epoch invariant: two contenders must "
            "return exactly CHANGED and CONFLICT"
        )
        raise AssertionError(message)
    current_epoch = await store.current_epoch(account.account_id)
    persisted = await store.get_password_state(account.account_id)
    if current_epoch != password_state.security_epoch + 1:
        message = (
            "PasswordCredentialStore.replace_password_and_bump_epoch epoch invariant: current epoch must "
            "advance by exactly one"
        )
        raise AssertionError(message)
    if (
        persisted is None
        or persisted.password_hash not in replacement_hashes
        or persisted.security_epoch != current_epoch
    ):
        message = (
            "PasswordCredentialStore.replace_password_and_bump_epoch state invariant: persisted password and "
            "password-state epoch must match the winning transition"
        )
        raise AssertionError(message)


async def _assert_verification_scenarios(
    store: _ConformanceLocalAccountStore, verification: PurposeTokenDelivery, account: LocalAccountState[object]
) -> None:
    consumed = await store.consume_and_verify(
        verification.issue.token_id,
        verification.issue.digest,
        now=_DEFAULT_NOW,
        event=_conformance_event("consume-and-verify"),
    )
    replay = await store.consume_and_verify(
        verification.issue.token_id,
        verification.issue.digest,
        now=_DEFAULT_NOW,
        event=_conformance_event("consume-and-verify-replay"),
    )
    stored_account = await store.get_by_id(account.account_id)
    if (
        consumed.status is not VerificationStatus.CONSUMED
        or consumed.account_id != account.account_id
        or consumed.security_epoch != account.security_epoch
        or stored_account is None
        or not stored_account.verified
        or stored_account.security_epoch != account.security_epoch
        or replay.status is VerificationStatus.CONSUMED
    ):
        message = (
            "VerificationTokenStore.consume_and_verify replay invariant: a verification token must be consumed once"
        )
        raise AssertionError(message)
    await _assert_verification_expiry(store)
    await _assert_verification_attempt_exhaustion(store)


async def _assert_verification_expiry(store: _ConformanceLocalAccountStore) -> None:
    delivery = _conformance_verification_delivery(_DEFAULT_NOW, marker=4)
    account = await _conformance_register_account(store, "expired-verification@example.com", verification=delivery)
    result = await store.consume_and_verify(
        delivery.issue.token_id,
        delivery.issue.digest,
        now=delivery.issue.expires_at,
        event=_conformance_event("consume-expired-verification"),
    )
    stored = await store.get_by_id(account.account_id)
    if result.status is not VerificationStatus.EXPIRED or stored is None or stored.verified:
        message = "VerificationTokenStore.consume_and_verify expiry invariant: expired tokens must not verify accounts"
        raise AssertionError(message)


async def _assert_verification_attempt_exhaustion(store: _ConformanceLocalAccountStore) -> None:
    delivery = _conformance_verification_delivery(_DEFAULT_NOW, marker=5, maximum_attempts=2)
    account = await _conformance_register_account(store, "burned-verification@example.com", verification=delivery)
    invalid_digest = _different_digest(delivery.issue.digest)
    invalid_results = tuple([
        await store.consume_and_verify(
            delivery.issue.token_id,
            invalid_digest,
            now=_DEFAULT_NOW,
            event=_conformance_event("burn-verification-attempt"),
        )
        for _attempt in range(delivery.issue.maximum_attempts)
    ])
    valid_after_burn = await store.consume_and_verify(
        delivery.issue.token_id,
        delivery.issue.digest,
        now=_DEFAULT_NOW,
        event=_conformance_event("verification-after-burn"),
    )
    stored = await store.get_by_id(account.account_id)
    if (
        any(result.status is not VerificationStatus.INVALID for result in invalid_results)
        or valid_after_burn.status is not VerificationStatus.USED
        or stored is None
        or stored.verified
    ):
        message = (
            "VerificationTokenStore.consume_and_verify attempt invariant: maximum failures must burn the token "
            "and reject its valid proof"
        )
        raise AssertionError(message)


async def _assert_recovery_epoch(store: _ConformanceLocalAccountStore, account: LocalAccountState[object]) -> None:
    delivery = _conformance_token_delivery(TokenPurpose.RECOVERY, marker=6)
    epoch = await store.current_epoch(account.account_id)
    if epoch is None:  # pragma: no cover - account was just registered
        message = "SecurityEpochStore.current_epoch invariant: a registered account must have an epoch"
        raise AssertionError(message)
    issue, notification = delivery.bind(account.account_id, security_epoch=epoch)
    await store.issue(issue, notification, event=_conformance_event("issue-recovery"))
    changed = await store.replace_password_and_bump_epoch(
        account.account_id,
        "conformance-password-recovery-change",
        expected_epoch=epoch,
        event=_conformance_event("change-before-recovery"),
    )
    changed_state = await store.get_password_state(account.account_id)
    reset = await store.consume_and_reset(
        issue.token_id,
        issue.digest,
        "conformance-password-reset",
        now=_DEFAULT_NOW,
        event=_conformance_event("consume-and-reset"),
    )
    state_after = await store.get_password_state(account.account_id)
    replay = await store.consume_and_reset(
        issue.token_id,
        issue.digest,
        "conformance-password-reset-replay",
        now=_DEFAULT_NOW,
        event=_conformance_event("consume-and-reset-replay"),
    )
    if (
        changed.status is not PasswordChangeStatus.CHANGED
        or changed_state is None
        or reset.status is not PasswordResetStatus.CONFLICT
        or replay.status is PasswordResetStatus.RESET
        or state_after != changed_state
    ):
        message = (
            "RecoveryTokenStore.consume_and_reset epoch invariant: a token issued before an epoch bump must be rejected"
        )
        raise AssertionError(message)


async def _assert_recovery_expiry(store: _ConformanceLocalAccountStore, account: LocalAccountState[object]) -> None:
    delivery = _conformance_token_delivery(TokenPurpose.RECOVERY, marker=7)
    epoch = await store.current_epoch(account.account_id)
    state_before = await store.get_password_state(account.account_id)
    if epoch is None or state_before is None:  # pragma: no cover - account exists with a password
        message = "RecoveryTokenStore.consume_and_reset setup invariant: registered accounts require password state"
        raise AssertionError(message)
    issue, notification = delivery.bind(account.account_id, security_epoch=epoch)
    await store.issue(issue, notification, event=_conformance_event("issue-expired-recovery"))
    result = await store.consume_and_reset(
        issue.token_id,
        issue.digest,
        "expired-recovery-password",
        now=issue.expires_at,
        event=_conformance_event("consume-expired-recovery"),
    )
    if (
        result.status is not PasswordResetStatus.EXPIRED
        or await store.get_password_state(account.account_id) != state_before
    ):
        message = "RecoveryTokenStore.consume_and_reset expiry invariant: expired tokens must not change password state"
        raise AssertionError(message)


async def _assert_recovery_attempt_exhaustion(
    store: _ConformanceLocalAccountStore, account: LocalAccountState[object]
) -> None:
    delivery = _conformance_token_delivery(TokenPurpose.RECOVERY, marker=8, maximum_attempts=2)
    epoch = await store.current_epoch(account.account_id)
    state_before = await store.get_password_state(account.account_id)
    if epoch is None or state_before is None:  # pragma: no cover - account exists with a password
        message = "RecoveryTokenStore.consume_and_reset setup invariant: registered accounts require password state"
        raise AssertionError(message)
    issue, notification = delivery.bind(account.account_id, security_epoch=epoch)
    await store.issue(issue, notification, event=_conformance_event("issue-burned-recovery"))
    invalid_digest = _different_digest(issue.digest)
    invalid_results: list[PasswordResetOutcome] = []
    for _attempt in range(issue.maximum_attempts):
        invalid_results.append(  # noqa: PERF401 - failed attempts must be sequential against one token
            await store.consume_and_reset(
                issue.token_id,
                invalid_digest,
                "invalid-recovery-password",
                now=_DEFAULT_NOW,
                event=_conformance_event("burn-recovery-attempt"),
            )
        )
    valid_after_burn = await store.consume_and_reset(
        issue.token_id,
        issue.digest,
        "valid-after-burn-password",
        now=_DEFAULT_NOW,
        event=_conformance_event("recovery-after-burn"),
    )
    if (
        any(result.status is not PasswordResetStatus.INVALID for result in invalid_results)
        or valid_after_burn.status is not PasswordResetStatus.USED
        or await store.get_password_state(account.account_id) != state_before
    ):
        message = (
            "RecoveryTokenStore.consume_and_reset attempt invariant: maximum failures must burn the token and "
            "reject its valid proof"
        )
        raise AssertionError(message)


async def _assert_final_login_method(store: _ConformanceLocalAccountStore, account: LocalAccountState[object]) -> None:
    other_account = await _conformance_register_account(store, "login-method-owner@example.com")
    method = LoginMethod("conformance-password", "password", _DEFAULT_NOW)
    await store.register_login_method(account.account_id, method, event=_conformance_event("register-login-method"))
    cross_account = await store.revoke_login_method(
        other_account.account_id,
        method.method_id,
        require_remaining=True,
        event=_conformance_event("cross-account-login-method-revoke"),
    )
    final_method = await store.revoke_login_method(
        account.account_id,
        method.method_id,
        require_remaining=True,
        event=_conformance_event("revoke-final-login-method"),
    )
    absent = await store.revoke_login_method(
        account.account_id,
        "missing-login-method",
        require_remaining=True,
        event=_conformance_event("revoke-missing-login-method"),
    )
    if (
        cross_account.status is not RevokeLoginMethodStatus.NOT_FOUND
        or final_method.status is not RevokeLoginMethodStatus.FINAL_METHOD
        or absent.status is not RevokeLoginMethodStatus.NOT_FOUND
    ):
        message = (
            "LoginMethodStore.revoke_login_method final-method invariant: enforce ownership, preserve the final "
            "method, and report absent methods"
        )
        raise AssertionError(message)


async def assert_session_registry_conformance(
    factory: Callable[[], SessionRegistry],
    *,
    now: datetime = _DEFAULT_NOW,
    identifiers: "Callable[[str, int], str] | None" = None,
) -> None:
    """Assert session-registry state, atomic replacement, and ownership behavior.

    Args:
        factory: Isolated zero-argument session-registry factory initialized so
            ``get()`` evaluates expiry against ``now``.
        now: Time used for every created record and expiry assertion.

        identifiers: Optional deterministic ``(namespace, sequence)`` account
            identifier factory for typed referential backends; ``None`` keeps
            the fixed conformance constants.

    Returns:
        None when every session-registry invariant holds.

    Raises:
        AssertionError: If session creation, expiry, replacement, or revocation
            violates its public contract.
    """
    store = factory()
    isolated = factory()
    if store is isolated:
        message = "SessionRegistry factory invariant: each call must return isolated state"
        raise AssertionError(message)
    ids = _resolve_conformance_account_ids(identifiers)
    command = _conformance_session_command(marker=1, account_id=ids.session_owner, now=now)
    created = await store.create(command, event=_conformance_event("create-session"))
    expected = _conformance_session_record(command)
    if created != expected or await store.get(command.session_id) != expected:
        message = "SessionRegistry.create/get state invariant: created records must be exact"
        raise AssertionError(message)
    if await isolated.get(command.session_id) is not None:
        message = "SessionRegistry factory isolation invariant: created sessions must be factory-local"
        raise AssertionError(message)
    expired = _conformance_session_command(
        marker=2, account_id=command.account_id, now=now, created_at=now - timedelta(minutes=2), expires_at=now
    )
    await store.create(expired, event=_conformance_event("create-expired-session"))
    if await store.get(expired.session_id) is not None:
        message = "SessionRegistry.get expiry invariant: expired sessions must not be returned"
        raise AssertionError(message)

    replacements = tuple(
        _conformance_session_command(marker=marker, account_id=command.account_id, now=now) for marker in (3, 4)
    )

    results: list[tuple[CreateSessionCommand, UserAuthSession | None]] = []

    def contender(replacement: CreateSessionCommand) -> Callable[[], Awaitable[bool]]:
        async def attempt() -> bool:
            result = await store.rebind(command.session_id, replacement, event=_conformance_event("rebind-session"))
            results.append((replacement, result))
            return _won_by_presence(result)

        return attempt

    winners = await _single_winner(tuple(contender(replacement) for replacement in replacements))
    if winners != 1:
        message = "SessionRegistry.rebind atomicity invariant: two contenders must produce one replacement"
        raise AssertionError(message)
    winner = next((candidate, result) for candidate, result in results if result is not None)
    winner_command, winner_record = winner
    if winner_record != _conformance_session_record(winner_command):
        message = "SessionRegistry.rebind state invariant: the winning replacement record must be exact"
        raise AssertionError(message)
    successor_records = [await store.get(replacement.session_id) for replacement in replacements]
    if await store.get(command.session_id) is not None or sum(record is not None for record in successor_records) != 1:
        message = (
            "SessionRegistry.rebind partial-write invariant: exactly one replacement must remain and the prior session "
            "must be gone"
        )
        raise AssertionError(message)

    other = _conformance_session_command(marker=5, account_id=ids.session_other, now=now)
    await store.create(other, event=_conformance_event("create-other-session"))
    if await store.revoke_session_for_account(
        command.account_id, other.session_id, event=_conformance_event("cross-account-session-revoke")
    ) or await store.get(other.session_id) != _conformance_session_record(other):
        message = (
            "SessionRegistry.revoke_session_for_account ownership invariant: another account's session must remain"
        )
        raise AssertionError(message)
    current = next(record for record in successor_records if record is not None)
    extra = _conformance_session_command(marker=6, account_id=command.account_id, now=now)
    await store.create(extra, event=_conformance_event("create-extra-session"))
    await store.revoke_other_sessions(
        command.account_id, current.session_id, event=_conformance_event("revoke-other-sessions")
    )
    if (
        await store.get(current.session_id) != current
        or await store.get(extra.session_id) is not None
        or await store.get(other.session_id) != _conformance_session_record(other)
    ):
        message = "SessionRegistry.revoke_other_sessions keep-current invariant: retain only the named owner session"
        raise AssertionError(message)


class _ConformanceRefreshFamilyStore(RefreshTokenFamilyStore, RegistrationStore[object], Protocol):
    """Refresh-family port plus the account registration setup required by its epoch contract."""

    async def get_password_state(self, account_id: str) -> PasswordCredentialState | None:
        """Return the password state used to force an epoch change after preparation."""
        ...  # pragma: no cover

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: SecurityEvent
    ) -> PasswordChangeOutcome:
        """Advance an account epoch so rotation must revalidate prepared context."""
        ...  # pragma: no cover


async def assert_refresh_family_store_conformance(factory: Callable[[], _ConformanceRefreshFamilyStore]) -> None:
    """Assert strict refresh-family creation, rotation, replay, and ownership behavior.

    Args:
        factory: Isolated zero-argument combined local-account and refresh-family
            store factory frozen at the conformance clock.

    Returns:
        None when every refresh-family invariant holds.

    Raises:
        AssertionError: If a refresh-family transition is not exact, atomic, or
            account-owned.
    """
    store = factory()
    isolated = factory()
    if store is isolated:
        message = "RefreshTokenFamilyStore factory invariant: each call must return isolated state"
        raise AssertionError(message)
    account = await _conformance_register_account(store, "refresh-owner@example.com")
    command = _conformance_refresh_family_command(account, marker=1)
    if not await store.create_family(command, event=_conformance_event("create-refresh-family")):
        message = "RefreshTokenFamilyStore.create_family state invariant: a current account epoch must create a family"
        raise AssertionError(message)
    context = await store.prepare_rotation(
        RefreshTokenProof(command.token_id, command.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-refresh"),
    )
    expected_context = _conformance_refresh_context(command)
    if context != expected_context:
        message = "RefreshTokenFamilyStore.prepare_rotation state invariant: active family context must be exact"
        raise AssertionError(message)
    token_collision = replace(command, family_id=_conformance_identifier("rf_", 12))
    family_collision = replace(command, token_id=_conformance_identifier("rt_", 12), token_digest=bytes((12,)) * 32)
    if await store.create_family(
        token_collision, event=_conformance_event("create-refresh-token-collision")
    ) or await store.create_family(family_collision, event=_conformance_event("create-refresh-family-collision")):
        message = (
            "RefreshTokenFamilyStore.create_family collision invariant: "
            "duplicate token and family identifiers must each fail"
        )
        raise AssertionError(message)
    isolated_result = await isolated.prepare_rotation(
        RefreshTokenProof(command.token_id, command.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-isolated-refresh"),
    )
    if (
        not isinstance(isolated_result, RefreshPreflightOutcome)
        or isolated_result.status is not RefreshRotationStatus.INVALID
    ):
        message = "RefreshTokenFamilyStore factory isolation invariant: created families must be factory-local"
        raise AssertionError(message)

    expired = _conformance_refresh_family_command(account, marker=2, expires_at=_DEFAULT_NOW)
    if not await store.create_family(expired, event=_conformance_event("create-expired-refresh")):
        message = (
            "RefreshTokenFamilyStore.create_family expiry setup invariant: expired families must still be recorded"
        )
        raise AssertionError(message)
    expired_result = await store.prepare_rotation(
        RefreshTokenProof(expired.token_id, expired.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-expired-refresh"),
    )
    if (
        not isinstance(expired_result, RefreshPreflightOutcome)
        or expired_result.status is not RefreshRotationStatus.EXPIRED
    ):
        message = "RefreshTokenFamilyStore.prepare_rotation expiry invariant: expired tokens must be rejected"
        raise AssertionError(message)

    # A valid command requires token_expires_at <= family_expires_at, so an
    # independently expired family with a live token is unrepresentable. This
    # shared deadline covers the public state boundary; divergent internal
    # store state is outside the protocol contract.
    shared_expiry = _conformance_refresh_family_command(
        account, marker=15, token_expires_at=_DEFAULT_NOW, family_expires_at=_DEFAULT_NOW
    )
    if not await store.create_family(shared_expiry, event=_conformance_event("create-shared-expiry-refresh")):
        message = (
            "RefreshTokenFamilyStore.prepare_rotation expiry setup invariant: a shared-expiry family must be created"
        )
        raise AssertionError(message)
    shared_result = await store.prepare_rotation(
        RefreshTokenProof(shared_expiry.token_id, shared_expiry.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-shared-expiry-refresh"),
    )
    if (
        not isinstance(shared_result, RefreshPreflightOutcome)
        or shared_result.status is not RefreshRotationStatus.EXPIRED
    ):
        message = (
            "RefreshTokenFamilyStore.prepare_rotation shared-expiry invariant: "
            "the token/family deadline must bound rotation"
        )
        raise AssertionError(message)

    await _assert_refresh_rotation_atomicity(store, account)
    await _assert_refresh_rotation_commit(store, account)
    await _assert_refresh_replay_and_idempotency(store, account)
    await _assert_refresh_ownership(store, account)
    await _assert_refresh_late_rotation_rejection(store, account)


async def _assert_refresh_rotation_atomicity(
    store: _ConformanceRefreshFamilyStore, account: LocalAccountState[object]
) -> None:
    command = _conformance_refresh_family_command(account, marker=3)
    if not await store.create_family(command, event=_conformance_event("create-atomic-refresh")):
        message = "RefreshTokenFamilyStore.rotate atomicity setup invariant: a fresh family must be created"
        raise AssertionError(message)
    context = _conformance_refresh_context(command)
    commands = tuple(_conformance_rotate_command(context, command, marker) for marker in (4, 5))
    results: list[tuple[RotateRefreshCommand, RefreshRotationOutcome]] = []

    async def rotate(candidate: RotateRefreshCommand) -> bool:
        result = await store.rotate(candidate, now=_DEFAULT_NOW, event=_conformance_event("rotate-refresh"))
        results.append((candidate, result))
        return _won_by_status(result.status, winning=RefreshRotationStatus.ROTATED)

    def contender(candidate: RotateRefreshCommand) -> Callable[[], Awaitable[bool]]:
        async def attempt() -> bool:
            return await rotate(candidate)

        return attempt

    winners = await _single_winner(tuple(contender(candidate) for candidate in commands))
    if winners != 1:
        message = "RefreshTokenFamilyStore.rotate atomicity invariant: two contenders must produce one rotation"
        raise AssertionError(message)
    winner, winner_result = next(
        (candidate, result) for candidate, result in results if result.status is RefreshRotationStatus.ROTATED
    )
    loser, loser_result = next((candidate, result) for candidate, result in results if candidate is not winner)
    winner_context = await store.prepare_rotation(
        RefreshTokenProof(winner.successor_id, winner.successor_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-atomic-winner"),
    )
    loser_context = await store.prepare_rotation(
        RefreshTokenProof(loser.successor_id, loser.successor_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-atomic-loser"),
    )
    if (
        winner_result.sealed_receipt != winner.sealed_receipt
        or loser_result.status is RefreshRotationStatus.ROTATED
        or loser_result.sealed_receipt is not None
        or winner_context != _conformance_successor_context(winner)
        or not isinstance(loser_context, RefreshPreflightOutcome)
        or loser_context.status is not RefreshRotationStatus.INVALID
    ):
        message = (
            "RefreshTokenFamilyStore.rotate durable-state invariant: one exact successor and receipt must persist, "
            "with no loser successor"
        )
        raise AssertionError(message)
    replay = await store.prepare_rotation(
        RefreshTokenProof(command.token_id, command.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-atomic-replay"),
    )
    revoked_successor = await store.prepare_rotation(
        RefreshTokenProof(winner.successor_id, winner.successor_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-atomic-revoked-successor"),
    )
    if (
        not isinstance(replay, RefreshPreflightOutcome)
        or replay.status is not RefreshRotationStatus.REPLAY_DETECTED
        or not replay.family_revoked
        or not isinstance(revoked_successor, RefreshPreflightOutcome)
        or revoked_successor.status is not RefreshRotationStatus.REVOKED
        or not revoked_successor.family_revoked
    ):
        message = (
            "RefreshTokenFamilyStore.prepare_rotation replay invariant: "
            "unkeyed consumed-token reuse must revoke the family"
        )
        raise AssertionError(message)


async def _assert_refresh_rotation_commit(
    store: _ConformanceRefreshFamilyStore, account: LocalAccountState[object]
) -> None:
    command = _conformance_refresh_family_command(account, marker=6)
    if not await store.create_family(command, event=_conformance_event("create-commit-refresh")):
        message = "RefreshTokenFamilyStore.rotate partial-write setup invariant: a fresh family must be created"
        raise AssertionError(message)
    context = _conformance_refresh_context(command)
    rotation = _conformance_rotate_command(context, command, marker=7)
    result = await store.rotate(rotation, now=_DEFAULT_NOW, event=_conformance_event("rotate-commit-refresh"))
    replay = await store.prepare_rotation(
        RefreshTokenProof(command.token_id, command.token_digest),
        rotation.idempotency_digest,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-commit-receipt"),
    )
    successor = await store.prepare_rotation(
        RefreshTokenProof(rotation.successor_id, rotation.successor_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-commit-successor"),
    )
    if (
        result.status is not RefreshRotationStatus.ROTATED
        or result.sealed_receipt != rotation.sealed_receipt
        or not isinstance(replay, RefreshReceiptReplay)
        or replay.sealed_receipt != rotation.sealed_receipt
        or replay.context != context
        or successor != _conformance_successor_context(rotation)
    ):
        message = (
            "RefreshTokenFamilyStore.rotate partial-write invariant: "
            "consume, successor, and receipt must commit together"
        )
        raise AssertionError(message)


async def _assert_refresh_late_rotation_rejection(
    store: _ConformanceRefreshFamilyStore, account: LocalAccountState[object]
) -> None:
    expiry_command = _conformance_refresh_family_command(account, marker=10)
    if not await store.create_family(expiry_command, event=_conformance_event("create-late-expiry-refresh")):
        message = "RefreshTokenFamilyStore.rotate late-expiry setup invariant: a fresh family must be created"
        raise AssertionError(message)
    expiry_context = await store.prepare_rotation(
        RefreshTokenProof(expiry_command.token_id, expiry_command.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-late-expiry-refresh"),
    )
    if not isinstance(expiry_context, RefreshFamilyContext) or expiry_context != _conformance_refresh_context(
        expiry_command
    ):
        message = "RefreshTokenFamilyStore.rotate late-expiry setup invariant: an active context must be prepared"
        raise AssertionError(message)
    expired_rotation = _conformance_rotate_command(expiry_context, expiry_command, marker=16)
    expired_result = await store.rotate(
        expired_rotation, now=expiry_command.token_expires_at, event=_conformance_event("rotate-late-expiry-refresh")
    )
    expired_successor = await store.prepare_rotation(
        RefreshTokenProof(expired_rotation.successor_id, expired_rotation.successor_digest),
        None,
        now=expiry_command.token_expires_at,
        event=_conformance_event("prepare-late-expiry-successor"),
    )
    if (
        expired_result.status is RefreshRotationStatus.ROTATED
        or expired_result.sealed_receipt is not None
        or not isinstance(expired_successor, RefreshPreflightOutcome)
        or expired_successor.status is not RefreshRotationStatus.INVALID
    ):
        message = (
            "RefreshTokenFamilyStore.rotate late-expiry invariant: expired commit must leave no successor or receipt"
        )
        raise AssertionError(message)

    epoch_command = _conformance_refresh_family_command(account, marker=13)
    if not await store.create_family(epoch_command, event=_conformance_event("create-late-epoch-refresh")):
        message = "RefreshTokenFamilyStore.rotate epoch setup invariant: a fresh family must be created"
        raise AssertionError(message)
    epoch_context = await store.prepare_rotation(
        RefreshTokenProof(epoch_command.token_id, epoch_command.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-late-epoch-refresh"),
    )
    password_state = await store.get_password_state(account.account_id)
    if (
        not isinstance(epoch_context, RefreshFamilyContext)
        or epoch_context != _conformance_refresh_context(epoch_command)
        or password_state is None
    ):
        message = "RefreshTokenFamilyStore.rotate epoch setup invariant: prepared families require password state"
        raise AssertionError(message)
    changed = await store.replace_password_and_bump_epoch(
        account.account_id,
        "conformance-refresh-epoch-bump",
        expected_epoch=epoch_context.security_epoch,
        event=_conformance_event("bump-refresh-epoch"),
    )
    epoch_rotation = _conformance_rotate_command(epoch_context, epoch_command, marker=14)
    epoch_result = await store.rotate(
        epoch_rotation, now=_DEFAULT_NOW, event=_conformance_event("rotate-late-epoch-refresh")
    )
    epoch_successor = await store.prepare_rotation(
        RefreshTokenProof(epoch_rotation.successor_id, epoch_rotation.successor_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-late-epoch-successor"),
    )
    if (
        changed.status is not PasswordChangeStatus.CHANGED
        or epoch_result.status is RefreshRotationStatus.ROTATED
        or epoch_result.sealed_receipt is not None
        or not isinstance(epoch_successor, RefreshPreflightOutcome)
        or epoch_successor.status is not RefreshRotationStatus.INVALID
    ):
        message = (
            "RefreshTokenFamilyStore.rotate epoch invariant: stale prepared context must leave no successor or receipt"
        )
        raise AssertionError(message)


async def _assert_refresh_replay_and_idempotency(
    store: _ConformanceRefreshFamilyStore, account: LocalAccountState[object]
) -> None:
    command = _conformance_refresh_family_command(account, marker=8)
    if not await store.create_family(command, event=_conformance_event("create-replay-refresh")):
        message = "RefreshTokenFamilyStore.prepare_rotation replay setup invariant: a fresh family must be created"
        raise AssertionError(message)
    context = _conformance_refresh_context(command)
    rotation = _conformance_rotate_command(context, command, marker=9)
    await store.rotate(rotation, now=_DEFAULT_NOW, event=_conformance_event("rotate-replay-refresh"))
    receipt = await store.prepare_rotation(
        RefreshTokenProof(command.token_id, command.token_digest),
        rotation.idempotency_digest,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-idempotent-refresh"),
    )
    if not isinstance(receipt, RefreshReceiptReplay) or receipt.sealed_receipt != rotation.sealed_receipt:
        message = (
            "RefreshTokenFamilyStore.prepare_rotation idempotency invariant: matching retries must recover one receipt"
        )
        raise AssertionError(message)
    replay = await store.prepare_rotation(
        RefreshTokenProof(command.token_id, command.token_digest),
        bytes((10,)) * 32,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-replayed-refresh"),
    )
    successor = await store.prepare_rotation(
        RefreshTokenProof(rotation.successor_id, rotation.successor_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-revoked-successor"),
    )
    if (
        not isinstance(replay, RefreshPreflightOutcome)
        or replay.status is not RefreshRotationStatus.REPLAY_DETECTED
        or not replay.family_revoked
        or not isinstance(successor, RefreshPreflightOutcome)
        or successor.status is not RefreshRotationStatus.REVOKED
        or not successor.family_revoked
    ):
        message = (
            "RefreshTokenFamilyStore.prepare_rotation replay invariant: consumed-token reuse must revoke its family"
        )
        raise AssertionError(message)


async def _assert_refresh_ownership(store: _ConformanceRefreshFamilyStore, account: LocalAccountState[object]) -> None:
    command = _conformance_refresh_family_command(account, marker=11)
    if not await store.create_family(command, event=_conformance_event("create-owned-refresh")):
        message = (
            "RefreshTokenFamilyStore.revoke_token_for_account ownership setup invariant: a fresh family must be created"
        )
        raise AssertionError(message)
    other = await _conformance_register_account(store, "refresh-other@example.com")
    if await store.revoke_token_for_account(
        other.account_id,
        command.token_id,
        command.token_digest,
        event=_conformance_event("cross-account-refresh-revoke"),
    ):
        message = (
            "RefreshTokenFamilyStore.revoke_token_for_account ownership invariant: "
            "another account must not revoke a family"
        )
        raise AssertionError(message)
    result = await store.prepare_rotation(
        RefreshTokenProof(command.token_id, command.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-owned-refresh"),
    )
    if not isinstance(result, RefreshFamilyContext):
        message = (
            "RefreshTokenFamilyStore.revoke_token_for_account ownership invariant: "
            "rejected cross-account revocation must not mutate"
        )
        raise AssertionError(message)  # noqa: TRY004 - conformance failures are intentionally AssertionError


async def assert_mfa_store_conformance(
    factory: "Callable[[], MFAStore]", *, identifiers: "Callable[[str, int], str] | None" = None
) -> None:
    """Assert atomic TOTP counter and recovery-code consumption.

    Args:
        factory: Isolated zero-argument MFA-store factory.

        identifiers: Optional deterministic ``(namespace, sequence)`` account
            identifier factory for typed referential backends; ``None`` keeps
            the fixed conformance constants.

    Returns:
        None when every MFA-store invariant holds.

    Raises:
        AssertionError: If a counter update is non-atomic or a recovery code can be reused.
    """
    from litestar_security.typing import require_dependency

    require_dependency("pyotp")
    from litestar_security.accounts._mfa import PendingTOTPEnrollment, ProtectedSecret, RecoveryCodeDigest, TOTPPolicy

    ids = _resolve_conformance_account_ids(identifiers)
    store = factory()
    enrollment = PendingTOTPEnrollment(
        enrollment_id="conformance-enrollment",
        method_id="conformance-totp",
        account_id=ids.account,
        protected_secret=ProtectedSecret(ciphertext=b"secret", key_version="v1"),
        policy=TOTPPolicy(),
        created_at=_DEFAULT_NOW,
        expires_at=_DEFAULT_NOW + timedelta(minutes=5),
    )
    await store.create_totp_enrollment(enrollment)
    activated = await store.activate_totp(
        enrollment.account_id,
        enrollment.enrollment_id,
        accepted_counter=1,
        login_method=LoginMethod("conformance-totp", "totp", _DEFAULT_NOW),
        event=_conformance_event("activate-totp"),
        now=_DEFAULT_NOW,
    )
    if activated is None:
        raise AssertionError("MFAStore setup invariant: a fresh enrollment must activate")

    async def advance() -> bool:
        return await store.advance_totp_counter(activated.method_id, accepted_counter=2, now=_DEFAULT_NOW)

    if await _single_winner((advance, advance)) != 1:
        raise AssertionError("MFAStore.advance_totp_counter atomicity invariant: two contenders must have one winner")
    if await store.advance_totp_counter(activated.method_id, accepted_counter=2, now=_DEFAULT_NOW):
        raise AssertionError("MFAStore.advance_totp_counter monotonicity invariant: equal counters must be refused")
    if await store.advance_totp_counter(activated.method_id, accepted_counter=1, now=_DEFAULT_NOW):
        raise AssertionError("MFAStore.advance_totp_counter monotonicity invariant: lower counters must be refused")
    digest = b"r" * 32
    await store.replace_recovery_codes(
        enrollment.account_id, (RecoveryCodeDigest(enrollment.account_id, "v1", digest),), now=_DEFAULT_NOW
    )

    async def consume() -> bool:
        return await store.consume_recovery_code(enrollment.account_id, digest, now=_DEFAULT_NOW)

    if await _single_winner((consume, consume)) != 1:
        raise AssertionError("MFAStore.consume_recovery_code atomicity invariant: two contenders must have one winner")


async def assert_mfa_login_challenge_store_conformance(
    factory: "Callable[[], MFALoginChallengeStore]", *, identifiers: "Callable[[str, int], str] | None" = None
) -> None:
    """Assert MFA-login challenges are bound, one-shot, and expiry-safe.

    Args:
        factory: Isolated zero-argument MFA login challenge-store factory.

        identifiers: Optional deterministic ``(namespace, sequence)`` account
            identifier factory for typed referential backends; ``None`` keeps
            the fixed conformance constants.

    Returns:
        None when every MFA login challenge invariant holds.

    Raises:
        AssertionError: If a challenge can be replayed or survives a rejected binding or expiry.
    """
    from litestar_security.typing import require_dependency

    require_dependency("pyotp")
    store = factory()
    ids = _resolve_conformance_account_ids(identifiers)
    wrong_account = _conformance_mfa_login_challenge(b"m" * 32, account_id=ids.account)
    await store.put(wrong_account)
    if (
        await store.consume(
            wrong_account.challenge_digest,
            account_id="other",
            security_epoch=wrong_account.security_epoch,
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("MFALoginChallengeStore binding invariant: wrong account must not consume successfully")
    if (
        await store.consume(
            wrong_account.challenge_digest,
            account_id=wrong_account.account_id,
            security_epoch=wrong_account.security_epoch,
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("MFALoginChallengeStore account-binding burn invariant: a rejected binding must burn")
    wrong_epoch = _conformance_mfa_login_challenge(b"n" * 32, account_id=ids.account)
    await store.put(wrong_epoch)
    if (
        await store.consume(
            wrong_epoch.challenge_digest,
            account_id=wrong_epoch.account_id,
            security_epoch=wrong_epoch.security_epoch + 1,
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("MFALoginChallengeStore epoch invariant: wrong epoch must not consume successfully")
    if (
        await store.consume(
            wrong_epoch.challenge_digest,
            account_id=wrong_epoch.account_id,
            security_epoch=wrong_epoch.security_epoch,
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("MFALoginChallengeStore epoch-binding burn invariant: a rejected binding must burn")
    winner = _conformance_mfa_login_challenge(b"w" * 32, account_id=ids.account)
    await store.put(winner)

    async def consume() -> "MFALoginChallenge | None":
        return await store.consume(
            winner.challenge_digest,
            account_id=winner.account_id,
            security_epoch=winner.security_epoch,
            now=_DEFAULT_NOW,
        )

    if await _single_winner((lambda: _presence(consume()), lambda: _presence(consume()))) != 1:
        raise AssertionError("MFALoginChallengeStore atomicity invariant: two contenders must have one winner")
    expired = _conformance_mfa_login_challenge(
        b"x" * 32, expires_at=_DEFAULT_NOW + timedelta(seconds=1), account_id=ids.account
    )
    await store.put(expired)
    if (
        await store.consume(
            expired.challenge_digest, account_id=expired.account_id, security_epoch=0, now=expired.expires_at
        )
        is not None
    ):
        raise AssertionError("MFALoginChallengeStore expiry invariant: expired challenges must be rejected")
    if (
        await store.consume(expired.challenge_digest, account_id=expired.account_id, security_epoch=0, now=_DEFAULT_NOW)
        is not None
    ):
        raise AssertionError("MFALoginChallengeStore expiry burn invariant: expired challenges must be removed")


async def assert_webauthn_challenge_store_conformance(
    factory: "Callable[[], WebAuthnChallengeStore]", *, identifiers: "Callable[[str, int], str] | None" = None
) -> None:
    """Assert WebAuthn challenges burn once and enforce every binding.

    Args:
        factory: Isolated zero-argument WebAuthn challenge-store factory.

        identifiers: Optional deterministic ``(namespace, sequence)`` account
            identifier factory for typed referential backends; ``None`` keeps
            the fixed conformance constants.

    Returns:
        None when every WebAuthn challenge invariant holds.

    Raises:
        AssertionError: If consume-once, binding, purpose, or expiry behavior is violated.
    """
    from litestar_security.typing import require_dependency

    require_dependency("webauthn")
    store = factory()
    ids = _resolve_conformance_account_ids(identifiers)
    wrong_binding = _conformance_webauthn_challenge(b"b" * 32, account_id=ids.account)
    await store.put(wrong_binding)
    if (
        await store.consume(
            wrong_binding.challenge_digest, binding_digest=b"z" * 32, purpose=wrong_binding.purpose, now=_DEFAULT_NOW
        )
        is not None
    ):
        raise AssertionError("WebAuthnChallengeStore binding invariant: wrong binding must return None")
    if (
        await store.consume(
            wrong_binding.challenge_digest,
            binding_digest=wrong_binding.binding_digest,
            purpose=wrong_binding.purpose,
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("WebAuthnChallengeStore binding burn invariant: mismatched challenge must be removed")
    wrong_purpose = _conformance_webauthn_challenge(b"p" * 32, account_id=ids.account)
    await store.put(wrong_purpose)
    if (
        await store.consume(
            wrong_purpose.challenge_digest,
            binding_digest=wrong_purpose.binding_digest,
            purpose="other",
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("WebAuthnChallengeStore purpose invariant: wrong purpose must return None")
    if (
        await store.consume(
            wrong_purpose.challenge_digest,
            binding_digest=wrong_purpose.binding_digest,
            purpose=wrong_purpose.purpose,
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("WebAuthnChallengeStore purpose burn invariant: mismatched challenge must be removed")
    winner = _conformance_webauthn_challenge(b"w" * 32, account_id=ids.account)
    await store.put(winner)

    async def consume() -> "WebAuthnChallenge | None":
        return await store.consume(
            winner.challenge_digest, binding_digest=winner.binding_digest, purpose=winner.purpose, now=_DEFAULT_NOW
        )

    if await _single_winner((lambda: _presence(consume()), lambda: _presence(consume()))) != 1:
        raise AssertionError("WebAuthnChallengeStore atomicity invariant: two contenders must have one winner")
    expired = _conformance_webauthn_challenge(
        b"x" * 32, expires_at=_DEFAULT_NOW + timedelta(seconds=1), account_id=ids.account
    )
    await store.put(expired)
    if (
        await store.consume(
            expired.challenge_digest,
            binding_digest=expired.binding_digest,
            purpose=expired.purpose,
            now=expired.expires_at,
        )
        is not None
    ):
        raise AssertionError("WebAuthnChallengeStore expiry invariant: expired challenges must be rejected")


async def assert_oauth_transaction_store_conformance(factory: Callable[[], OAuthTransactionStore]) -> None:
    """Assert OAuth transactions preserve matching, expiry, and one-shot consumption.

    Args:
        factory: Isolated zero-argument OAuth transaction-store factory.

    Returns:
        None when every OAuth transaction invariant holds.

    Raises:
        AssertionError: If callback state can be replayed or a mismatched callback is accepted.
    """
    store = factory()
    transaction = _conformance_oauth_transaction(b"s" * 32)
    await store.create(transaction)
    if (
        await store.consume(
            state_digest=transaction.state_digest,
            binding_digest=b"z" * 32,
            provider=transaction.provider,
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("OAuthTransactionStore binding invariant: wrong binding must return None")
    if (
        await store.consume(
            state_digest=transaction.state_digest,
            binding_digest=transaction.binding_digest,
            provider="other-provider",
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("OAuthTransactionStore provider invariant: wrong provider must return None")
    winner = await store.consume(
        state_digest=transaction.state_digest,
        binding_digest=transaction.binding_digest,
        provider=transaction.provider,
        now=_DEFAULT_NOW,
    )
    if winner != transaction:
        raise AssertionError("OAuthTransactionStore matching invariant: an exact callback must return its transaction")
    replay = await store.consume(
        state_digest=transaction.state_digest,
        binding_digest=transaction.binding_digest,
        provider=transaction.provider,
        now=_DEFAULT_NOW,
    )
    if replay is not None:
        raise AssertionError("OAuthTransactionStore consume-once invariant: a consumed transaction must not replay")
    concurrent = _conformance_oauth_transaction(b"c" * 32)
    await store.create(concurrent)

    async def consume() -> OAuthTransaction | None:
        return await store.consume(
            state_digest=concurrent.state_digest,
            binding_digest=concurrent.binding_digest,
            provider=concurrent.provider,
            now=_DEFAULT_NOW,
        )

    if await _single_winner((lambda: _presence(consume()), lambda: _presence(consume()))) != 1:
        raise AssertionError("OAuthTransactionStore atomicity invariant: two contenders must have one winner")
    expired = _conformance_oauth_transaction(b"e" * 32, expires_at=_DEFAULT_NOW + timedelta(seconds=1))
    await store.create(expired)
    if (
        await store.consume(
            state_digest=expired.state_digest,
            binding_digest=expired.binding_digest,
            provider=expired.provider,
            now=expired.expires_at,
        )
        is not None
    ):
        raise AssertionError("OAuthTransactionStore expiry invariant: expired transactions must be rejected")


async def assert_websocket_connect_token_store_conformance(
    factory: Callable[[], WebSocketConnectTokenStore], *, identifiers: "Callable[[str, int], str] | None" = None
) -> None:
    """Assert WebSocket connect tokens are exact, one-shot, and expiry-safe.

    Args:
        factory: Isolated zero-argument WebSocket connect-token store factory.

        identifiers: Optional deterministic ``(namespace, sequence)`` account
            identifier factory for typed referential backends; ``None`` keeps
            the fixed conformance constants.

    Returns:
        None when every WebSocket connect-token invariant holds.

    Raises:
        AssertionError: If a wrong digest burns a token, or a token can be reused or outlive expiry.
    """
    store = factory()
    ids = _resolve_conformance_account_ids(identifiers)
    record = _conformance_connect_token_record("aWlpaWlpaWlpaWlpaWlpaQ", b"d" * 32, subject_id=ids.subject)
    await store.create(record)
    if await store.consume(connect_token_id=record.connect_token_id, digest=b"z" * 32, now=_DEFAULT_NOW) is not None:
        raise AssertionError("WebSocketConnectTokenStore digest invariant: wrong digest must return None")
    if await store.consume(connect_token_id=record.connect_token_id, digest=record.digest, now=_DEFAULT_NOW) != record:
        raise AssertionError(
            "WebSocketConnectTokenStore digest preservation invariant: wrong digest must not consume the record"
        )
    winner = _conformance_connect_token_record("ampqampqampqampqampqag", b"w" * 32, subject_id=ids.subject)
    await store.create(winner)

    async def consume() -> WebSocketConnectAuthorization | None:
        return await store.consume(connect_token_id=winner.connect_token_id, digest=winner.digest, now=_DEFAULT_NOW)

    if await _single_winner((lambda: _presence(consume()), lambda: _presence(consume()))) != 1:
        raise AssertionError("WebSocketConnectTokenStore atomicity invariant: two contenders must have one winner")
    expired = _conformance_connect_token_record(
        "eXh4eXh4eXh4eXh4eXh4eA", b"e" * 32, expires_at=_DEFAULT_NOW + timedelta(seconds=1), subject_id=ids.subject
    )
    await store.create(expired)
    if (
        await store.consume(connect_token_id=expired.connect_token_id, digest=expired.digest, now=expired.expires_at)
        is not None
    ):
        raise AssertionError("WebSocketConnectTokenStore expiry invariant: expired records must be rejected")
    if (
        await store.consume(connect_token_id=expired.connect_token_id, digest=expired.digest, now=_DEFAULT_NOW)
        is not None
    ):
        raise AssertionError("WebSocketConnectTokenStore expiry deletion invariant: expired records must be removed")


async def assert_passkey_store_conformance(
    factory: "Callable[[], PasskeyStore]", *, identifiers: "Callable[[str, int], str] | None" = None
) -> None:
    """Assert optimistic assertion recording and clone-risk results.

    Args:
        factory: Isolated zero-argument passkey-store factory.

        identifiers: Optional deterministic ``(namespace, sequence)`` account
            identifier factory for typed referential backends; ``None`` keeps
            the fixed conformance constants.

    Returns:
        None when every passkey-store invariant holds.

    Raises:
        AssertionError: If only one optimistic writer is not recorded or clone risk is lost.
    """
    from litestar_security.typing import require_dependency

    require_dependency("webauthn")
    from litestar_security.accounts._passkeys import PasskeyAssertionStatus

    store = factory()
    ids = _resolve_conformance_account_ids(identifiers)
    credential = _conformance_passkey_credential(b"credential", account_id=ids.account)
    if not await store.add_credential(
        credential,
        login_method=LoginMethod("passkey-method", "passkey", _DEFAULT_NOW),
        event=_conformance_event("add-passkey"),
    ):
        raise AssertionError("PasskeyStore setup invariant: a fresh credential must be added")

    async def record() -> PasskeyAssertionStatus:
        return await store.record_assertion(
            credential.credential_id,
            expected_version=0,
            sign_count=2,
            backup_eligible=False,
            backup_state=False,
            clone_risk=False,
            now=_DEFAULT_NOW,
        )

    outcomes: list[PasskeyAssertionStatus] = []
    async with create_task_group() as group:
        group.start_soon(_append_result, record, outcomes)
        group.start_soon(_append_result, record, outcomes)
    if outcomes.count(PasskeyAssertionStatus.RECORDED) != 1 or outcomes.count(PasskeyAssertionStatus.CONFLICT) != 1:
        raise AssertionError(
            "PasskeyStore.record_assertion atomicity invariant: contenders must return RECORDED and CONFLICT"
        )
    recorded = await store.get_credential(credential.credential_id)
    expected_sign_count = 2
    if recorded is None or recorded.version != 1 or recorded.sign_count != expected_sign_count or recorded.suspect:
        raise AssertionError(
            "PasskeyStore.record_assertion state invariant: winning assertion must persist exact state"
        )
    clone = _conformance_passkey_credential(b"clone", account_id=ids.account)
    await store.add_credential(
        clone, login_method=LoginMethod("clone-method", "passkey", _DEFAULT_NOW), event=_conformance_event("add-clone")
    )
    if (
        await store.record_assertion(
            clone.credential_id,
            expected_version=0,
            sign_count=0,
            backup_eligible=False,
            backup_state=False,
            clone_risk=True,
            now=_DEFAULT_NOW,
        )
        is not PasskeyAssertionStatus.CLONE_RISK
    ):
        raise AssertionError(
            "PasskeyStore.record_assertion clone-risk invariant: a clone-risk assertion must return CLONE_RISK"
        )
    cloned = await store.get_credential(clone.credential_id)
    if cloned is None or cloned.version != 1 or not cloned.suspect:
        raise AssertionError("PasskeyStore.record_assertion clone-state invariant: clone risk must persist suspicion")


async def assert_oidc_session_logout_store_conformance(factory: Callable[[], OIDCSessionLogoutStore]) -> None:
    """Assert atomic OIDC logout against a fixed seeded mapped-session scenario.

    The factory must return a fresh store seeded with two active mappings for
    ``("conformance-provider", "https://issuer.example", "conformance-subject",
    "conformance-session")``, one unrelated mapping, and the exact
    ``"conformance-browser-binding"`` front-channel binding for that tuple.

    Args:
        factory: Isolated zero-argument factory that returns the required seeded store.

    Returns:
        None when the store preserves exact OIDC ownership and one-shot semantics.

    Raises:
        AssertionError: If the seeded mappings can be incorrectly revoked or replayed.
    """
    identity = _conformance_oidc_logout_identity("backchannel")
    expected_count = 2
    store = factory()
    if await store.consume_backchannel(identity, now=_DEFAULT_NOW) != expected_count:
        raise AssertionError(
            "OIDCSessionLogoutStore.consume_backchannel mapped-session invariant: "
            "exact identity must revoke two mappings"
        )
    if await store.consume_backchannel(identity, now=_DEFAULT_NOW) is not None:
        raise AssertionError(
            "OIDCSessionLogoutStore.consume_backchannel replay invariant: a consumed token id must return None"
        )
    for name, mismatch in (
        (
            "provider",
            replace(
                identity, provider="other-provider", token_id=_conformance_oidc_logout_identity("provider").token_id
            ),
        ),
        (
            "issuer",
            replace(
                identity,
                issuer="https://other-issuer.example",
                token_id=_conformance_oidc_logout_identity("issuer").token_id,
            ),
        ),
        (
            "subject",
            replace(identity, subject="other-subject", token_id=_conformance_oidc_logout_identity("subject").token_id),
        ),
        (
            "session",
            replace(
                identity, session_id="other-session", token_id=_conformance_oidc_logout_identity("session").token_id
            ),
        ),
    ):
        if await factory().consume_backchannel(mismatch, now=_DEFAULT_NOW) != 0:
            message = (
                f"OIDCSessionLogoutStore.consume_backchannel {name} invariant: "
                "non-matching identities must revoke nothing"
            )
            raise AssertionError(message)
    frontchannel = factory()
    if (
        await frontchannel.revoke_frontchannel(
            identity.provider,
            identity.issuer,
            cast("str", identity.session_id),
            binding="other-browser-binding",
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError(
            "OIDCSessionLogoutStore.revoke_frontchannel binding invariant: wrong browser binding must return None"
        )
    if (
        await frontchannel.revoke_frontchannel(
            identity.provider,
            identity.issuer,
            cast("str", identity.session_id),
            binding="conformance-browser-binding",
            now=_DEFAULT_NOW,
        )
        != expected_count
    ):
        raise AssertionError(
            "OIDCSessionLogoutStore.revoke_frontchannel mapped-session invariant: "
            "owned mapping must revoke two sessions"
        )
    if (
        await frontchannel.revoke_frontchannel(
            identity.provider,
            identity.issuer,
            cast("str", identity.session_id),
            binding="conformance-browser-binding",
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError(
            "OIDCSessionLogoutStore.revoke_frontchannel replay invariant: consumed mapping must return None"
        )


async def assert_step_up_store_conformance(
    factory: "Callable[[], StepUpStore]", *, identifiers: "Callable[[str, int], str] | None" = None
) -> None:
    """Assert one-time exact-binding step-up grant consumption.

    Args:
        factory: Isolated zero-argument step-up store factory.

        identifiers: Optional deterministic ``(namespace, sequence)`` account
            identifier factory for typed referential backends; ``None`` keeps
            the fixed conformance constants.

    Returns:
        None when the store has one winner and rejects every distinct binding mismatch.

    Raises:
        AssertionError: If a grant can be replayed, double-consumed, or accepted with an altered binding.
    """
    from litestar_security.typing import require_dependency

    require_dependency("pyotp")
    record = _conformance_step_up_record(principal_id=_resolve_conformance_account_ids(identifiers).principal)
    store = factory()
    await store.put(record)

    async def consume() -> "StepUpGrantState | None":
        return await store.consume(
            record.grant_digest,
            principal_id=record.principal_id,
            security_epoch=record.security_epoch,
            purpose=record.purpose,
            transport_digest=record.transport_digest,
            now=record.authenticated_at,
        )

    if await _single_winner((lambda: _presence(consume()), lambda: _presence(consume()))) != 1:
        message = "StepUpStore.consume atomicity invariant: exactly one concurrent consume must return the grant"
        raise AssertionError(message)
    if await consume() is not None:
        raise AssertionError("StepUpStore.consume replay invariant: a consumed grant must return None")
    for name, values in (
        ("principal", {"principal_id": "other-principal"}),
        ("epoch", {"security_epoch": record.security_epoch + 1}),
        ("purpose", {"purpose": "other-purpose"}),
        ("transport", {"transport_digest": b"u" * 32}),
        ("expiry", {"now": record.expires_at}),
    ):
        mismatched = factory()
        await mismatched.put(record)
        arguments: dict[str, object] = {
            "principal_id": record.principal_id,
            "security_epoch": record.security_epoch,
            "purpose": record.purpose,
            "transport_digest": record.transport_digest,
            "now": record.authenticated_at,
        }
        arguments.update(values)
        if await mismatched.consume(record.grant_digest, **arguments) is not None:  # type: ignore[arg-type]  # conformance matrix preserves named protocol arguments
            message = f"StepUpStore.consume {name} invariant: altered {name} must return None"
            raise AssertionError(message)


async def assert_oauth_account_store_conformance(
    factory: Callable[[], OAuthAccountStore], *, identifiers: "Callable[[str, int], str] | None" = None
) -> None:
    """Assert final-method protection and atomic OAuth identity unlinking.

    Args:
        factory: Isolated zero-argument OAuth account-store factory.

        identifiers: Optional deterministic ``(namespace, sequence)`` account
            identifier factory for typed referential backends; ``None`` keeps
            the fixed conformance constants.

    Returns:
        None when every OAuth account-store invariant holds.

    Raises:
        AssertionError: If a final method can be removed or concurrent unlinking has two winners.
    """
    ids = _resolve_conformance_account_ids(identifiers)
    store = factory()
    identity = _conformance_provider_identity("first")
    first = await store.link(
        ids.account,
        identity,
        _conformance_provider_grant(),
        _conformance_provider_tokens("first"),
        retain_tokens=False,
        now=_DEFAULT_NOW,
    )
    wrong_owner = await store.unlink(
        "other-account", first.provider, first.provider_account_id, require_remaining=True, now=_DEFAULT_NOW
    )
    if wrong_owner.status is not UnlinkStatus.NOT_FOUND:
        raise AssertionError("OAuthAccountStore ownership invariant: another account must receive NOT_FOUND")
    final = await store.unlink(
        ids.account, first.provider, first.provider_account_id, require_remaining=True, now=_DEFAULT_NOW
    )
    if final.status is not UnlinkStatus.FINAL_METHOD:
        raise AssertionError("OAuthAccountStore final-method invariant: the last identity must return FINAL_METHOD")
    preserved = await store.resolve_provider_account(ids.account, first.provider)
    if preserved != first:
        raise AssertionError("OAuthAccountStore ownership preservation invariant: rejected unlink must not mutate")
    second_identity = replace(_conformance_provider_identity("second"), provider="second-provider")
    second = await store.link(
        ids.account,
        second_identity,
        _conformance_provider_grant(),
        _conformance_provider_tokens("second"),
        retain_tokens=False,
        now=_DEFAULT_NOW,
    )

    async def unlink() -> UnlinkStatus:
        return (
            await store.unlink(
                ids.account, second.provider, second.provider_account_id, require_remaining=True, now=_DEFAULT_NOW
            )
        ).status

    statuses: list[UnlinkStatus] = []
    async with create_task_group() as group:
        group.start_soon(_append_result, unlink, statuses)
        group.start_soon(_append_result, unlink, statuses)
    if statuses.count(UnlinkStatus.UNLINKED) != 1 or statuses.count(UnlinkStatus.NOT_FOUND) != 1:
        raise AssertionError(
            "OAuthAccountStore.unlink atomicity invariant: contenders must return UNLINKED and NOT_FOUND"
        )


async def assert_rate_limiter_conformance(
    factory: Callable[[int], RateLimiter], *, limit: int = 5, concurrency: int = 20
) -> None:
    """Assert exact atomic admission for concurrent acquires against one bucket.

    Args:
        factory: Factory receiving the budget that the returned limiter must enforce.
        limit: Positive number of attempts that the limiter must admit.
        concurrency: Number of concurrent attempts; it must be at least ``limit``.

    Returns:
        None when the limiter admits exactly ``limit`` concurrent attempts.

    Raises:
        ValueError: If ``limit`` or ``concurrency`` is not a valid conformance scenario.
        AssertionError: If concurrent acquires over-admit or under-admit the configured budget.
    """
    limit_value: object = limit
    concurrency_value: object = concurrency
    if limit_value.__class__ is not int or limit < 1:
        message = "Rate limiter conformance limit must be a positive integer"
        raise ValueError(message)
    if concurrency_value.__class__ is not int or concurrency < limit:
        message = "Rate limiter conformance concurrency must be an integer at least as large as limit"
        raise ValueError(message)
    limiter = factory(limit)
    request = RateLimitAttempt(operation="conformance.rate_limit", client_key="conformance-bucket")
    outcomes: list[bool] = []

    async def attempt() -> None:
        outcomes.append((await limiter.acquire(request)).allowed)

    async with create_task_group() as task_group:
        for _ in range(concurrency):
            task_group.start_soon(attempt)

    admitted = outcomes.count(True)
    if admitted != limit:
        message = (
            "RateLimiter.acquire atomicity invariant: N concurrent acquires against limit k must admit exactly k "
            f"(limit={limit}, concurrency={concurrency}, observed={admitted})"
        )
        raise AssertionError(message)


def _dispatch_assertion(name: str) -> Callable[..., Awaitable[None]]:
    """Dispatch to the assertion in testing package (honoring monkeypatches) or local definition."""
    import sys

    testing_mod = sys.modules.get("litestar_security.testing")
    if testing_mod is not None:
        target = getattr(testing_mod, name, None)
        if target is not None:
            return cast("Callable[..., Awaitable[None]]", target)
    return cast("Callable[..., Awaitable[None]]", globals()[name])


async def assert_security_backend_conformance(
    factories: StoreConformanceFactories,
    *,
    create_account: Callable[[str], Awaitable[None]] | None = None,
    identifiers: Callable[[str, int], str] | None = None,
) -> None:
    """Run only the conformance scenarios whose factories were supplied.

    Args:
        factories: Explicit feature factories to exercise.
        create_account: Optional async hook to seed prerequisite account rows. A
            relational backend enforcing account foreign keys needs every
            identifier the enabled scenarios reference to exist first.
        identifiers: Optional deterministic ``(namespace, sequence)`` account
            identifier factory. A backend persisting account references as
            typed columns (for example UUID foreign keys) supplies one so
            every account-scoped identifier the scenarios reference satisfies
            its column type; the default keeps the fixed conformance
            constants.

    Returns:
        None when every enabled feature passes.

    Raises:
        AssertionError: If any enabled feature violates its public protocol.
    """
    if create_account is not None:
        seed_ids = (
            _CONFORMANCE_ACCOUNT_IDS if identifiers is None else _resolve_conformance_account_ids(identifiers).seeded()
        )
        for default_account_id in seed_ids:
            await create_account(default_account_id)
    if factories.api_key_store is not None:
        await _dispatch_assertion("assert_api_key_store_conformance")(factories.api_key_store, identifiers=identifiers)
    if factories.local_account_store is not None:
        await _dispatch_assertion("assert_local_account_store_conformance")(factories.local_account_store)
    if factories.mfa_login_challenge_store is not None:
        await _dispatch_assertion("assert_mfa_login_challenge_store_conformance")(
            factories.mfa_login_challenge_store, identifiers=identifiers
        )
    if factories.mfa_store is not None:
        await _dispatch_assertion("assert_mfa_store_conformance")(factories.mfa_store, identifiers=identifiers)
    if factories.oidc_session_logout_store is not None:
        await _dispatch_assertion("assert_oidc_session_logout_store_conformance")(factories.oidc_session_logout_store)
    if factories.oauth_account_store is not None:
        await _dispatch_assertion("assert_oauth_account_store_conformance")(
            factories.oauth_account_store, identifiers=identifiers
        )
    if factories.oauth_transaction_protector is not None:
        await _dispatch_assertion("assert_oauth_transaction_protector_conformance")(
            factories.oauth_transaction_protector
        )
    if factories.oauth_transaction_store is not None:
        await _dispatch_assertion("assert_oauth_transaction_store_conformance")(factories.oauth_transaction_store)
    if factories.passkey_store is not None:
        await _dispatch_assertion("assert_passkey_store_conformance")(factories.passkey_store, identifiers=identifiers)
    if factories.refresh_family_store is not None:
        await _dispatch_assertion("assert_refresh_family_store_conformance")(factories.refresh_family_store)
    if factories.secret_protector is not None:
        await _dispatch_assertion("assert_secret_protector_conformance")(factories.secret_protector)
    if factories.session_registry is not None:
        await _dispatch_assertion("assert_session_registry_conformance")(
            factories.session_registry, identifiers=identifiers
        )
    if factories.step_up_store is not None:
        await _dispatch_assertion("assert_step_up_store_conformance")(factories.step_up_store, identifiers=identifiers)
    if factories.webauthn_challenge_store is not None:
        await _dispatch_assertion("assert_webauthn_challenge_store_conformance")(
            factories.webauthn_challenge_store, identifiers=identifiers
        )
    if factories.websocket_connect_token_store is not None:
        await _dispatch_assertion("assert_websocket_connect_token_store_conformance")(
            factories.websocket_connect_token_store, identifiers=identifiers
        )


def _conformance_api_key_record(key_id: str, *, subject_id: str = "conformance-subject") -> APIKeyState:
    return APIKeyState(key_id=key_id, subject_id=subject_id, digest=b"d" * 32)


def _conformance_session_command(
    *,
    marker: int,
    account_id: str,
    now: datetime = _DEFAULT_NOW,
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> CreateSessionCommand:
    """Build one deterministic session command with exact valid identifier material."""
    session_created_at = created_at if created_at is not None else now
    return CreateSessionCommand(
        session_id=_conformance_identifier(None, marker),
        binding_id=_conformance_identifier("sb_", marker),
        binding_digest=bytes((marker,)) * 32,
        account_id=account_id,
        security_epoch=1,
        created_at=session_created_at,
        authenticated_at=session_created_at,
        expires_at=expires_at if expires_at is not None else now + timedelta(minutes=5),
        display_metadata={"device": f"conformance-{marker}"},
    )


def _conformance_session_record(command: CreateSessionCommand) -> UserAuthSession:
    """Return the exact stored projection required by one session creation command."""
    return UserAuthSession(
        session_id=command.session_id,
        binding_id=command.binding_id,
        binding_digest=command.binding_digest,
        account_id=command.account_id,
        security_epoch=command.security_epoch,
        created_at=command.created_at,
        authenticated_at=command.authenticated_at,
        last_seen_at=command.created_at,
        expires_at=command.expires_at,
        display_metadata=command.display_metadata,
    )


def _conformance_refresh_family_command(
    account: LocalAccountState[object],
    *,
    marker: int,
    expires_at: datetime | None = None,
    token_expires_at: datetime | None = None,
    family_expires_at: datetime | None = None,
) -> CreateRefreshFamilyCommand:
    """Build one deterministic family command bound to a registered account epoch."""
    expiration = token_expires_at if token_expires_at is not None else expires_at
    token_expiry = expiration if expiration is not None else _DEFAULT_NOW + timedelta(minutes=5)
    family_expiry = family_expires_at if family_expires_at is not None else _DEFAULT_NOW + timedelta(minutes=10)
    return CreateRefreshFamilyCommand(
        token_id=_conformance_identifier("rt_", marker),
        token_digest=bytes((marker,)) * 32,
        account_id=account.account_id,
        family_id=_conformance_identifier("rf_", marker),
        security_epoch=account.security_epoch,
        created_at=_DEFAULT_NOW - timedelta(minutes=1) if expiration is not None else _DEFAULT_NOW,
        token_expires_at=token_expiry,
        family_expires_at=family_expiry,
        scopes=frozenset({"conformance"}),
    )


def _conformance_refresh_context(command: CreateRefreshFamilyCommand) -> RefreshFamilyContext:
    """Return the exact active context for a newly created refresh family."""
    return RefreshFamilyContext(
        account_id=command.account_id,
        family_id=command.family_id,
        security_epoch=command.security_epoch,
        token_expires_at=command.token_expires_at,
        family_expires_at=command.family_expires_at,
        scopes=command.scopes,
    )


def _conformance_successor_context(command: RotateRefreshCommand) -> RefreshFamilyContext:
    """Return the exact active context committed for a rotated successor token."""
    return RefreshFamilyContext(
        account_id=command.account_id,
        family_id=command.family_id,
        security_epoch=command.security_epoch,
        token_expires_at=command.successor_expires_at,
        family_expires_at=command.family_expires_at,
        scopes=command.scopes,
    )


def _conformance_rotate_command(
    context: RefreshFamilyContext, command: CreateRefreshFamilyCommand, marker: int
) -> RotateRefreshCommand:
    """Build a deterministic one-time successor and receipt for one family context."""
    return RotateRefreshCommand(
        token_id=command.token_id,
        token_digest=command.token_digest,
        account_id=context.account_id,
        family_id=context.family_id,
        security_epoch=context.security_epoch,
        successor_id=_conformance_identifier("rt_", marker),
        successor_digest=bytes((marker,)) * 32,
        successor_expires_at=context.token_expires_at,
        family_expires_at=context.family_expires_at,
        sealed_receipt=bytes((marker,)),
        receipt_expires_at=context.token_expires_at,
        idempotency_digest=bytes((marker,)) * 32,
        scopes=context.scopes,
    )


def _conformance_identifier(prefix: str | None, marker: int) -> str:
    """Build an exact base64url lookup identifier without randomness."""
    length = 16 if prefix is not None else 32
    value = urlsafe_b64encode(bytes((marker,)) * length).rstrip(b"=").decode("ascii")
    return f"{prefix or ''}{value}"


async def _conformance_register_account(
    store: RegistrationStore[object], normalized_identifier: str, *, verification: PurposeTokenDelivery | None = None
) -> LocalAccountState[object]:
    """Register one password account required by several local-account scenarios."""
    result = await store.register(
        _conformance_registration_command(normalized_identifier),
        "conformance-password-hash",
        invitation_digest=None,
        verification=verification,
        now=_DEFAULT_NOW,
        event=_conformance_event("register-setup"),
    )
    if result.status is not RegistrationStatus.CREATED or result.account is None:  # pragma: no cover - result invariant
        message = "RegistrationStore.register setup invariant: a fresh normalized identifier must create an account"
        raise AssertionError(message)
    return result.account


def _conformance_event(operation: str) -> SecurityEvent:
    return SecurityEvent(
        event_id=f"conformance-{operation}", occurred_at=_DEFAULT_NOW, operation=operation, outcome="conformance"
    )


def _conformance_registration_command(normalized_identifier: str) -> RegistrationCommand:
    return RegistrationCommand(normalized_identifier=normalized_identifier, display_name="Conformance")


def _conformance_verification_delivery(
    now: datetime, *, marker: int, maximum_attempts: int = 5
) -> PurposeTokenDelivery:
    return _conformance_token_delivery(
        TokenPurpose.VERIFICATION, now=now, marker=marker, maximum_attempts=maximum_attempts
    )


def _conformance_token_delivery(
    purpose: TokenPurpose, *, marker: int, now: datetime = _DEFAULT_NOW, maximum_attempts: int = 5
) -> PurposeTokenDelivery:
    marker_byte = bytes((marker,))
    return PurposeTokenCodec(pepper=bytes(32), entropy=lambda length: marker_byte * length).issue(
        purpose,
        now=now,
        lifetime=timedelta(minutes=5),
        template=purpose.value,
        destination=f"{purpose.value}@example.com",
        maximum_attempts=maximum_attempts,
    )


def _different_digest(digest: bytes) -> bytes:
    return bytes((digest[0] ^ 1,)) + digest[1:]


def _conformance_mfa_login_challenge(
    digest: bytes, *, expires_at: datetime | None = None, account_id: str = "conformance-account"
) -> "MFALoginChallenge":
    """Build a fixed valid MFA-login challenge."""
    from litestar_security.accounts._mfa_login import MFALoginChallenge

    return MFALoginChallenge(
        challenge_digest=digest,
        account_id=account_id,
        security_epoch=0,
        client_key="conformance-client",
        issued_at=_DEFAULT_NOW,
        expires_at=expires_at if expires_at is not None else _DEFAULT_NOW + timedelta(minutes=5),
    )


def _conformance_webauthn_challenge(
    digest: bytes, *, expires_at: datetime | None = None, account_id: str = "conformance-account"
) -> "WebAuthnChallenge":
    """Build a fixed valid WebAuthn challenge."""
    from litestar_security.accounts._passkeys import UserVerification, WebAuthnChallenge

    return WebAuthnChallenge(
        challenge_digest=digest,
        binding_digest=b"b" * 32,
        purpose="authentication",
        account_id=account_id,
        rp_id="example.test",
        origins=("https://app.example",),
        user_verification=UserVerification.REQUIRED,
        algorithms=(-7,),
        expires_at=expires_at if expires_at is not None else _DEFAULT_NOW + timedelta(minutes=5),
    )


def _conformance_oauth_transaction(digest: bytes, *, expires_at: datetime | None = None) -> OAuthTransaction:
    """Build one fixed OAuth login transaction."""
    return OAuthTransaction(
        state_digest=digest,
        binding_digest=b"b" * 32,
        operation=OAuthOperation.LOGIN,
        provider="conformance-provider",
        expected_issuer="https://issuer.example",
        redirect_uri="https://app.example/callback",
        return_to="/",
        requested_scopes=frozenset({"profile"}),
        pkce_verifier=SecretStr("v" * 43),
        expires_at=expires_at if expires_at is not None else _DEFAULT_NOW + timedelta(minutes=5),
    )


def _conformance_connect_token_record(
    connect_token_id: str, digest: bytes, *, expires_at: datetime | None = None, subject_id: str = "conformance-subject"
) -> WebSocketConnectAuthorization:
    """Build one fixed valid WebSocket connect-token record."""
    return WebSocketConnectAuthorization(
        connect_token_id=connect_token_id,
        digest=digest,
        subject_id=subject_id,
        security_epoch=0,
        route_name="conformance-route",
        origin="https://app.example",
        restrictions=CredentialRestrictions(),
        policy_fingerprint="f" * 64,
        issued_at=_DEFAULT_NOW,
        expires_at=expires_at if expires_at is not None else _DEFAULT_NOW + timedelta(seconds=30),
    )


def _conformance_passkey_credential(
    credential_id: bytes, *, account_id: str = "conformance-account"
) -> "PasskeyCredential":
    """Build one fixed verified passkey credential."""
    from litestar_security.accounts._passkeys import PasskeyCredential

    return PasskeyCredential(
        credential_id=credential_id,
        account_id=account_id,
        public_key=b"public-key",
        sign_count=1,
        backup_eligible=False,
        backup_state=False,
        user_verified=True,
        aaguid="aaguid",
        attestation_format="none",
        created_at=_DEFAULT_NOW,
    )


def _conformance_provider_identity(subject: str) -> ProviderIdentity:
    """Build one distinct OAuth provider identity."""
    return ProviderIdentity(
        provider="conformance-provider",
        issuer="https://issuer.example",
        subject=subject,
        display_name="Conformance",
        email=f"{subject}@example.com",
        email_verified=True,
        raw_claims={"sub": subject},
    )


def _conformance_provider_grant() -> ProviderGrant:
    """Build one fixed OAuth provider grant."""
    return ProviderGrant(scopes=frozenset({"profile"}), expires_at=_DEFAULT_NOW + timedelta(hours=1))


def _conformance_provider_tokens(marker: str) -> ProviderTokenSet:
    """Build one exact OAuth token set without exposing it from a conformance helper."""
    return ProviderTokenSet(
        access_token=SecretStr(f"conformance-access-{marker}"),
        token_type="Bearer",  # noqa: S106 - standardized OAuth token type, not a credential
        scopes=frozenset({"profile"}),
        expires_at=_DEFAULT_NOW + timedelta(hours=1),
        refresh_token=SecretStr(f"conformance-refresh-{marker}"),
        id_token=SecretStr(f"conformance-id-{marker}"),
    )


def _conformance_oidc_logout_identity(token_id: str) -> OIDCLogoutIdentity:
    """Build one fixed verified OIDC logout identity for a seeded store."""
    return OIDCLogoutIdentity(
        provider="conformance-provider",
        issuer="https://issuer.example",
        subject="conformance-subject",
        session_id="conformance-session",
        token_id=f"conformance-{token_id}",
        expires_at=_DEFAULT_NOW + timedelta(minutes=5),
    )


def _conformance_step_up_record(*, principal_id: str = "conformance-principal") -> "StepUpGrantState":
    """Build one fixed exact-binding step-up grant."""
    from litestar_security.accounts._mfa import StepUpGrantState

    return StepUpGrantState(
        grant_digest=b"g" * 32,
        transport_digest=b"t" * 32,
        principal_id=principal_id,
        security_epoch=7,
        purpose="conformance-purpose",
        methods=frozenset({"passkey"}),
        traits=frozenset({"verified"}),
        authenticated_at=_DEFAULT_NOW,
        expires_at=_DEFAULT_NOW + timedelta(minutes=5),
    )


async def _presence(operation: Awaitable[object | None]) -> bool:
    """Project an optional async result to the shared winner boolean shape."""
    return _won_by_presence(await operation)


async def _append_result(operation: Callable[[], Awaitable[ResultT]], results: list[ResultT]) -> None:
    """Run one contender and retain its exact status result."""
    results.append(await operation())


async def _single_winner(contenders: tuple[Callable[[], Awaitable[bool]], ...]) -> int:
    """Run every contender concurrently and count the ones that won."""
    outcomes: list[bool] = []
    async with create_task_group() as task_group:
        for attempt in contenders:
            task_group.start_soon(_record, attempt, outcomes)
    return outcomes.count(True)


async def _record(attempt: Callable[[], Awaitable[bool]], outcomes: list[bool]) -> None:
    outcomes.append(_won_by_status(await attempt(), winning=True))


def _won_by_return(result: object) -> bool:
    """Return whether a boolean-result contender won."""
    return result is True


def _won_by_presence(result: object | None) -> bool:
    """Return whether an optional-result contender produced a record."""
    return _won_by_return(result is not None)


def _won_by_status(result: object, *, winning: object) -> bool:
    """Return whether a status-result contender produced its winning status."""
    return _won_by_presence(result if result == winning else None)


async def _won_unless_raised(operation: Callable[[], Awaitable[object]]) -> bool:
    """Return whether a contender completed without an implementation conflict."""
    try:
        await operation()
    except Exception:  # noqa: BLE001 - conformance accepts implementation-specific conflict exceptions
        return False
    return True
