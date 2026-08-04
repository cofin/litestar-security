"""Unit tests for the deterministic aggregate security backend."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from anyio import create_task_group

import litestar_security.testing as testing_module
from litestar_security.accounts import (
    ConsumeStatus,
    CreateRefreshFamilyCommand,
    CreateSessionCommand,
    LocalAccountCapabilities,
    LoginMethod,
    MFALoginChallenge,
    NativeSessionStore,
    NotificationCommand,
    PasswordChangeStatus,
    PasswordResetStatus,
    PrepareRefreshResult,
    PurposeTokenCodec,
    RefreshRotationStatus,
    RefreshTokenFamilyStore,
    RefreshTokenProof,
    RegistrationCommand,
    RegistrationStatus,
    RegistrationStore,
    RevokeLoginMethodStatus,
    RotateRefreshCommand,
    SecurityEvent,
    StepUpRecord,
    TokenIssue,
    TokenPurpose,
    UserVerification,
    WebAuthnChallenge,
)
from litestar_security.providers.api_key import APIKeyRecord
from litestar_security.providers.oauth import OAuthOperation, OAuthTransaction, SecretStr
from litestar_security.testing import InMemorySecurityBackend

_NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)
_INVITATION_ID = "invitation_aWlpaWlpaWlpaWlpaWlpaQ"
_SECOND_INVITATION_ID = "invitation_ampqampqampqampqampqag"
_REFRESH_ID = "rt_aWlpaWlpaWlpaWlpaWlpaQ"
_REFRESH_SUCCESSOR_ID = "rt_ampqampqampqampqampqag"
_SESSION_ID = "c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M"
_SECOND_SESSION_ID = "bm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm4"


def _record(key_id: str) -> APIKeyRecord:
    return APIKeyRecord(key_id=key_id, subject_id="subject-1", digest=b"d" * 32)


def _event(operation: str = "test") -> SecurityEvent:
    return SecurityEvent(event_id="event-1", occurred_at=_NOW, operation=operation, outcome="accepted")


async def _register(backend: InMemorySecurityBackend, identifier: str = "user@example.com") -> str:
    result = await backend.accounts.register(
        RegistrationCommand(normalized_identifier=identifier),
        "test-hash",
        invitation_digest=None,
        verification=None,
        now=_NOW,
        event=_event(),
    )
    assert result.status is RegistrationStatus.CREATED
    assert result.account is not None
    return result.account.account_id


def test_in_memory_backend_defaults_are_deterministic_and_isolated() -> None:
    first = InMemorySecurityBackend()
    second = InMemorySecurityBackend()

    assert first.clock() == second.clock()
    assert first.next_identifier("account") == second.next_identifier("account") == "account-0001"
    assert first.entropy(4) == second.entropy(4) == bytes(range(4))
    assert first.password_hash == second.password_hash
    assert first.api_keys is not second.api_keys
    assert first.mfa is not second.mfa


def test_in_memory_backend_exposes_full_local_account_store() -> None:
    backend = InMemorySecurityBackend()
    store: LocalAccountCapabilities[object] = backend.accounts

    assert isinstance(store, LocalAccountCapabilities)
    assert isinstance(store, NativeSessionStore)
    assert isinstance(store, RefreshTokenFamilyStore)
    assert isinstance(store, RegistrationStore)


@pytest.mark.anyio
async def test_local_account_store_consumes_invitations_only_with_successful_registration() -> None:
    backend = InMemorySecurityBackend(clock=lambda: _NOW)
    invitation = TokenIssue(
        token_id=_INVITATION_ID,
        digest=b"i" * 32,
        purpose=TokenPurpose.INVITATION,
        account_id="invitation",
        expires_at=_NOW + timedelta(hours=1),
        maximum_attempts=2,
    )
    notification = NotificationCommand("invite", "test@example.com", "secret", _NOW + timedelta(hours=1))
    await backend.accounts.issue(invitation, notification, event=_event())
    with pytest.raises(ValueError, match="purpose-token identifier collision"):
        await backend.accounts.issue(replace(invitation, digest=b"z" * 32), notification, event=_event())

    missing = await backend.accounts.register(
        RegistrationCommand(normalized_identifier="missing@example.com"),
        "test-hash",
        invitation_digest=b"x" * 32,
        verification=None,
        now=_NOW,
        event=_event(),
    )
    created = await backend.accounts.register(
        RegistrationCommand(normalized_identifier="user@example.com"),
        "test-hash",
        invitation_digest=invitation.digest,
        verification=None,
        now=_NOW,
        event=_event(),
    )

    second_invitation = TokenIssue(
        token_id=_SECOND_INVITATION_ID,
        digest=b"j" * 32,
        purpose=TokenPurpose.INVITATION,
        account_id="invitation",
        expires_at=_NOW + timedelta(hours=1),
        maximum_attempts=2,
    )
    await backend.accounts.issue(second_invitation, notification, event=_event())
    duplicate = await backend.accounts.register(
        RegistrationCommand(normalized_identifier="user@example.com"),
        "test-hash",
        invitation_digest=second_invitation.digest,
        verification=None,
        now=_NOW,
        event=_event(),
    )
    later = await backend.accounts.register(
        RegistrationCommand(normalized_identifier="later@example.com"),
        "test-hash",
        invitation_digest=second_invitation.digest,
        verification=None,
        now=_NOW,
        event=_event(),
    )

    assert missing.status is RegistrationStatus.INVALID_INVITATION
    assert created.status is RegistrationStatus.CREATED
    assert duplicate.status is RegistrationStatus.DUPLICATE
    assert later.status is RegistrationStatus.CREATED


@pytest.mark.anyio
async def test_local_account_store_rejects_registration_verification_token_collisions_before_writes() -> None:
    backend = InMemorySecurityBackend(clock=lambda: _NOW)
    delivery = PurposeTokenCodec(pepper=b"p" * 32, entropy=lambda length: b"v" * length).issue(
        TokenPurpose.VERIFICATION,
        now=_NOW,
        lifetime=timedelta(hours=1),
        template="verify",
        destination="test@example.com",
    )
    issue, notification = delivery.bind("existing-account")
    await backend.accounts.issue(issue, notification, event=_event())

    with pytest.raises(ValueError, match="purpose-token identifier collision"):
        await backend.accounts.register(
            RegistrationCommand(normalized_identifier="collision@example.com"),
            "test-hash",
            invitation_digest=None,
            verification=delivery,
            now=_NOW,
            event=_event(),
        )

    assert await backend.accounts.find_for_login("collision@example.com") is None


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("purpose", "result_status"),
    [(TokenPurpose.VERIFICATION, ConsumeStatus.USED), (TokenPurpose.RECOVERY, PasswordResetStatus.USED)],
)
async def test_local_account_store_burns_purpose_tokens_after_failed_attempt_limit(
    purpose: TokenPurpose, result_status: ConsumeStatus | PasswordResetStatus
) -> None:
    backend = InMemorySecurityBackend(clock=lambda: _NOW)
    account_id = await _register(backend)
    issue = TokenIssue(
        token_id=("verification" if purpose is TokenPurpose.VERIFICATION else "recovery") + "_aWlpaWlpaWlpaWlpaWlpaQ",
        digest=b"t" * 32,
        purpose=purpose,
        account_id=account_id,
        expires_at=_NOW + timedelta(hours=1),
        maximum_attempts=2,
        issued_security_epoch=1 if purpose is TokenPurpose.RECOVERY else None,
    )
    notification = NotificationCommand("token", "test@example.com", "secret", _NOW + timedelta(hours=1))
    await backend.accounts.issue(issue, notification, event=_event())

    if purpose is TokenPurpose.VERIFICATION:
        await backend.accounts.consume_and_verify(issue.token_id, b"x" * 32, now=_NOW, event=_event())
        await backend.accounts.consume_and_verify(issue.token_id, b"x" * 32, now=_NOW, event=_event())
        result = await backend.accounts.consume_and_verify(issue.token_id, issue.digest, now=_NOW, event=_event())
    else:
        await backend.accounts.consume_and_reset(issue.token_id, b"x" * 32, "new", now=_NOW, event=_event())
        await backend.accounts.consume_and_reset(issue.token_id, b"x" * 32, "new", now=_NOW, event=_event())
        result = await backend.accounts.consume_and_reset(issue.token_id, issue.digest, "new", now=_NOW, event=_event())

    assert result.status is result_status


@pytest.mark.anyio
async def test_local_account_store_filters_expired_sessions_using_its_clock() -> None:
    current = [_NOW]
    backend = InMemorySecurityBackend(clock=lambda: current[0])
    account_id = await _register(backend)
    command = CreateSessionCommand(
        session_id="c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M",
        binding_id="sb_aWlpaWlpaWlpaWlpaWlpaQ",
        binding_digest=b"b" * 32,
        account_id=account_id,
        security_epoch=1,
        created_at=_NOW,
        authenticated_at=_NOW,
        expires_at=_NOW + timedelta(minutes=1),
    )
    await backend.accounts.create(command, event=_event())
    assert await backend.accounts.touch(command.session_id, now=command.expires_at) is None
    current[0] = command.expires_at

    assert await backend.accounts.get(command.session_id) is None
    assert await backend.accounts.list_for_account(account_id) == ()
    assert await backend.accounts.touch(command.session_id, now=_NOW) is None


@pytest.mark.anyio
async def test_local_account_store_rejects_session_identifier_collisions_before_mutation() -> None:
    backend = InMemorySecurityBackend(clock=lambda: _NOW)
    account_id = await _register(backend)
    existing = CreateSessionCommand(
        session_id=_SESSION_ID,
        binding_id="sb_aWlpaWlpaWlpaWlpaWlpaQ",
        binding_digest=b"b" * 32,
        account_id=account_id,
        security_epoch=1,
        created_at=_NOW,
        authenticated_at=_NOW,
        expires_at=_NOW + timedelta(hours=1),
    )
    prior = replace(existing, session_id=_SECOND_SESSION_ID)
    await backend.accounts.create(existing, event=_event())
    await backend.accounts.create(prior, event=_event())

    with pytest.raises(ValueError, match="session identifier collision"):
        await backend.accounts.create(existing, event=_event())
    with pytest.raises(ValueError, match="session identifier collision"):
        await backend.accounts.rebind(prior.session_id, existing, event=_event())

    assert await backend.accounts.get(existing.session_id) is not None
    assert await backend.accounts.get(prior.session_id) is not None


@pytest.mark.anyio
async def test_local_account_store_reports_missing_conflicting_and_final_method_transitions() -> None:
    backend = InMemorySecurityBackend(clock=lambda: _NOW)
    missing = "account-missing"

    assert await backend.accounts.get_password_state(missing) is None
    assert not await backend.accounts.compare_and_replace_password(missing, "old", "test-hash-2", event=_event())
    assert (
        await backend.accounts.replace_password_and_bump_epoch(missing, "test-hash-2", expected_epoch=1, event=_event())
    ).status is PasswordChangeStatus.NOT_FOUND

    account_id = await _register(backend)
    assert not await backend.accounts.compare_and_replace_password(account_id, "wrong", "new", event=_event())
    conflict = await backend.accounts.replace_password_and_bump_epoch(
        account_id, "test-hash-2", expected_epoch=2, event=_event()
    )
    changed = await backend.accounts.replace_password_and_bump_epoch(
        account_id, "test-hash-2", expected_epoch=1, event=_event()
    )
    assert conflict.status is PasswordChangeStatus.CONFLICT
    assert changed.status is PasswordChangeStatus.CHANGED
    state = await backend.accounts.get_password_state(account_id)
    assert state is not None
    assert state.security_epoch == 2

    primary = LoginMethod("password", "password", _NOW)
    secondary = LoginMethod("passkey", "passkey", _NOW)
    await backend.accounts.register_login_method(account_id, primary, event=_event())
    assert (
        await backend.accounts.revoke_login_method(account_id, "missing", event=_event())
    ).status is RevokeLoginMethodStatus.NOT_FOUND
    assert (
        await backend.accounts.revoke_login_method(account_id, primary.method_id, event=_event())
    ).status is RevokeLoginMethodStatus.FINAL_METHOD
    await backend.accounts.register_login_method(account_id, secondary, event=_event())
    assert (
        await backend.accounts.revoke_login_method(account_id, primary.method_id, event=_event())
    ).status is RevokeLoginMethodStatus.REVOKED


@pytest.mark.anyio
async def test_local_account_store_rejects_duplicate_generated_account_identifiers_and_binds_verification() -> None:
    backend = InMemorySecurityBackend(clock=lambda: _NOW, identifiers=lambda _namespace, _sequence: "account-fixed")
    delivery = PurposeTokenCodec(pepper=b"p" * 32, entropy=lambda length: b"v" * length).issue(
        TokenPurpose.VERIFICATION,
        now=_NOW,
        lifetime=timedelta(hours=1),
        template="verify",
        destination="test@example.com",
    )
    created = await backend.accounts.register(
        RegistrationCommand(normalized_identifier="first@example.com"),
        "test-hash",
        invitation_digest=None,
        verification=delivery,
        now=_NOW,
        event=_event(),
    )

    assert created.account is not None
    assert not created.account.verified
    with pytest.raises(ValueError, match="account identifier collision"):
        await backend.accounts.register(
            RegistrationCommand(normalized_identifier="second@example.com"),
            "test-hash",
            invitation_digest=None,
            verification=None,
            now=_NOW,
            event=_event(),
        )


@pytest.mark.anyio
async def test_in_memory_one_time_challenge_stores_burn_invalid_presentations() -> None:
    expires_at = _NOW + timedelta(minutes=1)
    webauthn = WebAuthnChallenge(
        challenge_digest=b"c" * 32,
        binding_digest=b"b" * 32,
        purpose="register",
        account_id="account-1",
        rp_id="example.test",
        origins=("https://example.test",),
        user_verification=UserVerification.REQUIRED,
        algorithms=(-7,),
        expires_at=expires_at,
    )
    backend = InMemorySecurityBackend()
    await backend.challenges.put(webauthn)
    assert (
        await backend.challenges.consume(b"c" * 32, binding_digest=b"wrong" * 7 + b"!", purpose="register", now=_NOW)
    ) is None

    mfa = MFALoginChallenge(
        challenge_digest=b"m" * 32,
        account_id="account-1",
        security_epoch=1,
        client_key=None,
        issued_at=_NOW,
        expires_at=expires_at,
    )
    await backend.mfa_login.put(mfa)
    assert await backend.mfa_login.consume(b"m" * 32, account_id="other", security_epoch=1, now=_NOW) is None

    step_up = StepUpRecord(
        grant_digest=b"g" * 32,
        transport_digest=b"t" * 32,
        principal_id="account-1",
        security_epoch=1,
        purpose="transfer",
        methods=frozenset({"totp"}),
        traits=frozenset(),
        authenticated_at=_NOW,
        expires_at=expires_at,
    )
    await backend.step_up.put(step_up)
    assert (
        await backend.step_up.consume(
            b"g" * 32, principal_id="account-1", security_epoch=1, purpose="other", transport_digest=b"t" * 32, now=_NOW
        )
    ) is None


@pytest.mark.anyio
async def test_in_memory_oidc_logout_reference_rejects_missing_and_replayed_mappings() -> None:
    store = testing_module.InMemoryOIDCSessionLogoutStore(
        session_mappings=(("provider", "issuer", "subject", "sid"),),
        frontchannel_bindings={("provider", "issuer", "sid"): "binding"},
    )

    assert await store.revoke_frontchannel("provider", "issuer", "missing", binding="binding", now=_NOW) is None
    assert await store.revoke_frontchannel("provider", "issuer", "sid", binding="wrong", now=_NOW) is None
    assert await store.revoke_frontchannel("provider", "issuer", "sid", binding="binding", now=_NOW) == 1
    assert await store.revoke_frontchannel("provider", "issuer", "sid", binding="binding", now=_NOW) is None


@pytest.mark.anyio
async def test_local_account_store_keeps_refresh_families_revoked_and_does_not_rotate_expired_tokens() -> None:
    backend = InMemorySecurityBackend(clock=lambda: _NOW)
    account_id = await _register(backend)
    create = CreateRefreshFamilyCommand(
        token_id=_REFRESH_ID,
        token_digest=b"d" * 32,
        account_id=account_id,
        family_id="rf_a2tra2tra2tra2tra2traw",
        security_epoch=1,
        created_at=_NOW,
        token_expires_at=_NOW + timedelta(minutes=1),
        family_expires_at=_NOW + timedelta(hours=1),
    )
    rotate = RotateRefreshCommand(
        token_id=create.token_id,
        token_digest=create.token_digest,
        account_id=account_id,
        family_id=create.family_id,
        security_epoch=1,
        successor_id="rt_ampqampqampqampqampqag",
        successor_digest=b"s" * 32,
        successor_expires_at=_NOW + timedelta(minutes=2),
        family_expires_at=create.family_expires_at,
        sealed_receipt=b"receipt",
        receipt_expires_at=_NOW + timedelta(seconds=30),
        idempotency_digest=b"k" * 32,
    )
    assert await backend.accounts.create_family(create, event=_event())
    assert (await backend.accounts.rotate(rotate, now=_NOW, event=_event())).status is RefreshRotationStatus.ROTATED
    replay = await backend.accounts.prepare_rotation(
        RefreshTokenProof(create.token_id, create.token_digest), b"x" * 32, now=_NOW, event=_event()
    )
    after_revoke = await backend.accounts.prepare_rotation(
        RefreshTokenProof(create.token_id, create.token_digest), rotate.idempotency_digest, now=_NOW, event=_event()
    )

    assert isinstance(replay, PrepareRefreshResult)
    assert replay.status is RefreshRotationStatus.REPLAY_DETECTED
    assert isinstance(after_revoke, PrepareRefreshResult)
    assert after_revoke.status is RefreshRotationStatus.REVOKED

    expired_backend = InMemorySecurityBackend(clock=lambda: _NOW)
    expired_account_id = await _register(expired_backend)
    expired_create = replace(create, account_id=expired_account_id)
    expired_rotate = replace(rotate, account_id=expired_account_id)
    assert await expired_backend.accounts.create_family(expired_create, event=_event())
    expired = await expired_backend.accounts.rotate(expired_rotate, now=_NOW + timedelta(hours=2), event=_event())

    assert expired.status is RefreshRotationStatus.EXPIRED
    assert not isinstance(
        await expired_backend.accounts.prepare_rotation(
            RefreshTokenProof(expired_create.token_id, expired_create.token_digest), None, now=_NOW, event=_event()
        ),
        PrepareRefreshResult,
    )


@pytest.mark.anyio
async def test_local_account_store_rejects_refresh_identifier_collisions_before_mutation() -> None:
    backend = InMemorySecurityBackend(clock=lambda: _NOW)
    account_id = await _register(backend)
    create = CreateRefreshFamilyCommand(
        token_id=_REFRESH_ID,
        token_digest=b"d" * 32,
        account_id=account_id,
        family_id="rf_a2tra2tra2tra2tra2traw",
        security_epoch=1,
        created_at=_NOW,
        token_expires_at=_NOW + timedelta(hours=1),
        family_expires_at=_NOW + timedelta(hours=2),
    )
    assert await backend.accounts.create_family(create, event=_event())
    assert not await backend.accounts.create_family(
        replace(create, family_id="rf_bm5ubm5ubm5ubm5ubm5ubg"), event=_event()
    )
    assert not await backend.accounts.create_family(replace(create, token_id=_REFRESH_SUCCESSOR_ID), event=_event())

    successor = replace(
        create, token_id=_REFRESH_SUCCESSOR_ID, token_digest=b"s" * 32, family_id="rf_bm5ubm5ubm5ubm5ubm5ubg"
    )
    assert await backend.accounts.create_family(successor, event=_event())
    rotation = RotateRefreshCommand(
        token_id=create.token_id,
        token_digest=create.token_digest,
        account_id=account_id,
        family_id=create.family_id,
        security_epoch=1,
        successor_id=successor.token_id,
        successor_digest=b"x" * 32,
        successor_expires_at=_NOW + timedelta(hours=1),
        family_expires_at=create.family_expires_at,
        sealed_receipt=b"receipt",
        receipt_expires_at=_NOW + timedelta(seconds=30),
    )

    assert (await backend.accounts.rotate(rotation, now=_NOW, event=_event())).status is RefreshRotationStatus.INVALID
    assert not isinstance(
        await backend.accounts.prepare_rotation(
            RefreshTokenProof(create.token_id, create.token_digest), None, now=_NOW, event=_event()
        ),
        PrepareRefreshResult,
    )


@pytest.mark.anyio
async def test_local_account_store_preserves_purpose_token_terminal_outcomes() -> None:
    backend = InMemorySecurityBackend(clock=lambda: _NOW)
    account_id = await _register(backend)
    notification = NotificationCommand("token", "test@example.com", "secret", _NOW + timedelta(hours=1))
    verification = TokenIssue(
        token_id="verification_aWlpaWlpaWlpaWlpaWlpaQ",  # noqa: S106 - non-secret lookup ID
        digest=b"v" * 32,
        purpose=TokenPurpose.VERIFICATION,
        account_id=account_id,
        expires_at=_NOW + timedelta(hours=1),
        maximum_attempts=2,
    )
    expired = replace(
        verification,
        token_id="verification_ampqampqampqampqampqag",  # noqa: S106 - non-secret lookup ID
        expires_at=_NOW,
    )
    await backend.accounts.issue(verification, notification, event=_event())
    await backend.accounts.issue(expired, notification, event=_event())
    await backend.accounts.issue_absent()

    missing = await backend.accounts.consume_and_verify("missing", b"x", now=_NOW, event=_event())
    expired_result = await backend.accounts.consume_and_verify(
        expired.token_id, expired.digest, now=_NOW, event=_event()
    )
    consumed = await backend.accounts.consume_and_verify(
        verification.token_id, verification.digest, now=_NOW, event=_event()
    )
    replayed = await backend.accounts.consume_and_verify(
        verification.token_id, verification.digest, now=_NOW, event=_event()
    )
    assert missing.status is ConsumeStatus.INVALID
    assert expired_result.status is ConsumeStatus.EXPIRED
    assert consumed.status is ConsumeStatus.CONSUMED
    assert replayed.status is ConsumeStatus.USED

    recovery = TokenIssue(
        token_id="recovery_aWlpaWlpaWlpaWlpaWlpaQ",  # noqa: S106 - non-secret lookup ID
        digest=b"r" * 32,
        purpose=TokenPurpose.RECOVERY,
        account_id=account_id,
        expires_at=_NOW + timedelta(hours=1),
        maximum_attempts=2,
        issued_security_epoch=1,
    )
    await backend.accounts.issue(recovery, notification, event=_event())
    reset = await backend.accounts.consume_and_reset(
        recovery.token_id, recovery.digest, "new-hash", now=_NOW, event=_event()
    )

    assert reset.status is PasswordResetStatus.RESET
    assert reset.security_epoch == 2
    replayed_reset = await backend.accounts.consume_and_reset(
        recovery.token_id, recovery.digest, "new-hash", now=_NOW, event=_event()
    )
    assert replayed_reset.status is PasswordResetStatus.USED

    expired_recovery = replace(
        recovery,
        token_id="recovery_ampqampqampqampqampqag",  # noqa: S106 - non-secret lookup ID
        digest=b"e" * 32,
        expires_at=_NOW,
    )
    stale_recovery = replace(
        recovery,
        token_id="recovery_bm5ubm5ubm5ubm5ubm5ubg",  # noqa: S106 - non-secret lookup ID
        digest=b"s" * 32,
    )
    orphaned_verification = replace(
        verification,
        token_id="verification_bm5ubm5ubm5ubm5ubm5ubg",  # noqa: S106 - non-secret lookup ID
        digest=b"o" * 32,
        account_id="missing-account",
    )
    await backend.accounts.issue(expired_recovery, notification, event=_event())
    await backend.accounts.issue(stale_recovery, notification, event=_event())
    await backend.accounts.issue(orphaned_verification, notification, event=_event())

    assert (
        await backend.accounts.consume_and_reset(
            expired_recovery.token_id, expired_recovery.digest, "new-hash", now=_NOW, event=_event()
        )
    ).status is PasswordResetStatus.EXPIRED
    assert (
        await backend.accounts.consume_and_reset(
            stale_recovery.token_id, stale_recovery.digest, "new-hash", now=_NOW, event=_event()
        )
    ).status is PasswordResetStatus.CONFLICT
    assert (
        await backend.accounts.consume_and_verify(
            orphaned_verification.token_id, orphaned_verification.digest, now=_NOW, event=_event()
        )
    ).status is ConsumeStatus.INVALID


@pytest.mark.anyio
async def test_local_account_store_updates_and_revokes_owned_sessions() -> None:
    backend = InMemorySecurityBackend(clock=lambda: _NOW)
    account_id = await _register(backend)
    command = CreateSessionCommand(
        session_id=_SESSION_ID,
        binding_id="sb_aWlpaWlpaWlpaWlpaWlpaQ",
        binding_digest=b"b" * 32,
        account_id=account_id,
        security_epoch=1,
        created_at=_NOW,
        authenticated_at=_NOW,
        expires_at=_NOW + timedelta(hours=1),
    )
    successor = replace(command, session_id=_SECOND_SESSION_ID)
    await backend.accounts.create(command, event=_event())
    await backend.accounts.create(successor, event=_event())

    touched = await backend.accounts.touch(command.session_id, now=_NOW + timedelta(minutes=1))
    assert touched is not None
    assert touched.last_seen_at == _NOW + timedelta(minutes=1)
    assert not await backend.accounts.revoke_session_for_account("other", command.session_id, event=_event())
    assert await backend.accounts.revoke_session_for_account(account_id, command.session_id, event=_event())
    await backend.accounts.create(command, event=_event())
    assert await backend.accounts.revoke_other_sessions(account_id, successor.session_id, event=_event()) == 1
    assert await backend.accounts.revoke_sessions_for_account(account_id, event=_event()) == 1
    assert await backend.accounts.rebind("missing", command, event=_event()) is None
    await backend.accounts.create(command, event=_event())
    rebound = await backend.accounts.rebind(command.session_id, successor, event=_event())
    assert rebound is not None
    assert rebound.session_id == successor.session_id


@pytest.mark.anyio
async def test_local_account_store_refresh_revocation_and_epoch_outcomes() -> None:
    backend = InMemorySecurityBackend(clock=lambda: _NOW)
    account_id = await _register(backend)
    command = CreateRefreshFamilyCommand(
        token_id=_REFRESH_ID,
        token_digest=b"d" * 32,
        account_id=account_id,
        family_id="rf_a2tra2tra2tra2tra2traw",
        security_epoch=1,
        created_at=_NOW,
        token_expires_at=_NOW + timedelta(hours=1),
        family_expires_at=_NOW + timedelta(hours=2),
    )
    second = replace(
        command, token_id=_REFRESH_SUCCESSOR_ID, token_digest=b"s" * 32, family_id="rf_bm5ubm5ubm5ubm5ubm5ubg"
    )
    assert await backend.accounts.create_family(command, event=_event())
    assert await backend.accounts.create_family(second, event=_event())
    assert not await backend.accounts.revoke_token_for_account(
        "other", command.token_id, command.token_digest, event=_event()
    )
    assert await backend.accounts.revoke_token(command.token_id, command.token_digest, event=_event())
    assert not await backend.accounts.revoke_family(command.family_id, event=_event())
    assert await backend.accounts.revoke_for_account(account_id, event=_event()) == 1

    epoch_backend = InMemorySecurityBackend(clock=lambda: _NOW)
    epoch_account_id = await _register(epoch_backend, "epoch@example.com")
    current = replace(command, account_id=epoch_account_id)
    assert await epoch_backend.accounts.create_family(current, event=_event())
    assert (
        await epoch_backend.accounts.replace_password_and_bump_epoch(
            epoch_account_id, "later-hash", expected_epoch=1, event=_event()
        )
    ).status is PasswordChangeStatus.CHANGED
    prepared = await epoch_backend.accounts.prepare_rotation(
        RefreshTokenProof(current.token_id, current.token_digest), None, now=_NOW, event=_event()
    )

    assert isinstance(prepared, PrepareRefreshResult)
    assert prepared.status is RefreshRotationStatus.EPOCH_MISMATCH


def test_in_memory_backend_accepts_injected_deterministic_sources() -> None:
    test_hash = "$test$injected"
    backend = InMemorySecurityBackend(
        clock=lambda: _NOW,
        identifiers=lambda namespace, sequence: f"{namespace}:{sequence}",
        entropy=lambda length: b"x" * length,
        password_hash=test_hash,
    )

    assert backend.clock() is _NOW
    assert backend.next_identifier("session") == "session:1"
    assert backend.entropy(3) == b"xxx"
    assert backend.password_hash == test_hash


@pytest.mark.anyio
async def test_in_memory_api_key_store_has_one_atomic_rotation_winner() -> None:
    backend = InMemorySecurityBackend(clock=lambda: _NOW)
    current = _record("a2tra2tra2tra2tr")
    first = _record("ZmZmZmZmZmZmZmZm")
    second = _record("Z2dnZ2dnZ2dnZ2dn")
    await backend.api_keys.create(current)
    outcomes: list[str] = []

    async def rotate(replacement: APIKeyRecord) -> None:
        try:
            await backend.api_keys.rotate(
                current_key_id=current.key_id,
                replacement=replacement,
                overlap_until=_NOW + timedelta(seconds=30),
                now=_NOW,
            )
        except ValueError:
            outcomes.append("conflict")
        else:
            outcomes.append("rotated")

    async with create_task_group() as task_group:
        task_group.start_soon(rotate, first)
        task_group.start_soon(rotate, second)

    assert sorted(outcomes) == ["conflict", "rotated"]
    assert backend.call_counts["api_key.rotate"] == 2
    assert all("digest" not in event.details for event in backend.events)


@pytest.mark.anyio
async def test_in_memory_backend_barrier_and_failpoint_are_deterministic() -> None:
    backend = InMemorySecurityBackend()
    barrier = backend.install_barrier("api_key.create")
    record = _record("a2tra2tra2tra2tr")
    completed: list[None] = []

    async def create() -> None:
        completed.append(await backend.api_keys.create(record))

    async with create_task_group() as task_group:
        task_group.start_soon(create)
        await barrier.reached.wait()
        assert completed == []
        barrier.release.set()

    backend.set_failpoint("api_key.get", RuntimeError("injected failure"))
    with pytest.raises(RuntimeError, match="injected failure"):
        await backend.api_keys.get(record.key_id)

    assert backend.call_counts == {"api_key.create": 1, "api_key.get": 1}
    assert [event.operation for event in backend.events] == ["api_key.create", "api_key.get"]


def test_in_memory_backend_diagnostics_are_immutable_snapshots() -> None:
    backend = InMemorySecurityBackend()
    counts = backend.call_counts
    events = backend.events

    with pytest.raises(TypeError):
        counts["other"] = 1  # type: ignore[index]
    assert events == ()


@pytest.mark.parametrize("kwargs", [{"clock": object()}, {"identifiers": object()}, {"entropy": object()}])
def test_in_memory_backend_rejects_non_callable_sources(kwargs: dict[str, object]) -> None:
    with pytest.raises(TypeError, match="must be callable"):
        InMemorySecurityBackend(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("password_hash", ["", " "])
def test_in_memory_backend_rejects_blank_encoded_hash(password_hash: str) -> None:
    with pytest.raises(ValueError, match="password hash"):
        InMemorySecurityBackend(password_hash=password_hash)
    with pytest.raises(ValueError, match="password hash"):
        InMemorySecurityBackend(password_hash=object())  # type: ignore[arg-type]


def test_in_memory_backend_rejects_invalid_source_results() -> None:
    with pytest.raises(ValueError, match="naive"):
        InMemorySecurityBackend(clock=lambda: datetime(2026, 1, 1)).clock()  # noqa: DTZ001 - invalid clock fixture
    with pytest.raises(ValueError, match="identifier factory"):
        InMemorySecurityBackend(identifiers=lambda _namespace, _sequence: "").next_identifier("account")
    with pytest.raises(ValueError, match="identifier factory"):
        InMemorySecurityBackend(identifiers=lambda _namespace, _sequence: 1).next_identifier(  # type: ignore[arg-type]
            "account"
        )
    with pytest.raises(ValueError, match="length"):
        InMemorySecurityBackend().entropy(0)
    with pytest.raises(ValueError, match="entropy factory"):
        InMemorySecurityBackend(entropy=lambda _length: b"").entropy(4)
    with pytest.raises(ValueError, match="entropy factory"):
        InMemorySecurityBackend(entropy=lambda _length: "bad").entropy(4)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_in_memory_api_key_store_covers_duplicates_bounded_overlap_and_revoke() -> None:
    backend = InMemorySecurityBackend()
    current = APIKeyRecord(
        key_id="a2tra2tra2tra2tr", subject_id="subject-1", digest=b"d" * 32, expires_at=_NOW + timedelta(seconds=10)
    )
    replacement = _record("ZmZmZmZmZmZmZmZm")
    await backend.api_keys.create(current)
    with pytest.raises(ValueError, match="already exists"):
        await backend.api_keys.create(current)

    await backend.api_keys.rotate(
        current_key_id=current.key_id, replacement=replacement, overlap_until=_NOW + timedelta(seconds=30), now=_NOW
    )

    assert {record.key_id for record in backend.api_keys.records} == {current.key_id, replacement.key_id}
    assert (await backend.api_keys.get(current.key_id)).overlap_until == current.expires_at  # type: ignore[union-attr]
    await backend.api_keys.revoke(key_id=replacement.key_id, now=_NOW)
    assert (await backend.api_keys.get(replacement.key_id)).revoked_at == _NOW  # type: ignore[union-attr]
    with pytest.raises(ValueError, match="does not exist"):
        await backend.api_keys.revoke(key_id="Z2dnZ2dnZ2dnZ2dn", now=_NOW)


@pytest.mark.anyio
async def test_in_memory_backend_controls_can_be_cleared() -> None:
    backend = InMemorySecurityBackend()
    backend.install_barrier("unused")
    backend.set_failpoint("api_key.get", RuntimeError("failure"))
    backend.clear_controls()

    assert await backend.api_keys.get("a2tra2tra2tra2tr") is None
    with pytest.raises(TypeError, match="requires an exception"):
        backend.set_failpoint("api_key.get", object())  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_in_memory_backend_default_oauth_protector_round_trips() -> None:
    backend = InMemorySecurityBackend()
    transaction = OAuthTransaction(
        state_digest=b"s" * 32,
        binding_digest=b"b" * 32,
        operation=OAuthOperation.LOGIN,
        provider="example",
        expected_issuer="https://issuer.example",
        redirect_uri="https://app.example/callback",
        return_to="/",
        requested_scopes=frozenset({"openid"}),
        pkce_verifier=SecretStr("v" * 43),
        nonce=SecretStr("n" * 43),
        expires_at=_NOW + timedelta(minutes=5),
    )
    await backend.oauth_transactions.create(transaction)

    consumed = await backend.oauth_transactions.consume(
        state_digest=transaction.state_digest,
        binding_digest=transaction.binding_digest,
        provider=transaction.provider,
        now=_NOW,
    )

    assert consumed == transaction
