"""Unit tests for purpose-bound account lifecycle tokens."""

from datetime import datetime, timedelta, timezone

import pytest
from litestar.exceptions import ImproperlyConfiguredException

import litestar_security.accounts as accounts_module
import litestar_security.accounts._purpose_tokens as purpose_tokens_module
from litestar_security.authentication import VerificationUnavailable
from tests.fixtures.accounts import CredentialCleanup as _CredentialCleanup
from tests.fixtures.accounts import LifecycleStore as _LifecycleStore
from tests.fixtures.accounts import PasswordHasher as _PasswordHasher

_ACCOUNT_NOW = datetime(2026, 7, 27, tzinfo=timezone.utc)


def test_registration_policy_requires_an_explicit_mode() -> None:
    assert accounts_module.RegistrationPolicy.disabled() == accounts_module.RegistrationPolicy(
        accounts_module.RegistrationMode.DISABLED
    )
    assert accounts_module.RegistrationPolicy.public(require_verification=False) == accounts_module.RegistrationPolicy(
        accounts_module.RegistrationMode.PUBLIC, require_verification=False
    )
    assert accounts_module.RegistrationPolicy.invite_only() == accounts_module.RegistrationPolicy(
        accounts_module.RegistrationMode.INVITE_ONLY
    )


def _purpose_token_delivery(
    codec: accounts_module.PurposeTokenCodec, purpose: accounts_module.TokenPurpose, lifetime: timedelta
) -> accounts_module.PurposeTokenDelivery:
    return codec.issue(
        purpose, now=_ACCOUNT_NOW, lifetime=lifetime, template=f"local.{purpose.value}", destination="user@example.com"
    )


def test_purpose_token_codec_generates_strict_redacted_and_bindable_material() -> None:
    entropy_values = iter((b"i" * 16, b"s" * 32))
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32, entropy=lambda _length: next(entropy_values))

    issued = _purpose_token_delivery(codec, accounts_module.TokenPurpose.VERIFICATION, timedelta(hours=24))
    token = issued.notification.token
    proof = codec.proof(token, expected_purpose=accounts_module.TokenPurpose.VERIFICATION)

    assert token.startswith("verification_")
    assert len(token.split("_", 1)[1].split(".", 1)[0]) == 22
    assert len(token.rsplit(".", 1)[1]) == 43
    assert proof == accounts_module.PurposeTokenProof(
        token_id=issued.issue.token_id, digest=issued.issue.digest, purpose=accounts_module.TokenPurpose.VERIFICATION
    )
    assert issued.issue.expires_at == _ACCOUNT_NOW + timedelta(hours=24)
    assert issued.issue.maximum_attempts == 5
    bound, notification = issued.bind("account-1")
    assert (bound.account_id, bound.token_id, bound.digest) == ("account-1", issued.issue.token_id, issued.issue.digest)
    assert notification is issued.notification
    assert token not in repr(issued)
    assert issued.issue.digest.hex() not in repr(issued.issue)
    assert "p" * 32 not in repr(codec)


@pytest.mark.parametrize(
    "token",
    [
        None,
        object(),
        "",
        "verification_missing-secret",
        "verification_a.b.c",
        "verification_!!!!!!!!!!!!!!!!!!!!!!.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "verification_AAAAAAAAAAAAAAAAAAAAA=.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "verification_" + "\ud800" * 22 + "." + "A" * 43,
        "unknown_AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ],
)
def test_purpose_token_codec_rejects_malformed_runtime_values(token: object, monkeypatch: pytest.MonkeyPatch) -> None:
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
    calls = 0
    original = purpose_tokens_module.hmac_digest

    def tracked(key: bytes, message: bytes, digest: str) -> bytes:
        nonlocal calls
        calls += 1
        return original(key, message, digest)

    monkeypatch.setattr(purpose_tokens_module, "hmac_digest", tracked)

    assert codec.proof(token, expected_purpose=accounts_module.TokenPurpose.VERIFICATION) is None
    assert calls == 1


def test_purpose_token_codec_never_crosses_namespaces() -> None:
    entropy_values = iter((b"i" * 16, b"s" * 32))
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32, entropy=lambda _length: next(entropy_values))
    issued = _purpose_token_delivery(codec, accounts_module.TokenPurpose.RECOVERY, timedelta(minutes=30))
    token = issued.notification.token

    assert codec.proof(token, expected_purpose=accounts_module.TokenPurpose.VERIFICATION) is None
    assert codec.proof(token, expected_purpose=accounts_module.TokenPurpose.INVITATION) is None
    assert codec.proof(token, expected_purpose=accounts_module.TokenPurpose.RECOVERY) is not None


@pytest.mark.parametrize("kwargs", [{"pepper": b"short"}, {"pepper": "p" * 32}, {"pepper": b"p" * 32, "entropy": None}])
def test_purpose_token_codec_rejects_invalid_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Purpose token"):
        accounts_module.PurposeTokenCodec(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "entropy", [lambda _length: b"short", lambda _length: "not-bytes", lambda _length: (_ for _ in ()).throw(OSError)]
)
def test_purpose_token_codec_rejects_invalid_entropy(entropy: object) -> None:
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32, entropy=entropy)  # type: ignore[arg-type]

    with pytest.raises(accounts_module.PurposeTokenGenerationError):
        _purpose_token_delivery(codec, accounts_module.TokenPurpose.VERIFICATION, timedelta(hours=24))


@pytest.mark.parametrize(
    ("purpose", "lifetime", "attempts"),
    [
        ("verification", timedelta(hours=1), 5),
        (accounts_module.TokenPurpose.VERIFICATION, timedelta(0), 5),
        (accounts_module.TokenPurpose.VERIFICATION, timedelta(hours=1), 0),
        (accounts_module.TokenPurpose.VERIFICATION, timedelta(hours=1), True),
    ],
)
def test_purpose_token_codec_rejects_invalid_issue_arguments(
    purpose: object, lifetime: timedelta, attempts: object
) -> None:
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)

    with pytest.raises(ValueError, match="Purpose token"):
        codec.issue(  # type: ignore[arg-type]
            purpose,
            now=_ACCOUNT_NOW,
            lifetime=lifetime,
            template="local.verify",
            destination="user@example.com",
            maximum_attempts=attempts,
        )
    with pytest.raises(ValueError, match="Expected purpose"):
        codec.proof("invalid", expected_purpose="verification")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"token_id": "invalid"},
        {"token_id": object()},
        {"digest": b"short"},
        {"purpose": "verification"},
        {"maximum_attempts": 0},
        {"maximum_attempts": True},
        {"expires_at": datetime(2026, 7, 27)},  # noqa: DTZ001 - explicit rejection input
    ],
)
def test_pending_token_issue_rejects_invalid_storage_shapes(kwargs: dict[str, object]) -> None:
    values = {
        "token_id": "verification_aWlpaWlpaWlpaWlpaWlpaQ",
        "digest": b"d" * 32,
        "purpose": accounts_module.TokenPurpose.VERIFICATION,
        "expires_at": _ACCOUNT_NOW + timedelta(hours=1),
        "maximum_attempts": 5,
        **kwargs,
    }

    with pytest.raises(ValueError, match="purpose token"):
        accounts_module.PendingTokenIssue(**values)  # type: ignore[arg-type]


def test_bound_token_and_proof_reject_invalid_identifiers_or_digests() -> None:
    pending = accounts_module.PendingTokenIssue(
        token_id="verification_aWlpaWlpaWlpaWlpaWlpaQ",  # noqa: S106 - non-secret lookup ID
        digest=b"d" * 32,
        purpose=accounts_module.TokenPurpose.VERIFICATION,
        expires_at=_ACCOUNT_NOW + timedelta(hours=1),
        maximum_attempts=5,
    )

    with pytest.raises(ValueError, match="account binding"):
        pending.bind(" ")
    with pytest.raises(ValueError, match="proof"):
        accounts_module.PurposeTokenProof(
            token_id=pending.token_id, digest=b"short", purpose=accounts_module.TokenPurpose.VERIFICATION
        )

    recovery = accounts_module.PendingTokenIssue(
        token_id="recovery_aWlpaWlpaWlpaWlpaWlpaQ",  # noqa: S106 - non-secret lookup ID
        digest=b"d" * 32,
        purpose=accounts_module.TokenPurpose.RECOVERY,
        expires_at=_ACCOUNT_NOW + timedelta(hours=1),
        maximum_attempts=5,
    )
    with pytest.raises(ValueError, match="issuance epoch"):
        recovery.bind("account-1")
    assert recovery.bind("account-1", security_epoch=1).issued_security_epoch == 1
    with pytest.raises(ValueError, match="issuance epoch"):
        pending.bind("account-1", security_epoch=1)


def test_purpose_token_delivery_is_codec_created_digest_bound_and_redacted() -> None:
    entropy_values = iter((b"i" * 16, b"s" * 32))
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32, entropy=lambda _length: next(entropy_values))
    plan = codec.issue(
        accounts_module.TokenPurpose.VERIFICATION,
        now=_ACCOUNT_NOW,
        lifetime=timedelta(hours=24),
        template="local.verify",
        destination="user@example.com",
        return_url="https://app.example/verified",
    )
    proof = codec.proof(plan.notification.token, expected_purpose=accounts_module.TokenPurpose.VERIFICATION)

    assert plan.issue.purpose is accounts_module.TokenPurpose.VERIFICATION
    assert proof == accounts_module.PurposeTokenProof(
        plan.issue.token_id, plan.issue.digest, accounts_module.TokenPurpose.VERIFICATION
    )
    assert plan.notification.token not in repr(plan.notification)
    assert "user@example.com" not in repr(plan.notification)
    assert plan.notification.token not in repr(plan)


def test_purpose_token_delivery_cannot_be_publicly_constructed_with_mismatched_material() -> None:
    with pytest.raises(TypeError, match="PurposeTokenCodec"):
        accounts_module.PurposeTokenDelivery()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"template": "", "destination": "user", "token": "token"},
        {"template": "verify", "destination": "", "token": "token"},
        {"template": "verify", "destination": "user", "token": ""},
        {
            "template": "verify",
            "destination": "user",
            "token": "token",
            "expires_at": datetime(2026, 7, 27),  # noqa: DTZ001 - explicit rejection input
        },
        {
            "template": "verify",
            "destination": "user",
            "token": "token",
            "return_url": "https://user:secret@app.example/callback",
        },
        {
            "template": "verify",
            "destination": "user",
            "token": "token",
            "return_url": "https://app.example/callback#token",
        },
        {"template": "verify", "destination": "user", "token": "token", "return_url": object()},
    ],
)
def test_notification_command_rejects_incomplete_or_unsafe_values(kwargs: dict[str, object]) -> None:
    values = {"expires_at": _ACCOUNT_NOW + timedelta(hours=1), **kwargs}

    with pytest.raises(ValueError, match="Notification"):
        accounts_module.NotificationCommand(**values)  # type: ignore[arg-type]


_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)


def test_notification_destination_rejects_control_characters() -> None:
    with pytest.raises(ValueError, match="destination"):
        accounts_module.NotificationCommand(
            template="local.recovery",
            destination="victim@example.com\r\nBcc: attacker@example.com",
            token="opaque-token",  # noqa: S106 - opaque test fixture, not a credential
            expires_at=_JWT_NOW + timedelta(minutes=30),
        )


def _lifecycle_account(*, active: bool = True, verified: bool = False) -> "accounts_module.LocalAccountState[object]":
    return accounts_module.LocalAccountState(
        account_id="account-1",
        normalized_identifier="user@example.com",
        display_name="User",
        active=active,
        verified=verified,
        security_epoch=1,
    )


def _lifecycle_token(
    codec: accounts_module.PurposeTokenCodec, purpose: accounts_module.TokenPurpose, lifetime: timedelta
) -> accounts_module.PurposeTokenDelivery:
    return codec.issue(
        purpose, now=_JWT_NOW, lifetime=lifetime, template=f"local.{purpose.value}", destination="user@example.com"
    )


def _unavailable_password_check(_password: str) -> bool:
    raise OSError


@pytest.mark.parametrize(
    ("registration_status", "require_verification"),
    [
        (accounts_module.RegistrationStatus.CREATED, True),
        (accounts_module.RegistrationStatus.DUPLICATE, True),
        (accounts_module.RegistrationStatus.CREATED, False),
        (accounts_module.RegistrationStatus.DUPLICATE, False),
    ],
)
async def test_registration_service_collapses_created_and_duplicate_atomic_results(
    registration_status: accounts_module.RegistrationStatus, *, require_verification: bool
) -> None:
    store = _LifecycleStore(registration_status=registration_status)
    hasher = _PasswordHasher()
    service = accounts_module.RegistrationService(
        accounts=store,
        hasher=hasher,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        registration=accounts_module.RegistrationPolicy.public(require_verification=require_verification),
        verification_return_url="https://app.example/verified",
        event_ids=lambda: "event-1",
    )

    outcome = await service.register(
        " User@EXAMPLE.COM ", "correct horse battery staple", display_name="User", now=_JWT_NOW
    )

    assert outcome == accounts_module.LifecycleAccepted()
    assert hasher.hash_calls == ["correct horse battery staple"]
    assert len(store.registrations) == 1
    command, password_hash, invitation_digest, verification, now, event = store.registrations[0]
    assert command == accounts_module.RegistrationCommand(normalized_identifier="user@example.com", display_name="User")
    assert password_hash == "hashed:correct horse battery staple"  # noqa: S105 - fake hasher output
    assert invitation_digest is None
    assert now == _JWT_NOW
    assert (event.event_id, event.operation, event.outcome) == ("event-1", "local.registration", "created")
    assert (verification is not None) is require_verification
    if verification is not None:
        assert verification.issue.purpose is accounts_module.TokenPurpose.VERIFICATION
        assert verification.issue.expires_at == _JWT_NOW + timedelta(hours=24)
        assert verification.notification.expires_at == verification.issue.expires_at
        assert "correct horse battery staple" not in repr(verification)


@pytest.mark.parametrize(
    ("case", "expected_type", "store_status"),
    [
        ("missing", accounts_module.InvalidInvitation, accounts_module.RegistrationStatus.CREATED),
        ("purpose_swap", accounts_module.InvalidInvitation, accounts_module.RegistrationStatus.CREATED),
        ("replay", accounts_module.InvalidInvitation, accounts_module.RegistrationStatus.INVALID_INVITATION),
        ("expired", accounts_module.InvalidInvitation, accounts_module.RegistrationStatus.INVALID_INVITATION),
        ("accepted", accounts_module.LifecycleAccepted, accounts_module.RegistrationStatus.CREATED),
    ],
)
async def test_invite_registration_passes_only_one_purpose_bound_digest_to_atomic_store(
    case: str, expected_type: type[object], store_status: accounts_module.RegistrationStatus
) -> None:
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
    purpose = (
        accounts_module.TokenPurpose.RECOVERY if case == "purpose_swap" else accounts_module.TokenPurpose.INVITATION
    )
    issued = _lifecycle_token(codec, purpose, timedelta(hours=1))
    invitation = None if case == "missing" else issued.notification.token
    store = _LifecycleStore(registration_status=store_status)
    hasher = _PasswordHasher()
    service = accounts_module.RegistrationService(
        accounts=store, hasher=hasher, tokens=codec, registration=accounts_module.RegistrationPolicy.invite_only()
    )

    outcome = await service.register(
        "user@example.com", "correct horse battery staple", invitation_token=invitation, now=_JWT_NOW
    )

    assert isinstance(outcome, expected_type)
    if case in {"missing", "purpose_swap"}:
        assert store.registrations == []
        assert hasher.hash_calls == []
    else:
        assert len(store.registrations) == 1
        stored_digest = store.registrations[0][2]
        proof = codec.proof(issued.notification.token, expected_purpose=accounts_module.TokenPurpose.INVITATION)
        assert proof is not None
        assert stored_digest == proof.digest
        assert issued.notification.token not in repr(store.registrations[0])


@pytest.mark.parametrize("failure", ["password", "policy", "store", "identifier", "empty_identifier", "event"])
async def test_registration_service_returns_secret_free_domain_failures(failure: str) -> None:
    store = _LifecycleStore(fail=failure == "store")
    hasher = _PasswordHasher(unavailable=failure == "password")
    service = accounts_module.RegistrationService(
        accounts=store,
        hasher=hasher,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        registration=accounts_module.RegistrationPolicy.public(),
        password_policy=accounts_module.PasswordPolicy(
            compromised=_unavailable_password_check if failure == "policy" else None
        ),
        normalizer=(
            (lambda _value: (_ for _ in ()).throw(ValueError))
            if failure == "identifier"
            else (lambda _value: "")
            if failure == "empty_identifier"
            else accounts_module.normalize_identifier
        ),
        event_ids=(lambda: " ") if failure == "event" else (lambda: "event-1"),
    )

    outcome = await service.register("user@example.com", "correct horse battery staple", now=_JWT_NOW)

    assert isinstance(
        outcome,
        (
            accounts_module.LifecycleRejected
            if failure in {"identifier", "empty_identifier"}
            else VerificationUnavailable
        ),
    )
    assert "correct horse battery staple" not in repr(outcome)


async def test_registration_service_returns_password_policy_without_hash_or_store_call() -> None:
    store = _LifecycleStore()
    hasher = _PasswordHasher()
    service = accounts_module.RegistrationService(
        accounts=store,
        hasher=hasher,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        registration=accounts_module.RegistrationPolicy.public(),
    )

    outcome = await service.register("user@example.com", "short", now=_JWT_NOW)

    assert outcome == accounts_module.PasswordPolicyDecision(
        frozenset({accounts_module.PasswordPolicyViolation.TOO_SHORT})
    )
    assert hasher.hash_calls == []
    assert store.registrations == []


@pytest.mark.parametrize(
    ("account", "fail", "issue_count"),
    [
        (None, False, 0),
        (_lifecycle_account(verified=True), False, 0),
        (_lifecycle_account(active=False), False, 0),
        (_lifecycle_account(), False, 1),
        (_lifecycle_account(), True, 1),
    ],
)
async def test_verification_resend_is_generic_across_account_and_store_states(
    account: "accounts_module.LocalAccountState[object] | None",
    *,
    fail: bool,
    issue_count: int,
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = _LifecycleStore(account=account, fail=fail)
    service = accounts_module.VerificationTokenService(
        accounts=store,
        store=store,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        return_url="https://app.example/verified",
        event_ids=lambda: "event-1",
    )

    outcome = await service.resend(" User@EXAMPLE.COM ", now=_JWT_NOW)

    assert outcome == accounts_module.LifecycleAccepted()
    assert len(store.issues) == issue_count
    if issue_count:
        issue, notification, event = store.issues[0]
        assert issue.purpose is accounts_module.TokenPurpose.VERIFICATION
        assert issue.expires_at == _JWT_NOW + timedelta(hours=24)
        assert (event.operation, event.account_id) == ("local.verification.issue", "account-1")
        assert "user@example.com" not in repr(notification)
        assert notification.token not in repr(notification)
    if fail:
        assert "Verification token request failed" in caplog.text


@pytest.mark.parametrize(
    "status",
    [
        accounts_module.VerificationStatus.CONSUMED,
        accounts_module.VerificationStatus.INVALID,
        accounts_module.VerificationStatus.EXPIRED,
        accounts_module.VerificationStatus.USED,
    ],
)
async def test_verification_consume_delegates_replay_and_expiry_atomically(
    status: accounts_module.VerificationStatus,
) -> None:
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
    issued = _lifecycle_token(codec, accounts_module.TokenPurpose.VERIFICATION, timedelta(hours=24))
    store = _LifecycleStore(consume_status=status)
    service = accounts_module.VerificationTokenService(accounts=store, store=store, tokens=codec)

    outcome = await service.consume(issued.notification.token, now=_JWT_NOW)

    assert isinstance(outcome, accounts_module.VerificationOutcome)
    assert outcome.status is status
    assert len(store.consumptions) == 1
    token_id, digest, now, event = store.consumptions[0]
    assert (token_id, digest, now) == (issued.issue.token_id, issued.issue.digest, _JWT_NOW)
    assert event.operation == "local.verification.consume"


async def test_verification_consume_rejects_purpose_swap_without_store_access() -> None:
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
    recovery = _lifecycle_token(codec, accounts_module.TokenPurpose.RECOVERY, timedelta(minutes=30))
    store = _LifecycleStore()
    service = accounts_module.VerificationTokenService(accounts=store, store=store, tokens=codec)

    outcome = await service.consume(recovery.notification.token, now=_JWT_NOW)

    assert outcome == accounts_module.VerificationOutcome(accounts_module.VerificationStatus.INVALID)
    assert store.consumptions == []


async def test_verification_consume_maps_atomic_store_failure_to_unavailable() -> None:
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
    issued = _lifecycle_token(codec, accounts_module.TokenPurpose.VERIFICATION, timedelta(hours=24))
    store = _LifecycleStore(fail=True)
    service = accounts_module.VerificationTokenService(accounts=store, store=store, tokens=codec)

    outcome = await service.consume(issued.notification.token, now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable)
    assert len(store.consumptions) == 1


@pytest.mark.parametrize(
    ("account", "fail", "issue_count"),
    [
        (None, False, 0),
        (_lifecycle_account(active=False), False, 0),
        (_lifecycle_account(), False, 1),
        (_lifecycle_account(), True, 1),
    ],
)
async def test_recovery_request_is_generic_and_emits_only_atomic_outbox_commands(
    account: "accounts_module.LocalAccountState[object] | None",
    *,
    fail: bool,
    issue_count: int,
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = _LifecycleStore(account=account, fail=fail)
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
    service = accounts_module.RecoveryTokenService(
        accounts=store,
        store=store,
        tokens=codec,
        hasher=_PasswordHasher(),
        return_url="https://app.example/reset",
        event_ids=lambda: "event-1",
    )

    outcome = await service.request(" User@EXAMPLE.COM ", now=_JWT_NOW)

    assert outcome == accounts_module.LifecycleAccepted()
    assert len(store.issues) == issue_count
    if issue_count:
        issue, notification, event = store.issues[0]
        assert issue.purpose is accounts_module.TokenPurpose.RECOVERY
        assert issue.issued_security_epoch == 1
        assert issue.expires_at == _JWT_NOW + timedelta(minutes=30)
        assert codec.proof(
            notification.token, expected_purpose=accounts_module.TokenPurpose.RECOVERY
        ) == accounts_module.PurposeTokenProof(issue.token_id, issue.digest, accounts_module.TokenPurpose.RECOVERY)
        assert (event.operation, event.account_id) == ("local.recovery.issue", "account-1")
    if fail:
        assert "Recovery token request failed" in caplog.text


async def test_recovery_request_with_control_character_destination_stays_generic_and_does_not_emit() -> None:
    store = _LifecycleStore(account=_lifecycle_account())
    service = accounts_module.RecoveryTokenService(
        accounts=store,
        store=store,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        hasher=_PasswordHasher(),
        event_ids=lambda: "event-1",
    )

    outcome = await service.request("victim@example.com\r\nBcc: attacker@example.com", now=_JWT_NOW)

    assert outcome == accounts_module.LifecycleAccepted()
    assert store.issues == []


@pytest.mark.parametrize(
    "status",
    [
        accounts_module.PasswordResetStatus.RESET,
        accounts_module.PasswordResetStatus.INVALID,
        accounts_module.PasswordResetStatus.EXPIRED,
        accounts_module.PasswordResetStatus.USED,
        accounts_module.PasswordResetStatus.CONFLICT,
    ],
)
async def test_recovery_reset_delegates_replay_expiry_and_epoch_mutation_atomically(
    status: accounts_module.PasswordResetStatus,
) -> None:
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
    issued = _lifecycle_token(codec, accounts_module.TokenPurpose.RECOVERY, timedelta(minutes=30))
    store = _LifecycleStore(reset_status=status)
    hasher = _PasswordHasher()
    cleanup = _CredentialCleanup()
    service = accounts_module.RecoveryTokenService(
        accounts=store, store=store, tokens=codec, hasher=hasher, sessions=cleanup, refresh_tokens=cleanup
    )

    outcome = await service.reset(
        issued.notification.token, "correct horse battery staple", now=_JWT_NOW + timedelta(minutes=1)
    )

    assert isinstance(outcome, accounts_module.PasswordResetOutcome)
    assert outcome.status is status
    assert hasher.hash_calls == ["correct horse battery staple"]
    assert len(store.resets) == 1
    token_id, digest, password_hash, now, event = store.resets[0]
    assert (token_id, digest, password_hash, now) == (
        issued.issue.token_id,
        issued.issue.digest,
        "hashed:correct horse battery staple",
        _JWT_NOW + timedelta(minutes=1),
    )
    assert event.operation == "local.recovery.consume"
    expected_cleanup = ["account-1"] if status is accounts_module.PasswordResetStatus.RESET else []
    assert [account_id for account_id, _event in cleanup.session_revocations] == expected_cleanup
    assert [account_id for account_id, _event in cleanup.refresh_revocations] == expected_cleanup


@pytest.mark.parametrize("transport", ["sessions", "refresh", "refresh_failure"])
async def test_recovery_reset_cleans_each_configured_transport_independently(
    transport: str, caplog: pytest.LogCaptureFixture
) -> None:
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
    issued = _lifecycle_token(codec, accounts_module.TokenPurpose.RECOVERY, timedelta(minutes=30))
    store = _LifecycleStore()
    cleanup = _CredentialCleanup(failures=frozenset({"refresh"}) if transport == "refresh_failure" else frozenset())
    service = accounts_module.RecoveryTokenService(
        accounts=store,
        store=store,
        tokens=codec,
        hasher=_PasswordHasher(),
        sessions=cleanup if transport == "sessions" else None,
        refresh_tokens=cleanup if transport != "sessions" else None,
    )

    outcome = await service.reset(
        issued.notification.token, "correct horse battery staple", now=_JWT_NOW + timedelta(minutes=1)
    )

    assert outcome == accounts_module.PasswordResetOutcome(accounts_module.PasswordResetStatus.RESET, "account-1", 2)
    assert len(cleanup.session_revocations) == (1 if transport == "sessions" else 0)
    assert len(cleanup.refresh_revocations) == (0 if transport == "sessions" else 1)
    if transport == "refresh_failure":
        assert "Password refresh cleanup failed" in caplog.text


@pytest.mark.parametrize("case", ["purpose_swap", "policy", "policy_failure", "store_failure"])
async def test_recovery_reset_rejects_invalid_inputs_without_splitting_atomic_consumption(case: str) -> None:
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
    purpose = (
        accounts_module.TokenPurpose.VERIFICATION if case == "purpose_swap" else accounts_module.TokenPurpose.RECOVERY
    )
    issued = _lifecycle_token(codec, purpose, timedelta(minutes=30))
    store = _LifecycleStore(fail=case == "store_failure")
    hasher = _PasswordHasher()
    service = accounts_module.RecoveryTokenService(
        accounts=store,
        store=store,
        tokens=codec,
        hasher=hasher,
        password_policy=accounts_module.PasswordPolicy(
            compromised=_unavailable_password_check if case == "policy_failure" else None
        ),
    )
    password = "short" if case == "policy" else "correct horse battery staple"

    outcome = await service.reset(issued.notification.token, password, now=_JWT_NOW)

    if case == "purpose_swap":
        assert outcome == accounts_module.PasswordResetOutcome(accounts_module.PasswordResetStatus.INVALID)
        assert hasher.hash_calls == []
        assert store.resets == []
    elif case == "policy":
        assert outcome == accounts_module.PasswordPolicyDecision(
            frozenset({accounts_module.PasswordPolicyViolation.TOO_SHORT})
        )
        assert hasher.hash_calls == []
        assert store.resets == []
    elif case == "store_failure":
        assert isinstance(outcome, VerificationUnavailable)
        assert hasher.hash_calls == ["correct horse battery staple"]
        assert len(store.resets) == 1
    else:
        assert isinstance(outcome, VerificationUnavailable)
        assert hasher.hash_calls == []
        assert store.resets == []


@pytest.mark.parametrize(
    ("service_name", "invalid_field"),
    [
        ("registration", "accounts"),
        ("registration", "hasher"),
        ("registration", "tokens"),
        ("registration", "registration"),
        ("verification", "accounts"),
        ("verification", "store"),
        ("verification", "tokens"),
        ("recovery", "accounts"),
        ("recovery", "store"),
        ("recovery", "tokens"),
        ("recovery", "hasher"),
        ("recovery", "password_policy"),
        ("recovery", "sessions"),
        ("recovery", "refresh_tokens"),
    ],
)
def test_lifecycle_services_reject_invalid_structural_dependencies(service_name: str, invalid_field: str) -> None:
    store = _LifecycleStore()
    common: dict[str, object] = {"accounts": store, "tokens": accounts_module.PurposeTokenCodec(pepper=b"p" * 32)}
    if service_name == "registration":
        factory = accounts_module.RegistrationService
        common.update(hasher=_PasswordHasher(), registration=accounts_module.RegistrationPolicy.public())
    elif service_name == "verification":
        factory = accounts_module.VerificationTokenService
        common["store"] = store
    else:
        factory = accounts_module.RecoveryTokenService
        common.update(store=store, hasher=_PasswordHasher())
    common[invalid_field] = object()

    with pytest.raises(ImproperlyConfiguredException):
        factory(**common)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("lifetime", timedelta(0)),
        ("attempts", 0),
        ("attempts", True),
        ("return_url", "javascript:alert(1)"),
        ("clock", None),
        ("normalizer", None),
        ("event_ids", None),
    ],
)
def test_lifecycle_services_reject_invalid_shared_configuration(field: str, value: object) -> None:
    values: dict[str, object] = {
        "accounts": _LifecycleStore(),
        "store": _LifecycleStore(),
        "tokens": accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
    }
    values["maximum_attempts" if field == "attempts" else field] = value

    with pytest.raises(ImproperlyConfiguredException):
        accounts_module.VerificationTokenService(**values)  # type: ignore[arg-type]
