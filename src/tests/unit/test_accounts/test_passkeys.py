"""Unit coverage for passkey registration and authentication ceremonies."""

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, cast

import pytest
from litestar.exceptions import ImproperlyConfiguredException

import litestar_security.accounts as accounts_module
import litestar_security.accounts._passkeys as passkeys_module
import litestar_security.testing as testing_module
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.context import AuthenticationEvidence
from tests.fixtures.accounts import (
    ChainAttestationVerifier,
    ConflictingPasskeyStore,
    FailingRecoveryLoginMethods,
    InvalidAttestationVerifier,
    MismatchedAttestation,
    MutableAccountLookup,
    PasskeyStore,
    RecordingTokenIssuer,
    RecoveryLoginMethods,
    SecurityEvents,
    SlowWebAuthnVerifier,
    StaticSessionIssuer,
    TrustedAttestation,
    UnanchoredAttestation,
    WebAuthnChallengeStore,
    WebAuthnVerifier,
    build_passkey_service,
    stored_passkey,
)

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)


async def test_passkey_registration_is_bound_one_time_and_stores_only_verified_project_types() -> None:
    challenge_store, store = WebAuthnChallengeStore(), PasskeyStore()
    service = build_passkey_service(challenge_store=challenge_store, store=store)
    binding = b"session-binding"
    options = await service.begin_registration("account-1", user_name="person@example.com", binding=binding)
    assert isinstance(options, accounts_module.WebAuthnOptions)
    credential = await service.verify_registration("account-1", binding=binding, response='{"id":"credential"}')
    assert isinstance(credential, accounts_module.PasskeyCredential)
    assert credential.account_id == "account-1"
    assert credential.user_verified
    assert b"public-key" not in repr(credential).encode()
    assert isinstance(
        await service.verify_registration("account-1", binding=binding, response='{"id":"credential"}'),
        InvalidCredentials,
    )


@pytest.mark.parametrize(
    "case",
    [
        "binding",
        "account",
        "expired",
        "wrong_type",
        "origin",
        "rp_id",
        "user_presence",
        "user_verification",
        "signature",
        "algorithm",
        "store",
    ],
)
async def test_passkey_registration_rejects_unbound_invalid_or_unavailable_ceremonies(case: str) -> None:
    challenge_store, store = WebAuthnChallengeStore(), PasskeyStore()
    verifier = WebAuthnVerifier(failure=case if case not in {"binding", "account", "expired", "store"} else None)
    service = build_passkey_service(challenge_store=challenge_store, store=store, verifier=verifier)
    binding = b"session-binding"
    assert isinstance(
        await service.begin_registration("account-1", user_name="person@example.com", binding=binding),
        accounts_module.WebAuthnOptions,
    )
    if case == "expired":
        challenge = next(iter(challenge_store.records.values()))
        service.clock = lambda: challenge.expires_at
    if case == "store":
        store.fail = True
    outcome = await service.verify_registration(
        "account-2" if case == "account" else "account-1",
        binding=b"wrong" if case == "binding" else binding,
        response='{"id":"credential"}',
    )
    assert isinstance(outcome, VerificationUnavailable if case == "store" else InvalidCredentials)


def test_py_webauthn_adapter_builds_exact_options_and_sanitizes_malformed_json() -> None:
    verifier = accounts_module.PyWebAuthnVerifier()
    registration = verifier.registration_options(
        challenge=b"c" * 32,
        rp_id="example.com",
        rp_name="Example",
        account_id="account-1",
        user_name="person@example.com",
        timeout_ms=300_000,
        user_verification="required",
        algorithms=(-8, -7, -257),
    )
    authentication = verifier.authentication_options(
        challenge=b"c" * 32, rp_id="example.com", timeout_ms=300_000, user_verification="required"
    )
    assert json.loads(registration)["rp"]["id"] == "example.com"
    assert json.loads(registration)["attestation"] == "none"
    assert json.loads(authentication)["userVerification"] == "required"
    for operation in (verifier.registration_challenge, verifier.authentication_challenge, verifier.credential_id):
        with pytest.raises(accounts_module.WebAuthnVerificationError):
            operation("{}")


async def test_passkey_authentication_verifies_owner_and_emits_normalized_assurance() -> None:
    challenge_store, store, verifier = WebAuthnChallengeStore(), PasskeyStore(), WebAuthnVerifier()
    store.credentials[verifier.expected_credential_id] = stored_passkey()
    service = build_passkey_service(challenge_store=challenge_store, store=store, verifier=verifier)
    binding = b"session-binding"
    assert isinstance(await service.begin_authentication("account-1", binding=binding), accounts_module.WebAuthnOptions)
    evidence = await service.verify_authentication("account-1", binding=binding, response='{"id":"credential"}')
    assert isinstance(evidence, AuthenticationEvidence)
    assert evidence.methods == frozenset({"passkey"})
    assert evidence.traits == frozenset({"phishing-resistant", "user-verified"})


@pytest.mark.parametrize(
    ("stored_count", "new_count", "policy", "expected_type", "suspect"),
    [
        (0, 0, accounts_module.CloneRiskPolicy.REJECT, AuthenticationEvidence, False),
        (0, 1, accounts_module.CloneRiskPolicy.REJECT, AuthenticationEvidence, False),
        (1, 2, accounts_module.CloneRiskPolicy.REJECT, AuthenticationEvidence, False),
        (1, 1, accounts_module.CloneRiskPolicy.REJECT, InvalidCredentials, True),
        (2, 1, accounts_module.CloneRiskPolicy.REJECT, InvalidCredentials, True),
        (100, 0, accounts_module.CloneRiskPolicy.REJECT, InvalidCredentials, True),
        (2, 1, accounts_module.CloneRiskPolicy.AUDIT_ONLY, AuthenticationEvidence, True),
    ],
)
async def test_passkey_counter_policy_persists_clone_risk_before_assurance(
    stored_count: int,
    new_count: int,
    policy: accounts_module.CloneRiskPolicy,
    expected_type: type[object],
    suspect: bool,  # noqa: FBT001
) -> None:
    store = PasskeyStore()
    store.credentials[b"credential-1"] = stored_passkey(sign_count=stored_count)
    verifier = WebAuthnVerifier(sign_count=new_count)
    service = build_passkey_service(store=store, verifier=verifier)
    service.clone_risk_policy = policy
    binding = b"session-binding"
    assert isinstance(await service.begin_authentication("account-1", binding=binding), accounts_module.WebAuthnOptions)
    outcome = await service.verify_authentication("account-1", binding=binding, response='{"id":"credential"}')
    assert isinstance(outcome, expected_type)
    assert store.credentials[b"credential-1"].suspect is suspect
    assert store.credentials[b"credential-1"].sign_count == max(stored_count, new_count)
    assert verifier.current_sign_counts == [stored_count]


async def test_passkey_listing_rename_and_removal_are_safe_and_final_method_guarded() -> None:
    store = PasskeyStore()
    store.credentials[b"credential-1"] = stored_passkey()
    login_methods = RecoveryLoginMethods(accounts_module.RevokeLoginMethodStatus.FINAL_METHOD)
    service = build_passkey_service(store=store, login_methods=login_methods)
    summaries = await service.list_credentials("account-1")
    renamed = await service.rename_credential("account-1", b"credential-1", "Work key")
    removal = await service.remove_credential("account-1", b"credential-1")
    assert len(summaries) == 1
    assert not hasattr(summaries[0], "public_key")
    assert renamed is not None
    assert renamed.display_name == "Work key"
    assert removal.status is accounts_module.RevokeLoginMethodStatus.FINAL_METHOD


async def test_passkey_defensive_registration_authentication_and_audit_outcomes() -> None:  # noqa: PLR0915
    binding = b"session-binding"
    assert not passkeys_module._valid_attestation_roots({"none": (b"root",)})  # noqa: SLF001
    service = build_passkey_service(verifier=InvalidAttestationVerifier())
    await service.begin_registration("account-1", user_name="person@example.com", binding=binding)
    assert isinstance(
        await service.verify_registration("account-1", binding=binding, response="{}"), InvalidCredentials
    )
    service = build_passkey_service(verifier=WebAuthnVerifier(backup_state=True))
    await service.begin_registration("account-1", user_name="person@example.com", binding=binding)
    assert isinstance(
        await service.verify_registration("account-1", binding=binding, response="{}"), InvalidCredentials
    )
    service = build_passkey_service(verifier=InvalidAttestationVerifier(), attestation_trust=UnanchoredAttestation())
    await service.begin_registration("account-1", user_name="person@example.com", binding=binding)
    assert isinstance(
        await service.verify_registration("account-1", binding=binding, response="{}"), InvalidCredentials
    )
    service = build_passkey_service(verifier=InvalidAttestationVerifier(), attestation_trust=TrustedAttestation())
    await service.begin_registration("account-1", user_name="person@example.com", binding=binding)
    assert isinstance(
        await service.verify_registration("account-1", binding=binding, response="{}"), InvalidCredentials
    )
    service = build_passkey_service(verifier=ChainAttestationVerifier(), attestation_trust=MismatchedAttestation())
    await service.begin_registration("account-1", user_name="person@example.com", binding=binding)
    assert isinstance(
        await service.verify_registration("account-1", binding=binding, response="{}"), InvalidCredentials
    )

    trusted_store = PasskeyStore()
    trusted_events = SecurityEvents()
    service = build_passkey_service(
        store=trusted_store, verifier=ChainAttestationVerifier(sign_count=1), attestation_trust=TrustedAttestation()
    )
    service.events = trusted_events
    await service.begin_registration("account-1", user_name="person@example.com", binding=binding)
    trusted = await service.verify_registration("account-1", binding=binding, response="{}")
    assert isinstance(trusted, accounts_module.PasskeyCredential)
    assert trusted.hardware_backed
    assert trusted_store.login_methods["pk_Y3JlZGVudGlhbC0x"].kind == "passkey"
    cast("ChainAttestationVerifier", service.verifier).sign_count = 2
    await service.begin_authentication("account-1", binding=binding)
    trusted_evidence = await service.verify_authentication("account-1", binding=binding, response="{}")
    assert isinstance(trusted_evidence, AuthenticationEvidence)
    assert "hardware-backed" in trusted_evidence.traits
    assert [(event.operation, event.outcome) for event in trusted_events.events] == [
        ("local.passkey.registration.verify", "created"),
        ("local.passkey.assert", "verified"),
    ]

    store = PasskeyStore()
    store.credentials[b"credential-1"] = stored_passkey()
    service = build_passkey_service(store=store)
    await service.begin_registration("account-1", user_name="person@example.com", binding=binding)
    assert isinstance(
        await service.verify_registration("account-1", binding=binding, response="{}"), InvalidCredentials
    )

    service = build_passkey_service(store=store)
    await service.begin_authentication("account-1", binding=binding)
    assert isinstance(await service.verify_authentication("other", binding=binding, response="{}"), InvalidCredentials)

    service = build_passkey_service(store=store, verifier=WebAuthnVerifier(failure="authentication"))
    await service.begin_authentication("account-1", binding=binding)
    assert isinstance(
        await service.verify_authentication("account-1", binding=binding, response="{}"), InvalidCredentials
    )

    challenge_store = WebAuthnChallengeStore()
    service = build_passkey_service(challenge_store=challenge_store, store=store)
    await service.begin_authentication("account-1", binding=binding)
    challenge_store.fail = True
    assert isinstance(
        await service.verify_authentication("account-1", binding=binding, response="{}"), VerificationUnavailable
    )

    service = build_passkey_service(store=store, verifier=WebAuthnVerifier(user_verified=False, sign_count=2))
    await service.begin_authentication("account-1", binding=binding)
    evidence = await service.verify_authentication("account-1", binding=binding, response="{}")
    assert isinstance(evidence, AuthenticationEvidence)
    assert "user-verified" not in evidence.traits

    service.login_methods = cast("Any", FailingRecoveryLoginMethods())
    assert isinstance(await service.remove_credential("account-1", b"credential-1"), VerificationUnavailable)
    service.events = SecurityEvents(fail=True)
    await service._emit_event(  # noqa: SLF001 - verifies best-effort audit isolation directly
        operation="passkey.assert", outcome="clone_risk", account_id="account-1", occurred_at=_JWT_NOW
    )


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"origins": ("http://example.com",)}, "HTTPS"),
        ({"origins": ("https://other.example",)}, "HTTPS"),
        ({"algorithms": (-999,)}, "algorithm"),
        ({"challenge_ttl": timedelta()}, "expiry"),
    ],
)
def test_passkey_service_rejects_insecure_or_unsupported_configuration(kwargs: dict[str, object], match: str) -> None:
    config: dict[str, object] = {
        "store": PasskeyStore(),
        "challenge_store": WebAuthnChallengeStore(),
        "rp_id": "example.com",
        "rp_name": "Example",
        "origins": ("https://example.com",),
    }
    config.update(kwargs)
    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.PasskeyService(**config)  # type: ignore[arg-type]


def test_pywebauthn_adapter_projects_pinned_dependency_results(monkeypatch: pytest.MonkeyPatch) -> None:
    client_data = b'{"type":"webauthn.get"}'
    credential = SimpleNamespace(
        raw_id=b"credential", response=SimpleNamespace(client_data_json=client_data, attestation_object=b"attestation")
    )
    verified = SimpleNamespace(
        credential_id=b"credential",
        credential_public_key=b"public-key",
        sign_count=1,
        new_sign_count=2,
        credential_device_type=passkeys_module.CredentialDeviceType.SINGLE_DEVICE,
        credential_backed_up=False,
        user_verified=True,
        aaguid="00000000-0000-0000-0000-000000000000",
        fmt=passkeys_module.AttestationFormat.PACKED,
    )
    monkeypatch.setattr(passkeys_module, "generate_registration_options", lambda **_kwargs: object())
    monkeypatch.setattr(passkeys_module, "generate_authentication_options", lambda **_kwargs: object())
    monkeypatch.setattr(passkeys_module, "options_to_json", lambda _options: "{}")
    monkeypatch.setattr(passkeys_module, "parse_registration_credential_json", lambda _response: credential)
    monkeypatch.setattr(
        passkeys_module,
        "parse_attestation_object",
        lambda _value: SimpleNamespace(att_stmt=SimpleNamespace(x5c=[b"leaf-certificate"])),
    )
    monkeypatch.setattr(passkeys_module, "parse_authentication_credential_json", lambda _response: credential)
    monkeypatch.setattr(
        passkeys_module, "parse_client_data_json", lambda _value: SimpleNamespace(challenge=b"challenge")
    )
    registration_kwargs: dict[str, object] = {}

    def verify_registration_response(**kwargs: object) -> object:
        registration_kwargs.update(kwargs)
        return verified

    monkeypatch.setattr(passkeys_module, "verify_registration_response", verify_registration_response)
    monkeypatch.setattr(passkeys_module, "verify_authentication_response", lambda **_kwargs: verified)
    adapter = accounts_module.PyWebAuthnVerifier()
    options_kwargs = {
        "challenge": b"challenge",
        "rp_id": "example.com",
        "rp_name": "Example",
        "account_id": "account-1",
        "user_name": "person@example.com",
        "timeout_ms": 300_000,
        "user_verification": "required",
        "algorithms": (-7,),
    }

    assert adapter.registration_options(**options_kwargs) == "{}"
    assert adapter.authentication_options(**options_kwargs) == "{}"
    assert adapter.registration_challenge("{}") == b"challenge"
    assert adapter.authentication_challenge("{}") == b"challenge"
    assert adapter.credential_id("{}") == b"credential"
    registration = adapter.verify_registration(
        response="{}",
        challenge=b"challenge",
        rp_id="example.com",
        origins=("https://example.com",),
        require_user_verification=True,
        algorithms=(-7,),
        root_certificates={"packed": (b"trusted-root",)},
    )
    authentication = adapter.verify_authentication(
        response="{}",
        challenge=b"challenge",
        rp_id="example.com",
        origins=("https://example.com",),
        public_key=b"public-key",
        current_sign_count=1,
        require_user_verification=True,
    )
    assert registration.credential_id == b"credential"
    assert registration.attestation_chain_verified
    assert registration_kwargs["pem_root_certs_bytes_by_fmt"] == {
        passkeys_module.AttestationFormat.PACKED: [b"trusted-root"]
    }
    verified.fmt = passkeys_module.AttestationFormat.APPLE
    unproven_builtin_root = adapter.verify_registration(
        response="{}",
        challenge=b"challenge",
        rp_id="example.com",
        origins=("https://example.com",),
        require_user_verification=True,
        algorithms=(-7,),
        root_certificates={"apple": (b"application-root",)},
    )
    assert not unproven_builtin_root.attestation_chain_verified
    assert authentication.sign_count == 2

    monkeypatch.setattr(passkeys_module, "options_to_json", lambda _options: 1 / 0)
    with pytest.raises(accounts_module.WebAuthnVerificationError):
        adapter.registration_options(**options_kwargs)
    with pytest.raises(accounts_module.WebAuthnVerificationError):
        adapter.authentication_options(**options_kwargs)
    monkeypatch.setattr(passkeys_module, "verify_registration_response", lambda **_kwargs: 1 / 0)
    monkeypatch.setattr(passkeys_module, "verify_authentication_response", lambda **_kwargs: 1 / 0)
    with pytest.raises(accounts_module.WebAuthnVerificationError):
        adapter.verify_registration(
            response="{}",
            challenge=b"challenge",
            rp_id="example.com",
            origins=("https://example.com",),
            require_user_verification=True,
            algorithms=(-7,),
        )
    with pytest.raises(accounts_module.WebAuthnVerificationError):
        adapter.verify_authentication(
            response="{}",
            challenge=b"challenge",
            rp_id="example.com",
            origins=("https://example.com",),
            public_key=b"public-key",
            require_user_verification=True,
        )


async def test_passkey_service_defensive_store_and_ceremony_outcomes_are_sanitized() -> None:
    store = PasskeyStore()
    service = build_passkey_service(store=store)
    assert isinstance(await service.remove_credential("account-1", b"credential"), VerificationUnavailable)
    assert await service.rename_credential("account-1", b"credential", " ") is None
    store.fail = True
    assert isinstance(await service.list_credentials("account-1"), VerificationUnavailable)
    assert isinstance(await service.rename_credential("account-1", b"credential", "Laptop"), VerificationUnavailable)
    store.fail = False
    service.challenge_entropy = cast("Any", lambda _size: b"short")
    assert isinstance(await service.begin_authentication("account-1", binding=b"session"), VerificationUnavailable)
    service.challenge_entropy = lambda size: b"c" * size
    assert isinstance(await service.begin_authentication("account-1", binding=b""), VerificationUnavailable)

    conflict_store = ConflictingPasskeyStore()
    conflict_store.credentials[b"credential-1"] = stored_passkey()
    conflict_service = build_passkey_service(store=conflict_store)
    options = await conflict_service.begin_authentication("account-1", binding=b"session")
    assert isinstance(options, accounts_module.WebAuthnOptions)
    assert isinstance(
        await conflict_service.verify_authentication("account-1", binding=b"session", response="{}"), InvalidCredentials
    )


async def test_passkey_worker_timeout_cancels_the_request_boundary() -> None:
    service = build_passkey_service(verifier=SlowWebAuthnVerifier(), worker_timeout=0.001)
    assert isinstance(await service.begin_authentication("account-1", binding=b"binding"), VerificationUnavailable)


async def test_local_auth_passkey_login_selects_only_configured_transport() -> None:
    account = accounts_module.LocalAccountState(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Person",
        active=True,
        verified=True,
        security_epoch=1,
    )

    accounts = MutableAccountLookup(account)
    session = StaticSessionIssuer(
        accounts_module.SessionAuthentication(
            session_id="c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M",
            binding_id="sb_aWlpaWlpaWlpaWlpaWlpaQ",
            account_id="account-1",
            security_epoch=1,
            authenticated_at=_JWT_NOW,
            expires_at=_JWT_NOW + timedelta(hours=1),
        )
    )
    tokens = RecordingTokenIssuer(object())
    evidence = AuthenticationEvidence(
        mechanism="passkey",
        slot="mfa",
        authenticated_at=_JWT_NOW,
        methods=frozenset({"passkey"}),
        traits=frozenset({"phishing-resistant"}),
    )

    def services(
        *, session_auth: object | None, refresh_tokens: object | None
    ) -> accounts_module.LocalAuthService[Any]:
        return accounts_module.LocalAuthService(
            accounts=cast("Any", accounts),
            password_login=cast("Any", object()),
            password_reauthentication=cast("Any", object()),
            password_change=cast("Any", object()),
            verification=cast("Any", object()),
            recovery=cast("Any", object()),
            session_auth=cast("Any", session_auth),
            refresh_tokens=cast("Any", refresh_tokens),
        )

    result = await services(session_auth=session, refresh_tokens=None).passkey_login(
        cast("Any", object()), "account-1", transport=None, evidence=evidence
    )
    assert isinstance(result, accounts_module.LocalAccount)
    assert (
        await services(session_auth=None, refresh_tokens=tokens).passkey_login(
            cast("Any", object()), "account-1", transport=None, evidence=evidence
        )
        is tokens.result
    )
    assert tokens.evidence is evidence
    assert isinstance(
        await services(session_auth=session, refresh_tokens=tokens).passkey_login(
            cast("Any", object()), "account-1", transport=None, evidence=evidence
        ),
        InvalidCredentials,
    )
    assert isinstance(
        await services(session_auth=None, refresh_tokens=None).passkey_login(
            cast("Any", object()), "account-1", transport="session", evidence=evidence
        ),
        InvalidCredentials,
    )
    assert isinstance(
        await services(session_auth=None, refresh_tokens=None).passkey_login(
            cast("Any", object()), "account-1", transport="tokens", evidence=evidence
        ),
        InvalidCredentials,
    )
    original_session_result = session.result
    session.result = VerificationUnavailable()
    assert isinstance(
        await services(session_auth=session, refresh_tokens=None).passkey_login(
            cast("Any", object()), "account-1", transport="session", evidence=evidence
        ),
        VerificationUnavailable,
    )
    session.result = original_session_result
    accounts.value = None
    assert isinstance(
        await services(session_auth=session, refresh_tokens=None).passkey_login(
            cast("Any", object()), "account-1", transport="session", evidence=evidence
        ),
        InvalidCredentials,
    )
    accounts.value = OSError()
    assert isinstance(
        await services(session_auth=session, refresh_tokens=None).passkey_login(
            cast("Any", object()), "account-1", transport="session", evidence=evidence
        ),
        VerificationUnavailable,
    )


def test_passkey_values_and_dependency_configuration_reject_invalid_shapes() -> None:
    now = datetime(2026, 7, 27, tzinfo=timezone.utc)
    with pytest.raises(ImproperlyConfiguredException, match="LoginMethodStore"):
        build_passkey_service(login_methods=cast("Any", object()))
    with pytest.raises(ValueError, match="challenge"):
        accounts_module.WebAuthnChallenge(
            challenge_digest=b"short",
            binding_digest=b"b" * 32,
            purpose="registration",
            account_id="account-1",
            rp_id="example.com",
            origins=("https://example.com",),
            user_verification=accounts_module.UserVerification.REQUIRED,
            algorithms=(-7,),
            expires_at=now,
        )
    with pytest.raises(ValueError, match="Passkey credential"):
        replace(stored_passkey(), backup_state=True)
    base: dict[str, object] = {
        "store": PasskeyStore(),
        "challenge_store": WebAuthnChallengeStore(),
        "verifier": WebAuthnVerifier(),
        "rp_id": "example.com",
        "rp_name": "Example",
        "origins": ("https://example.com",),
    }
    for replacement, match in (
        ({"store": object()}, "Store"),
        ({"challenge_store": object()}, "Store"),
        ({"verifier": object()}, "verifier"),
        ({"worker_limiter": object()}, "limiter"),
        ({"worker_timeout": 0}, "configuration"),
        ({"attestation_trust": object()}, "attestation"),
        ({"origins": ("https://user@example.com",)}, "HTTPS"),
        ({"origins": ("https://example.com/path",)}, "HTTPS"),
        ({"origins": ("https://example.com:bad",)}, "HTTPS"),
    ):
        config = {**base, **replacement}
        with pytest.raises(ImproperlyConfiguredException, match=match):
            accounts_module.PasskeyService(**config)  # type: ignore[arg-type]
    localhost_config = {
        **base,
        "origins": ("http://localhost:8000",),
        "rp_id": "localhost",
        "allow_insecure_localhost": True,
    }
    localhost = accounts_module.PasskeyService(**localhost_config)  # type: ignore[arg-type]
    assert localhost.allow_insecure_localhost is True


@pytest.mark.parametrize(
    ("stored_be", "stored_bs", "new_be", "new_bs", "expected_type"),
    [
        (False, False, False, False, AuthenticationEvidence),
        (True, False, True, True, AuthenticationEvidence),
        (True, True, True, False, AuthenticationEvidence),
        (True, False, False, False, InvalidCredentials),
        (False, False, False, True, InvalidCredentials),
    ],
)
async def test_passkey_backup_eligibility_is_immutable_and_state_may_transition(
    stored_be: bool,  # noqa: FBT001
    stored_bs: bool,  # noqa: FBT001
    new_be: bool,  # noqa: FBT001
    new_bs: bool,  # noqa: FBT001
    expected_type: type[object],
) -> None:
    store = PasskeyStore()
    store.credentials[b"credential-1"] = stored_passkey(backup_eligible=stored_be, backup_state=stored_bs)
    verifier = WebAuthnVerifier(backup_eligible=new_be, backup_state=new_bs)
    service = build_passkey_service(store=store, verifier=verifier)
    binding = b"session-binding"
    assert isinstance(await service.begin_authentication("account-1", binding=binding), accounts_module.WebAuthnOptions)

    outcome = await service.verify_authentication("account-1", binding=binding, response='{"id":"credential"}')

    assert isinstance(outcome, expected_type)


async def test_testing_stores_cover_expiry_update_and_clone_risk_outcomes() -> None:
    now = datetime(2026, 7, 27, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="timezone-aware"):
        testing_module.FakeClock(now.replace(tzinfo=None))
    store = testing_module.InMemoryMFAStore()
    pending = accounts_module.PendingTOTPEnrollment(
        enrollment_id="e1",
        method_id="m1",
        account_id="a1",
        protected_secret=accounts_module.ProtectedSecret(b"cipher", "v1"),
        policy=accounts_module.TOTPPolicy(),
        created_at=now - timedelta(minutes=2),
        expires_at=now - timedelta(minutes=1),
    )
    login_method = accounts_module.LoginMethod("m1", "totp", now)
    event = accounts_module.SecurityEvent("event-1", now, "mfa.totp.verify", "verified", "a1")
    await store.create_totp_enrollment(pending)
    assert await store.get_totp_enrollment("e1") is pending
    assert (
        await store.activate_totp("a1", "e1", accepted_counter=1, login_method=login_method, event=event, now=now)
        is None
    )
    assert (
        await store.activate_totp_with_recovery_codes(
            "a1", "e1", accepted_counter=1, codes=(), login_method=login_method, event=event, now=now
        )
        is None
    )
    active = replace(pending, enrollment_id="e2", expires_at=now + timedelta(minutes=1))
    await store.create_totp_enrollment(active)
    digest = accounts_module.RecoveryCodeDigest("a1", "v1", b"d" * 32)
    activated = await store.activate_totp_with_recovery_codes(
        "a1", "e2", accepted_counter=1, codes=(digest,), login_method=login_method, event=event, now=now
    )
    assert activated is not None
    assert store.recovery_codes["a1"] == (digest,)
    assert store.login_methods["m1"] == login_method
    assert store.events == [event]
    assert await store.advance_totp_counter("m1", accepted_counter=2, now=now)

    credential = stored_passkey()
    passkeys = testing_module.InMemoryPasskeyStore()
    assert await passkeys.add_credential(
        credential,
        login_method=accounts_module.LoginMethod("pk_credential-1", "passkey", now),
        event=accounts_module.SecurityEvent("event-2", now, "passkey.register.verify", "created", "account-1"),
    )
    assert passkeys.login_methods["pk_credential-1"].kind == "passkey"
    assert passkeys.events[-1].event_id == "event-2"
    assert (
        await passkeys.record_assertion(
            credential.credential_id,
            expected_version=0,
            sign_count=0,
            backup_eligible=False,
            backup_state=False,
            clone_risk=True,
            now=now,
        )
        is accounts_module.PasskeyAssertionStatus.CLONE_RISK
    )
