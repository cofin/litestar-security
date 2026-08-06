"""Source-oriented accounts unit tests."""

import hmac
from collections.abc import Callable  # noqa: TC003
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, cast

import pytest
from litestar.exceptions import ImproperlyConfiguredException

import litestar_security.accounts as accounts_module
import litestar_security.accounts._sessions as sessions_module
from litestar_security.authentication import (
    Authenticated,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
    VerificationUnavailable,
)
from litestar_security.context import AuthenticationEvidence, NullSessionHandle, Principal, SecurityContext
from litestar_security.guards import requires_assurance
from tests.fixtures.accounts import (
    _copy_native_session,
    _native_session_connection,
    _NativeSessionStore,
    _queued_binding_token,
    _SessionEntropy,
)

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)
_NAIVE_JWT_NOW = datetime(2026, 7, 26)  # noqa: DTZ001 - explicit rejection fixture
_JWT_ISSUER = "https://issuer.example"
_JWT_AUDIENCE = "litestar-security"
_OIDC_ISSUER = "https://issuer.example/tenant"
_OIDC_DISCOVERY_URL = f"{_OIDC_ISSUER}/.well-known/openid-configuration"
_OIDC_PUBLIC_IP = "93.184.216.34"
_JWKS_URI = f"{_JWT_ISSUER}/.well-known/jwks.json"
_MFA_VECTOR_NOW = datetime.fromtimestamp(59, tz=timezone.utc)
_MFA_ENCODED_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
_MFA_POLICY = accounts_module.TOTPPolicy()
_ACCOUNT_NOW = datetime(2026, 7, 27, tzinfo=timezone.utc)


_SESSION_ID = "c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M"
_BINDING_ID = "sb_aWlpaWlpaWlpaWlpaWlpaQ"


def test_native_session_legacy_v1_decode_does_not_synthesize_password_assurance() -> None:
    authentication = sessions_module.NativeSessionAuth._decode_authentication(  # noqa: SLF001 - decode contract regression
        {
            "version": 1,
            "session_id": "bm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm4",
            "binding_id": "sb_aWlpaWlpaWlpaWlpaWlpaQ",
            "account_id": "account-1",
            "security_epoch": 1,
            "authenticated_at": _JWT_NOW.isoformat(),
            "expires_at": (_JWT_NOW + timedelta(hours=1)).isoformat(),
        }
    )

    assert authentication is not None
    assert authentication.methods == frozenset()
    assert authentication.amr == ()
    assert authentication.traits == frozenset({"session"})
    evidence = AuthenticationEvidence(
        mechanism="session",
        slot="session",
        authenticated_at=authentication.authenticated_at,
        expires_at=authentication.expires_at,
        methods=authentication.methods,
        traits=authentication.traits,
        amr=authentication.amr,
    )
    decision = requires_assurance(methods={"password"}, clock=lambda: _JWT_NOW).decide(
        cast(
            "Any",
            SimpleNamespace(
                user=Principal(id=authentication.account_id),
                auth=SecurityContext(session=NullSessionHandle(), evidence=(evidence,)),
            ),
        )
    )
    assert not decision.granted
    assert decision.code == "missing_assurance"


def test_native_session_payload_preserves_independent_assurance_expiry() -> None:
    """Session serialization retains a step-up expiry shorter than the session lifetime."""
    assurance_expires_at = _JWT_NOW + timedelta(minutes=5)
    authentication = accounts_module.SessionAuthentication(
        session_id="bm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm4",
        binding_id="sb_aWlpaWlpaWlpaWlpaWlpaQ",
        account_id="account-1",
        security_epoch=1,
        authenticated_at=_JWT_NOW,
        expires_at=_JWT_NOW + timedelta(hours=1),
        assurance_expires_at=assurance_expires_at,
        methods=frozenset({"totp"}),
    )

    payload = sessions_module.NativeSessionAuth._encode_authentication(authentication)  # noqa: SLF001
    restored = sessions_module.NativeSessionAuth._decode_authentication(payload)  # noqa: SLF001

    assert restored is not None
    assert restored.assurance_expires_at == assurance_expires_at


async def test_native_session_remains_authenticated_after_step_up_assurance_expires() -> None:
    """A short step-up expiry does not shorten the underlying native session."""
    store = _NativeSessionStore()
    current = [_JWT_NOW]
    auth = accounts_module.NativeSessionAuth(
        accounts=store,
        binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        clock=lambda: current[0],
        entropy=_SessionEntropy(),
    )
    session: dict[str, object] = {}
    connection = _native_session_connection(session)
    evidence = AuthenticationEvidence(
        mechanism="totp",
        slot="mfa",
        authenticated_at=_JWT_NOW,
        expires_at=_JWT_NOW + timedelta(minutes=5),
        methods=frozenset({"totp"}),
    )
    established = await auth.establish(
        connection, cast("accounts_module.LocalAccountRecord[object]", store.account), evidence=evidence
    )
    assert isinstance(established, accounts_module.SessionAuthentication)
    token = _queued_binding_token(connection)
    current[0] += timedelta(minutes=6)
    authenticated_connection = _native_session_connection(session, binding_token=token)
    extraction = auth.extract(authenticated_connection)
    assert isinstance(extraction, PresentedCredential)

    outcome = await auth.authenticate(extraction.value, authenticated_connection)

    assert isinstance(outcome, Authenticated)
    authenticated_connection.scope["user"] = Principal(id="account-1")
    authenticated_connection.scope["auth"] = SecurityContext(session=NullSessionHandle(), evidence=(outcome.evidence,))
    decision = requires_assurance(methods={"totp"}, clock=lambda: current[0]).decide(authenticated_connection)
    assert decision.code == "missing_assurance"


async def test_native_session_establish_authenticate_touch_and_rebind_are_fixation_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _NativeSessionStore()
    current = [_JWT_NOW]
    auth = accounts_module.NativeSessionAuth(
        accounts=store,
        binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32, preserve_session_keys=("cart",)),
        clock=lambda: current[0],
        entropy=_SessionEntropy(),
        event_ids=lambda: "event-1",
    )
    session: dict[str, object] = {"cart": "anonymous", "discard": "value"}
    connection = _native_session_connection(session)

    authentication = await auth.establish(
        connection,
        cast("accounts_module.LocalAccountRecord[object]", store.account),
        display_metadata={"device": "browser"},
    )

    assert isinstance(authentication, accounts_module.SessionAuthentication)
    assert session == {
        "cart": "anonymous",
        "_litestar_security": {
            "version": 3,
            "session_id": authentication.session_id,
            "binding_id": authentication.binding_id,
            "account_id": "account-1",
            "security_epoch": 1,
            "authenticated_at": _JWT_NOW.isoformat(),
            "expires_at": (_JWT_NOW + timedelta(days=14)).isoformat(),
            "assurance_expires_at": None,
            "methods": ["password"],
            "traits": ["session"],
            "amr": ["pwd"],
        },
    }

    with pytest.raises(ValueError, match="assurance"):
        replace(authentication, methods=cast("Any", {1}))
    token = _queued_binding_token(connection)
    assert token.startswith(f"{authentication.binding_id}.")
    assert token not in repr(store.commands)
    assert "binding_digest" not in repr(store.commands[0])

    comparisons: list[tuple[bytes | str, bytes | str]] = []

    def monitored_compare_digest(left: bytes | str, right: bytes | str) -> bool:
        comparisons.append((left, right))
        return hmac.compare_digest(left, right)

    monkeypatch.setattr(sessions_module, "compare_digest", monitored_compare_digest)
    authenticated_connection = _native_session_connection(session, binding_token=token)
    extraction = auth.extract(authenticated_connection)
    assert isinstance(extraction, PresentedCredential)
    outcome = await auth.authenticate(extraction.value, authenticated_connection)
    assert isinstance(outcome, Authenticated)
    assert outcome.evidence.mechanism == "session"
    assert outcome.evidence.traits == frozenset({"session"})
    assert comparisons == [
        (authentication.binding_id.encode(), store.records[authentication.session_id].binding_id.encode()),
        (extraction.value.binding.digest, store.records[authentication.session_id].binding_digest),
    ]
    principal = await auth.resolve(outcome.claims)
    assert (principal.id, principal.display_name, principal.user) == ("account-1", "User", store.account.user)
    assert store.touches == []

    current[0] += timedelta(minutes=5)
    assert isinstance(await auth.authenticate(extraction.value, authenticated_connection), Authenticated)
    assert store.touches == [(authentication.session_id, current[0])]

    old_session = _copy_native_session(session)
    old_token = token
    replacement = await auth.establish(connection, cast("accounts_module.LocalAccountRecord[object]", store.account))
    assert isinstance(replacement, accounts_module.SessionAuthentication)
    assert replacement.session_id != authentication.session_id
    assert store.rebinds[0][0] == authentication.session_id
    replacement_token = _queued_binding_token(connection)
    assert replacement_token != old_token

    replay_connection = _native_session_connection(old_session, binding_token=old_token)
    replay = auth.extract(replay_connection)
    assert isinstance(replay, PresentedCredential)
    assert isinstance(await auth.authenticate(replay.value, replay_connection), InvalidCredentials)
    assert "_litestar_security" not in old_session
    replacement_connection = _native_session_connection(session, binding_token=replacement_token)
    replacement_extraction = auth.extract(replacement_connection)
    assert isinstance(replacement_extraction, PresentedCredential)
    assert isinstance(await auth.authenticate(replacement_extraction.value, replacement_connection), Authenticated)


async def test_native_session_binds_evidence_authentication_time_to_durable_record() -> None:
    store = _NativeSessionStore()
    auth = accounts_module.NativeSessionAuth(
        accounts=store,
        binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        clock=lambda: _JWT_NOW,
        entropy=_SessionEntropy(),
    )
    session: dict[str, object] = {}
    establishing_connection = _native_session_connection(session)
    evidence_authenticated_at = _JWT_NOW - timedelta(minutes=5)
    established = await auth.establish(
        establishing_connection,
        cast("accounts_module.LocalAccountRecord[object]", store.account),
        evidence=AuthenticationEvidence(
            mechanism="local",
            slot="password",
            authenticated_at=evidence_authenticated_at,
            expires_at=_JWT_NOW + timedelta(hours=1),
            methods=frozenset({"password"}),
            traits=frozenset(),
            amr=("pwd",),
        ),
    )

    assert isinstance(established, accounts_module.SessionAuthentication)
    assert established.authenticated_at == evidence_authenticated_at
    assert store.records[established.session_id].created_at == _JWT_NOW
    token = _queued_binding_token(establishing_connection)
    connection = _native_session_connection(session, binding_token=token)
    extraction = auth.extract(connection)
    assert isinstance(extraction, PresentedCredential)
    assert isinstance(await auth.authenticate(extraction.value, connection), Authenticated)

    payload = cast("dict[str, object]", session["_litestar_security"])
    payload["authenticated_at"] = (_JWT_NOW - timedelta(minutes=4)).isoformat()
    tampered_connection = _native_session_connection(session, binding_token=token)
    tampered_extraction = auth.extract(tampered_connection)
    assert isinstance(tampered_extraction, PresentedCredential)
    assert isinstance(await auth.authenticate(tampered_extraction.value, tampered_connection), InvalidCredentials)
    assert "_litestar_security" not in session


@pytest.mark.parametrize(
    ("session_value", "binding_token", "outcome_type", "cleared"),
    [
        ({}, None, NoCredentials, False),
        ({"_litestar_security": {"version": 2}}, None, InvalidCredentials, True),
        ({}, "malformed", InvalidCredentials, True),
        ({"_litestar_security": "malformed"}, "malformed", InvalidCredentials, True),
    ],
)
def test_native_session_extraction_is_strict_and_cleans_only_presented_invalid_http_state(
    session_value: dict[str, object], binding_token: str | None, outcome_type: type[object], *, cleared: bool
) -> None:
    auth = accounts_module.NativeSessionAuth(
        accounts=_NativeSessionStore(), binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32)
    )
    connection = _native_session_connection(session_value, binding_token=binding_token)

    outcome = auth.extract(connection)

    assert isinstance(outcome, outcome_type)
    assert ("_litestar_security_response_headers" in connection.scope) is cleared
    if cleared:
        assert "_litestar_security" not in session_value


@pytest.mark.parametrize("failure", ["get", "account", "epoch"])
async def test_native_session_transient_verification_failures_preserve_retryable_state(failure: str) -> None:
    store = _NativeSessionStore()
    auth = accounts_module.NativeSessionAuth(
        accounts=store,
        binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        clock=lambda: _JWT_NOW,
        entropy=_SessionEntropy(),
    )
    session: dict[str, object] = {}
    establishing_connection = _native_session_connection(session)
    assert isinstance(
        await auth.establish(
            establishing_connection, cast("accounts_module.LocalAccountRecord[object]", store.account)
        ),
        accounts_module.SessionAuthentication,
    )
    connection = _native_session_connection(session, binding_token=_queued_binding_token(establishing_connection))
    extraction = auth.extract(connection)
    assert isinstance(extraction, PresentedCredential)
    store.failures.add(failure)

    outcome = await auth.authenticate(extraction.value, connection)

    assert isinstance(outcome, VerificationUnavailable)
    assert "_litestar_security" in session
    assert "_litestar_security_response_headers" not in connection.scope


@pytest.mark.parametrize(
    "invalid_state", ["missing", "disabled", "unverified", "epoch", "binding", "authenticated_at", "expired"]
)
async def test_native_session_current_state_mismatch_is_invalid_and_cleared(invalid_state: str) -> None:
    store = _NativeSessionStore()
    current = [_JWT_NOW]
    auth = accounts_module.NativeSessionAuth(
        accounts=store,
        binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        clock=lambda: current[0],
        entropy=_SessionEntropy(),
    )
    session: dict[str, object] = {}
    establishing_connection = _native_session_connection(session)
    established = await auth.establish(
        establishing_connection, cast("accounts_module.LocalAccountRecord[object]", store.account)
    )
    assert isinstance(established, accounts_module.SessionAuthentication)
    if invalid_state == "missing":
        store.records.clear()
    elif invalid_state in {"disabled", "unverified"}:
        store.account = accounts_module.LocalAccountRecord(
            account_id="account-1",
            normalized_identifier="user@example.com",
            display_name="User",
            active=invalid_state != "disabled",
            verified=invalid_state != "unverified",
            security_epoch=1,
        )
    elif invalid_state == "epoch":
        store.epoch = 2
    elif invalid_state == "binding":
        record = store.records[established.session_id]
        store.records[established.session_id] = accounts_module.SessionRecord(
            session_id=record.session_id,
            binding_id=record.binding_id,
            binding_digest=b"x" * 32,
            account_id=record.account_id,
            security_epoch=record.security_epoch,
            created_at=record.created_at,
            authenticated_at=record.authenticated_at,
            last_seen_at=record.last_seen_at,
            expires_at=record.expires_at,
        )
    elif invalid_state == "authenticated_at":
        payload = cast("dict[str, object]", session["_litestar_security"])
        payload["authenticated_at"] = (_JWT_NOW + timedelta(seconds=1)).isoformat()
    else:
        current[0] = established.expires_at
    connection = _native_session_connection(session, binding_token=_queued_binding_token(establishing_connection))
    extraction = auth.extract(connection)
    assert isinstance(extraction, PresentedCredential)

    outcome = await auth.authenticate(extraction.value, connection)

    assert isinstance(outcome, InvalidCredentials)
    assert "_litestar_security" not in session
    assert _queued_binding_token(connection) == ""


async def test_native_session_logout_and_account_qualified_revoke_are_explicit_and_idempotent() -> None:
    store = _NativeSessionStore()
    auth = accounts_module.NativeSessionAuth(
        accounts=store,
        binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        clock=lambda: _JWT_NOW,
        entropy=_SessionEntropy(),
        event_ids=lambda: "event-1",
    )
    session: dict[str, object] = {}
    connection = _native_session_connection(session)
    current = await auth.establish(connection, cast("accounts_module.LocalAccountRecord[object]", store.account))
    assert isinstance(current, accounts_module.SessionAuthentication)
    other = _NativeSessionStore.record(
        accounts_module.CreateSessionCommand(
            session_id="bm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm4",
            binding_id="sb_aWlpaWlpaWlpaWlpaWlpaQ",
            binding_digest=b"b" * 32,
            account_id="account-1",
            security_epoch=1,
            created_at=_JWT_NOW,
            authenticated_at=_JWT_NOW,
            expires_at=_JWT_NOW + timedelta(hours=1),
        )
    )
    store.records[other.session_id] = other

    assert await auth.revoke_session(connection, "account-1", other.session_id, now=_JWT_NOW)
    assert "_litestar_security" in session
    assert not await auth.revoke_session(connection, "account-2", current.session_id, now=_JWT_NOW)
    assert await auth.logout(connection, now=_JWT_NOW)
    assert "_litestar_security" not in session
    assert not await auth.logout(connection, now=_JWT_NOW)
    assert store.revocations == [
        ("account-1", other.session_id),
        ("account-2", current.session_id),
        ("account-1", current.session_id),
    ]


async def test_native_session_password_rebind_plan_activates_only_the_committed_record() -> None:
    store = _NativeSessionStore()
    auth = accounts_module.NativeSessionAuth(
        accounts=store,
        binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        clock=lambda: _JWT_NOW,
        entropy=_SessionEntropy(),
    )
    session: dict[str, object] = {}
    connection = _native_session_connection(session)
    current = await auth.establish(connection, cast("accounts_module.LocalAccountRecord[object]", store.account))
    assert isinstance(current, accounts_module.SessionAuthentication)
    assert auth.current_authentication(connection) == current

    plan = auth.prepare_password_rebind(connection, cast("accounts_module.LocalAccountRecord[object]", store.account))
    assert isinstance(plan, accounts_module.SessionRebindPlan)
    assert plan.binding_token not in repr(plan)
    replacement = replace(plan.command, security_epoch=2)
    event = accounts_module.SecurityEvent(
        event_id="event",
        occurred_at=_JWT_NOW,
        operation="local.password.session_rebind",
        outcome="rebound",
        account_id="account-1",
    )
    assert await store.rebind(plan.prior_session_id, replacement, event=event)

    assert await auth.activate_password_rebind(connection, plan, 2)
    activated = auth.current_authentication(connection)
    assert activated is not None
    assert (activated.session_id, activated.security_epoch) == (replacement.session_id, 2)
    assert _queued_binding_token(connection) == plan.binding_token

    with pytest.raises(ValueError, match="Session rebind plan"):
        replace(plan, prior_session_id=plan.command.session_id)

    empty_connection = _native_session_connection({})
    assert isinstance(
        auth.prepare_password_rebind(
            empty_connection, cast("accounts_module.LocalAccountRecord[object]", store.account)
        ),
        VerificationUnavailable,
    )
    assert isinstance(
        replace(auth, entropy=lambda _size: b"").prepare_password_rebind(
            connection, cast("accounts_module.LocalAccountRecord[object]", store.account)
        ),
        VerificationUnavailable,
    )

    assert not await auth.activate_password_rebind(connection, cast("Any", object()), 2)
    assert auth.current_authentication(connection) is None

    current = await auth.establish(connection, cast("accounts_module.LocalAccountRecord[object]", store.account))
    assert isinstance(current, accounts_module.SessionAuthentication)
    failed_plan = auth.prepare_password_rebind(
        connection, cast("accounts_module.LocalAccountRecord[object]", store.account)
    )
    assert isinstance(failed_plan, accounts_module.SessionRebindPlan)

    async def failing_get(_session_id: str) -> accounts_module.SessionRecord | None:
        raise OSError

    original_get = store.get
    store.get = failing_get  # type: ignore[method-assign]
    assert not await auth.activate_password_rebind(connection, failed_plan, 2)
    store.get = original_get  # type: ignore[method-assign]

    current = await auth.establish(connection, cast("accounts_module.LocalAccountRecord[object]", store.account))
    assert isinstance(current, accounts_module.SessionAuthentication)
    missing_plan = auth.prepare_password_rebind(
        connection, cast("accounts_module.LocalAccountRecord[object]", store.account)
    )
    assert isinstance(missing_plan, accounts_module.SessionRebindPlan)
    assert not await auth.activate_password_rebind(connection, missing_plan, 2)

    current = await auth.establish(connection, cast("accounts_module.LocalAccountRecord[object]", store.account))
    assert isinstance(current, accounts_module.SessionAuthentication)
    mismatch_plan = auth.prepare_password_rebind(
        connection, cast("accounts_module.LocalAccountRecord[object]", store.account)
    )
    assert isinstance(mismatch_plan, accounts_module.SessionRebindPlan)
    store.records[mismatch_plan.command.session_id] = _NativeSessionStore.record(
        replace(mismatch_plan.command, security_epoch=3)
    )
    assert not await auth.activate_password_rebind(connection, mismatch_plan, 2)


async def test_native_session_lists_safe_summaries_and_websocket_lifecycle_is_read_only() -> None:
    store = _NativeSessionStore()
    auth = accounts_module.NativeSessionAuth(
        accounts=store,
        binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        clock=lambda: _JWT_NOW,
        entropy=_SessionEntropy(),
    )
    session: dict[str, object] = {}
    connection = _native_session_connection(session)
    current = await auth.establish(connection, cast("accounts_module.LocalAccountRecord[object]", store.account))
    assert isinstance(current, accounts_module.SessionAuthentication)
    summaries = await auth.list_sessions("account-1", current_session_id=current.session_id)
    assert len(summaries) == 1
    assert summaries[0].current
    assert not hasattr(summaries[0], "binding_id")
    assert not hasattr(summaries[0], "binding_digest")
    assert await auth.list_sessions(" ") == ()

    websocket_session = _copy_native_session(session)
    websocket = _native_session_connection(
        websocket_session, binding_token=_queued_binding_token(connection), scope_type="websocket"
    )
    extraction = auth.extract(websocket)
    assert isinstance(extraction, PresentedCredential)
    assert isinstance(await auth.authenticate(extraction.value, websocket), Authenticated)
    assert isinstance(
        await auth.establish(websocket, cast("accounts_module.LocalAccountRecord[object]", store.account)),
        VerificationUnavailable,
    )
    assert isinstance(await auth.logout(websocket), VerificationUnavailable)
    assert isinstance(await auth.revoke_session(websocket, "account-1", current.session_id), VerificationUnavailable)
    assert websocket_session == session
    assert "_litestar_security_response_headers" not in websocket.scope

    invalid_websocket_session = _copy_native_session(session)
    invalid_websocket = _native_session_connection(
        invalid_websocket_session,
        binding_token="malformed",  # noqa: S106
        scope_type="websocket",
    )
    assert isinstance(auth.extract(invalid_websocket), InvalidCredentials)
    assert invalid_websocket_session == session
    assert "_litestar_security_response_headers" not in invalid_websocket.scope


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("accounts", object(), "account, epoch"),
        ("binding", object(), "SessionBindingConfig"),
        ("clock", None, "hooks"),
        ("entropy", None, "hooks"),
        ("event_ids", None, "hooks"),
    ],
)
def test_native_session_auth_rejects_invalid_runtime_dependencies(field: str, value: object, match: str) -> None:
    values: dict[str, object] = {
        "accounts": _NativeSessionStore(),
        "binding": accounts_module.SessionBindingConfig(pepper=b"p" * 32),
    }
    values[field] = value

    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.NativeSessionAuth(**values)  # type: ignore[arg-type]


async def test_native_session_rejects_wrong_credential_and_ignores_touch_failure() -> None:
    store = _NativeSessionStore()
    current = [_JWT_NOW]
    auth = accounts_module.NativeSessionAuth(
        accounts=store,
        binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        clock=lambda: current[0],
        entropy=_SessionEntropy(),
    )
    session: dict[str, object] = {}
    establishing_connection = _native_session_connection(session)
    established = await auth.establish(
        establishing_connection, cast("accounts_module.LocalAccountRecord[object]", store.account)
    )
    assert isinstance(established, accounts_module.SessionAuthentication)
    wrong_connection = _native_session_connection(_copy_native_session(session))

    assert isinstance(await auth.authenticate(cast("Any", object()), wrong_connection), InvalidCredentials)
    assert "_litestar_security" not in wrong_connection.scope["session"]

    connection = _native_session_connection(session, binding_token=_queued_binding_token(establishing_connection))
    extraction = auth.extract(connection)
    assert isinstance(extraction, PresentedCredential)
    current[0] += timedelta(minutes=5)
    store.failures.add("touch")

    assert isinstance(await auth.authenticate(extraction.value, connection), Authenticated)


@pytest.mark.parametrize(
    "case",
    ["invalid_account", "create_failure", "record_mismatch", "lookup_entropy", "secret_entropy", "event_id", "clock"],
)
async def test_native_session_establishment_fails_closed_without_revealing_a_cookie(case: str) -> None:  # noqa: C901
    def valid_event_id() -> str:
        return "event-1"

    def valid_clock() -> datetime:
        return _JWT_NOW

    def short_entropy(length: int) -> bytes:
        return b"x" * (length - 1)

    secret_values = iter((b"i" * 16, b"short"))

    def invalid_secret_entropy(_length: int) -> bytes:
        return next(secret_values)

    def invalid_event_id() -> str:
        return " "

    def naive_clock() -> datetime:
        return _JWT_NOW.replace(tzinfo=None)

    store = _NativeSessionStore()
    entropy: Callable[[int], bytes] = _SessionEntropy()
    event_ids: Callable[[], str] = valid_event_id
    clock: Callable[[], datetime] = valid_clock
    account = store.account
    if case == "invalid_account":
        account = accounts_module.LocalAccountRecord(
            "account-1", "user@example.com", None, active=False, verified=True, security_epoch=1
        )
    elif case == "create_failure":
        store.failures.add("create")
    elif case == "record_mismatch":
        store.mismatch_create = True
    elif case == "lookup_entropy":
        entropy = short_entropy
    elif case == "secret_entropy":
        entropy = invalid_secret_entropy
    elif case == "event_id":
        event_ids = invalid_event_id
    elif case == "clock":
        clock = naive_clock
    auth = accounts_module.NativeSessionAuth(
        accounts=store,
        binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        clock=clock,
        entropy=entropy,
        event_ids=event_ids,
    )
    session: dict[str, object] = {"anonymous": "value"}
    connection = _native_session_connection(session)

    outcome = await auth.establish(connection, cast("accounts_module.LocalAccountRecord[object]", account))

    assert isinstance(outcome, VerificationUnavailable)
    assert session == {"anonymous": "value"}
    assert "_litestar_security_response_headers" not in connection.scope


@pytest.mark.parametrize("mutation", ["separator", "binding", "secret", "version", "boolean_version", "timestamp"])
async def test_native_session_rejects_canonical_length_malformed_binding_and_payload(mutation: str) -> None:
    store = _NativeSessionStore()
    auth = accounts_module.NativeSessionAuth(
        accounts=store,
        binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        clock=lambda: _JWT_NOW,
        entropy=_SessionEntropy(),
    )
    session: dict[str, object] = {}
    establishing_connection = _native_session_connection(session)
    assert isinstance(
        await auth.establish(
            establishing_connection, cast("accounts_module.LocalAccountRecord[object]", store.account)
        ),
        accounts_module.SessionAuthentication,
    )
    token = _queued_binding_token(establishing_connection)
    if mutation == "separator":
        token = token.replace(".", "x", 1)
    elif mutation == "binding":
        token = f"xx_{token[3:]}"
    elif mutation == "secret":
        token = f"{token[:-1]}!"
    else:
        payload = cast("dict[str, object]", session["_litestar_security"])
        if mutation in {"version", "boolean_version"}:
            payload["version"] = True if mutation == "boolean_version" else 4
        else:
            payload["authenticated_at"] = "not-a-timestamp"
    connection = _native_session_connection(session, binding_token=token)

    outcome = auth.extract(connection)

    assert isinstance(outcome, InvalidCredentials)
    assert "_litestar_security" not in session


async def test_native_session_logout_and_revoke_report_store_failure_after_local_cleanup() -> None:
    store = _NativeSessionStore()
    auth = accounts_module.NativeSessionAuth(
        accounts=store,
        binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        clock=lambda: _JWT_NOW,
        entropy=_SessionEntropy(),
    )
    session: dict[str, object] = {}
    connection = _native_session_connection(session)
    current = await auth.establish(connection, cast("accounts_module.LocalAccountRecord[object]", store.account))
    assert isinstance(current, accounts_module.SessionAuthentication)
    store.failures.add("revoke")

    assert isinstance(await auth.revoke_session(connection, "account-1", current.session_id), VerificationUnavailable)
    assert "_litestar_security" in session
    assert not await auth.revoke_session(connection, " ", current.session_id)
    assert not await auth.revoke_session(connection, "account-1", "invalid")
    assert isinstance(await auth.logout(connection), VerificationUnavailable)
    assert "_litestar_security" not in session


async def test_native_session_current_revoke_clears_browser_state_and_list_filters_store_leaks() -> None:
    store = _NativeSessionStore()
    auth = accounts_module.NativeSessionAuth(
        accounts=store,
        binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        clock=lambda: _JWT_NOW,
        entropy=_SessionEntropy(),
    )
    session: dict[str, object] = {}
    connection = _native_session_connection(session)
    current = await auth.establish(connection, cast("accounts_module.LocalAccountRecord[object]", store.account))
    assert isinstance(current, accounts_module.SessionAuthentication)
    leaked = accounts_module.SessionRecord(
        session_id="bm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm4",
        binding_id="sb_aWlpaWlpaWlpaWlpaWlpaQ",
        binding_digest=b"b" * 32,
        account_id="account-2",
        security_epoch=1,
        created_at=_JWT_NOW,
        authenticated_at=_JWT_NOW,
        last_seen_at=_JWT_NOW,
        expires_at=_JWT_NOW + timedelta(hours=1),
    )
    store.records[leaked.session_id] = leaked

    summaries = await auth.list_sessions("account-1", current_session_id=current.session_id)
    assert tuple(summary.session_id for summary in summaries) == (current.session_id,)
    assert await auth.revoke_session(connection, "account-1", current.session_id)
    assert "_litestar_security" not in session

    replacement = await auth.establish(connection, cast("accounts_module.LocalAccountRecord[object]", store.account))
    assert isinstance(replacement, accounts_module.SessionAuthentication)
    store.records.clear()
    assert not await auth.revoke_session(connection, "account-1", replacement.session_id)
    assert "_litestar_security" not in session


def test_native_session_http_cleanup_without_mutable_native_session_only_expires_binding() -> None:
    auth = accounts_module.NativeSessionAuth(
        accounts=_NativeSessionStore(), binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32)
    )
    connection = _native_session_connection({}, binding_token="malformed")  # noqa: S106
    connection.scope["session"] = object()

    outcome = auth.extract(connection)

    assert isinstance(outcome, InvalidCredentials)
    assert _queued_binding_token(connection) == ""


def _local_access_account(
    *, active: bool = True, verified: bool = True, security_epoch: int = 3
) -> accounts_module.LocalAccountRecord[object]:
    return accounts_module.LocalAccountRecord(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Local Person",
        active=active,
        verified=verified,
        security_epoch=security_epoch,
        user={"safe": "application object"},
    )


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"pepper": b"short"}, "at least 32 bytes"),
        ({"pepper": bytearray(b"p" * 32)}, "at least 32 bytes"),
        ({"pepper": b"p" * 32, "cookie_name": ""}, "cookie-safe"),
        ({"pepper": b"p" * 32, "cookie_name": " binding"}, "cookie-safe"),
        ({"pepper": b"p" * 32, "cookie_name": "bind;ing"}, "cookie-safe"),
        ({"pepper": b"p" * 32, "secure": 1}, "Secure setting"),
        ({"pepper": b"p" * 32, "same_site": "bogus"}, "SameSite"),
        ({"pepper": b"p" * 32, "allow_insecure": 1}, "opt-in must be boolean"),
        ({"pepper": b"p" * 32, "allow_insecure": True}, "requires an insecure cookie"),
        ({"pepper": b"p" * 32, "secure": False}, "development opt-in"),
        ({"pepper": b"p" * 32, "secure": False, "allow_insecure": True}, "__Host-"),
        (
            {
                "pepper": b"p" * 32,
                "cookie_name": "binding",
                "secure": False,
                "allow_insecure": True,
                "same_site": "none",
            },
            "SameSite=None",
        ),
        ({"pepper": b"p" * 32, "path": "/nested"}, "__Host-"),
        ({"pepper": b"p" * 32, "cookie_name": "binding", "path": "relative"}, "absolute printable"),
        ({"pepper": b"p" * 32, "cookie_name": "binding", "path": "/bad path"}, "absolute printable"),
        ({"pepper": b"p" * 32, "cookie_name": "binding", "domain": " "}, "domain"),
        ({"pepper": b"p" * 32, "cookie_name": "binding", "domain": "bad domain"}, "domain"),
        ({"pepper": b"p" * 32, "max_age": 0}, "positive integer"),
        ({"pepper": b"p" * 32, "max_age": True}, "positive integer"),
        ({"pepper": b"p" * 32, "touch_interval": timedelta(0)}, "touch interval"),
        ({"pepper": b"p" * 32, "touch_interval": object()}, "touch interval"),
        ({"pepper": b"p" * 32, "max_age": 1, "touch_interval": timedelta(seconds=2)}, "touch interval"),
        ({"pepper": b"p" * 32, "preserve_session_keys": ["cart"]}, "immutable tuple"),
        ({"pepper": b"p" * 32, "preserve_session_keys": ("cart", "cart")}, "unique"),
        ({"pepper": b"p" * 32, "preserve_session_keys": ("_litestar_security",)}, "unique"),
        ({"pepper": b"p" * 32, "preserve_session_keys": (" ",)}, "unique"),
    ],
)
def test_session_binding_config_rejects_unsafe_boundaries(kwargs: dict[str, object], match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.SessionBindingConfig(**kwargs)  # type: ignore[arg-type]


def test_session_binding_config_supports_explicit_insecure_development() -> None:
    config = accounts_module.SessionBindingConfig(
        pepper=b"p" * 32,
        cookie_name="litestar-security-binding",
        secure=False,
        allow_insecure=True,
        preserve_session_keys=("cart",),
    )

    assert not config.secure
    assert config.allow_insecure
    assert config.preserve_session_keys == ("cart",)


@pytest.mark.parametrize(
    ("contract", "overrides", "match"),
    [
        ("authentication", {"authenticated_at": _ACCOUNT_NOW.replace(tzinfo=None)}, "timezone-aware"),
        ("authentication", {"session_id": object()}, "payload"),
        ("authentication", {"session_id": "invalid"}, "payload"),
        ("authentication", {"binding_id": "invalid"}, "payload"),
        ("authentication", {"account_id": " "}, "payload"),
        ("authentication", {"expires_at": _ACCOUNT_NOW}, "payload"),
        ("proof", {"binding_id": "invalid"}, "proof"),
        ("proof", {"digest": bytearray(b"d" * 32)}, "proof"),
        ("proof", {"digest": b"short"}, "proof"),
        ("record", {"created_at": _ACCOUNT_NOW.replace(tzinfo=None)}, "timezone-aware"),
        ("record", {"session_id": "invalid"}, "record is invalid"),
        ("record", {"binding_id": "invalid"}, "record is invalid"),
        ("record", {"binding_digest": bytearray(b"d" * 32)}, "record is invalid"),
        ("record", {"binding_digest": b"short"}, "record is invalid"),
        ("record", {"account_id": " "}, "record is invalid"),
        ("record", {"last_seen_at": _ACCOUNT_NOW + timedelta(hours=1)}, "record is invalid"),
        ("record", {"display_metadata": {" ": "browser"}}, "display metadata"),
        ("record", {"display_metadata": {str(index): "x" for index in range(33)}}, "display metadata"),
        ("record", {"display_metadata": {"device": "x" * 251}}, "display metadata"),
        ("record", {"display_metadata": {str(index): "x" * 200 for index in range(21)}}, "display metadata"),
        ("create", {"created_at": _ACCOUNT_NOW.replace(tzinfo=None)}, "timezone-aware"),
        ("create", {"session_id": "invalid"}, "creation command"),
        ("create", {"binding_id": "invalid"}, "creation command"),
        ("create", {"binding_digest": bytearray(b"d" * 32)}, "creation command"),
        ("create", {"binding_digest": b"short"}, "creation command"),
        ("create", {"account_id": " "}, "creation command"),
        ("create", {"expires_at": _ACCOUNT_NOW}, "creation command"),
        ("summary", {"created_at": _ACCOUNT_NOW.replace(tzinfo=None)}, "timezone-aware"),
        ("summary", {"session_id": "invalid"}, "summary is invalid"),
        ("summary", {"current": 1}, "summary is invalid"),
        ("summary", {"last_seen_at": _ACCOUNT_NOW + timedelta(hours=1)}, "summary is invalid"),
        ("summary", {"display_metadata": {"device": " "}}, "display metadata"),
    ],
)
def test_native_session_contracts_reject_malformed_state(
    contract: str, overrides: dict[str, object], match: str
) -> None:
    common: dict[str, object] = {
        "session_id": _SESSION_ID,
        "binding_id": _BINDING_ID,
        "binding_digest": b"d" * 32,
        "account_id": "account-1",
        "security_epoch": 1,
        "created_at": _ACCOUNT_NOW,
        "last_seen_at": _ACCOUNT_NOW,
        "authenticated_at": _ACCOUNT_NOW,
        "expires_at": _ACCOUNT_NOW + timedelta(hours=1),
        "current": True,
        "digest": b"d" * 32,
    }
    fields_by_contract = {
        "authentication": (
            "session_id",
            "binding_id",
            "account_id",
            "security_epoch",
            "authenticated_at",
            "expires_at",
        ),
        "proof": ("binding_id", "digest"),
        "record": (
            "session_id",
            "binding_id",
            "binding_digest",
            "account_id",
            "security_epoch",
            "created_at",
            "authenticated_at",
            "last_seen_at",
            "expires_at",
            "display_metadata",
        ),
        "create": (
            "session_id",
            "binding_id",
            "binding_digest",
            "account_id",
            "security_epoch",
            "created_at",
            "authenticated_at",
            "expires_at",
            "display_metadata",
        ),
        "summary": ("session_id", "current", "created_at", "last_seen_at", "expires_at", "display_metadata"),
    }
    factories = {
        "authentication": accounts_module.SessionAuthentication,
        "proof": accounts_module.SessionBindingProof,
        "record": accounts_module.SessionRecord,
        "create": accounts_module.CreateSessionCommand,
        "summary": accounts_module.SessionSummary,
    }
    common.update(overrides)
    values = {name: common[name] for name in fields_by_contract[contract] if name in common}

    with pytest.raises(ValueError, match=match):
        factories[contract](**values)  # type: ignore[operator]
