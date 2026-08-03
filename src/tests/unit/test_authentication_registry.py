"""Unit tests for authentication outcomes and registry compilation."""

import asyncio
import base64
import gzip
import hmac
import importlib
import json
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping
from collections.abc import Set as AbstractSet
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from math import inf, nan
from threading import Event as ThreadEvent
from threading import Lock as ThreadLock
from time import perf_counter, perf_counter_ns, sleep
from types import SimpleNamespace
from typing import Any, cast

import httpx
import jwt
import pyotp
import pytest
from anyio import CancelScope, CapacityLimiter, Event, create_task_group, fail_after, get_cancelled_exc_class, to_thread
from anyio.lowlevel import checkpoint
from argon2 import PasswordHasher as Argon2Engine
from argon2 import extract_parameters as extract_argon2_parameters
from argon2.exceptions import VerificationError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from litestar.connection import ASGIConnection
from litestar.exceptions import (
    ClientException,
    HTTPException,
    ImproperlyConfiguredException,
    NotAuthorizedException,
    ServiceUnavailableException,
    TooManyRequestsException,
)
from litestar.openapi.spec import SecurityScheme
from litestar.stores.memory import MemoryStore

import litestar_security.accounts as accounts_module
import litestar_security.accounts._access_tokens as access_tokens_module
import litestar_security.accounts._mfa_login as mfa_login_module
import litestar_security.accounts._passkeys as passkeys_module
import litestar_security.accounts._rate_limits as rate_limits_module
import litestar_security.accounts._sessions as sessions_module
import litestar_security.accounts.controllers._local as controllers_module
import litestar_security.accounts.controllers._mfa as mfa_controllers_module
import litestar_security.testing as testing_module
from litestar_security.accounts._mfa_login import MFARequired
from litestar_security.accounts._operations import LOGIN_MFA
from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationPolicy,
    AuthenticationRegistry,
    InvalidCredentials,
    MechanismRequirement,
    NoCredentials,
    PresentedCredential,
    VerificationUnavailable,
    all_of,
    any_of,
    at_least,
    mechanism,
    optional,
    public,
    required,
)
from litestar_security.config import ExternalCSRF, MFAConfig, PasskeyConfig, SecurityConfig
from litestar_security.context import (
    AuthenticationEvidence,
    AuthorizationSnapshot,
    CredentialRestrictions,
    NullSessionHandle,
    Principal,
    SecurityContext,
)
from litestar_security.guards import requires_assurance
from litestar_security.providers.jwks import (
    AsyncJWKSFetcher,
    CachedJWKSProvider,
    JWKSCacheEntry,
    JWKSCachePolicy,
    JWKSFetchRequest,
    JWKSFetchResponse,
    NoOpSecurityMetrics,
    SecurityMetrics,
    SyncJWKSFetcher,
    WorkerLimits,
    normalize_fetcher,
)
from litestar_security.providers.jwks import _documents as jwks_documents
from litestar_security.providers.jwt import (
    BearerSlotSelector,
    BearerTokenSlot,
    CompositeBearerConfig,
    JWTClaims,
    JWTValidationConfig,
    LocalKeyRing,
    PyJWTVerifier,
    SigningKey,
    SyncJWTVerifier,
    SyncTokenSigner,
    TokenSigner,
    UnverifiedJWTRoute,
    VerificationKey,
    VerificationKeySet,
    build_access_token_claims,
    extend_composite_bearer,
    normalize_signer,
    normalize_verifier,
    parse_unverified_jwt_route,
)
from litestar_security.providers.jwt import _capabilities as jwt_capabilities
from litestar_security.providers.jwt import _claims as jwt_claims
from litestar_security.providers.jwt import _keyring as jwt_keyring
from litestar_security.providers.jwt import _workers as jwt_workers
from litestar_security.providers.oidc import DiscoveryPolicy, OIDCDiscoveryClient, OIDCDiscoveryError, OIDCMetadata
from litestar_security.providers.oidc import _discovery as oidc_discovery
from litestar_security.providers.oidc import _urls as oidc_urls

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


def test_mfa_login_outcome_is_secret_safe_and_rate_limited() -> None:
    """The pre-authentication MFA outcome never exposes its challenge in repr."""
    outcome = MFARequired(
        challenge="reveal-once-challenge",
        account_id="account-1",
        expires_at=_JWT_NOW + timedelta(minutes=5),
        methods=frozenset({"totp", "recovery-code"}),
    )

    assert outcome.code == "mfa_required"
    assert outcome.account_id == "account-1"
    assert "reveal-once-challenge" not in repr(outcome)
    with pytest.raises(FrozenInstanceError):
        outcome.challenge = "replacement"  # type: ignore[misc]
    assert rate_limits_module.DEFAULT_RATE_LIMIT_POLICIES[LOGIN_MFA] == rate_limits_module.RateLimitPolicy(
        limit=10, window=timedelta(minutes=5)
    )


@pytest.mark.anyio
async def test_mfa_login_issue_derives_a_domain_separated_digest_and_consumes_once() -> None:
    """Login-MFA challenges are HMAC-bound opaque, reveal-once credentials."""
    now = _JWT_NOW
    secrets = accounts_module.LocalAuthSecrets.session(purpose_token_pepper=b"p" * 32)
    store = testing_module.InMemoryMFALoginChallengeStore()
    service = mfa_login_module.MFALoginService(
        store=store,
        mfa=_mfa_service(_MFAStore(), _MFAProtector(), now=now),
        pepper=secrets.mfa_login_pepper,
        clock=lambda: now,
        entropy=lambda size: b"x" * size,
    )

    issued = await service.issue(
        accounts_module.LocalAccount(
            account_id="account-1",
            normalized_identifier="person@example.com",
            display_name="Person",
            active=True,
            verified=True,
            security_epoch=0,
            user={"id": "account-1"},
        ),
        client_key="127.0.0.1",
    )

    assert isinstance(issued, MFARequired)
    assert issued.account_id == "account-1"
    assert issued.challenge == "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg"
    assert len(store.challenges) == 1
    expected_digest = hmac.digest(secrets.mfa_login_pepper, issued.challenge.encode("ascii"), "sha256")
    assert tuple(store.challenges) == (expected_digest,)
    record = await service.consume(issued.challenge, account_id="account-1", security_epoch=0, client_key="127.0.0.1")
    assert isinstance(record, accounts_module.MFALoginChallenge)
    assert (
        await service.consume(issued.challenge, account_id="account-1", security_epoch=0, client_key="127.0.0.1")
        == InvalidCredentials()
    )


@pytest.mark.anyio
async def test_mfa_login_rejects_malformed_challenges_and_burns_client_key_mismatches() -> None:
    """Malformed input does not reach the store, while a binding mismatch burns it."""
    now = _JWT_NOW
    store = testing_module.InMemoryMFALoginChallengeStore()
    service = mfa_login_module.MFALoginService(
        store=store,
        mfa=_mfa_service(_MFAStore(), _MFAProtector(), now=now),
        pepper=b"p" * 32,
        clock=lambda: now,
        entropy=lambda size: b"x" * size,
    )
    account = accounts_module.LocalAccount(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Person",
        active=True,
        verified=True,
        security_epoch=0,
    )
    assert (
        await service.consume("not-ascii-\u00e9", account_id="account-1", security_epoch=0, client_key="client")
        == InvalidCredentials()
    )
    issued = await service.issue(account, client_key="client")
    assert isinstance(issued, MFARequired)
    assert (
        await service.consume(issued.challenge, account_id="account-1", security_epoch=0, client_key="other-client")
        == InvalidCredentials()
    )
    assert (
        await service.consume(issued.challenge, account_id="account-1", security_epoch=0, client_key="client")
        == InvalidCredentials()
    )
    unicode_issued = await service.issue(account, client_key="client")
    assert isinstance(unicode_issued, MFARequired)
    assert (
        await service.consume(
            unicode_issued.challenge, account_id="account-1", security_epoch=0, client_key="bad-\ud800"
        )
        == InvalidCredentials()
    )
    assert (
        await service.consume(unicode_issued.challenge, account_id="account-1", security_epoch=0, client_key="client")
        == InvalidCredentials()
    )


class _MFALoginVerificationService(accounts_module.MFAService):
    """MFA port double recording exact MFA-login factor dispatch."""

    def __init__(self, *, fail: bool = False) -> None:
        super().__init__(store=_MFAStore(), secret_protector=_MFAProtector())
        self.calls: list[tuple[str, str, str | None, str]] = []
        self.fail = fail

    async def verify_totp(
        self, account_id: str, method_id: str, code: str
    ) -> AuthenticationEvidence | InvalidCredentials | VerificationUnavailable:
        self.calls.append(("totp", account_id, method_id, code))
        if self.fail:
            raise OSError
        return AuthenticationEvidence(
            mechanism="totp", slot="mfa", authenticated_at=_JWT_NOW, methods=frozenset({"totp"})
        )

    async def consume_recovery_code(
        self, account_id: str, code: str
    ) -> AuthenticationEvidence | InvalidCredentials | VerificationUnavailable:
        self.calls.append(("recovery-code", account_id, None, code))
        if self.fail:
            raise OSError
        return AuthenticationEvidence(
            mechanism="recovery-code", slot="mfa", authenticated_at=_JWT_NOW, methods=frozenset({"recovery-code"})
        )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("method", "method_id", "expected_call"),
    [
        ("totp", "method-1", ("totp", "account-1", "method-1", "123456")),
        ("recovery-code", None, ("recovery-code", "account-1", None, "123456")),
    ],
)
async def test_mfa_login_verifies_only_the_selected_factor(
    method: str, method_id: str | None, expected_call: tuple[str, str, str | None, str]
) -> None:
    """TOTP and recovery code dispatch retain their exact account and method binding."""
    mfa = _MFALoginVerificationService()
    service = mfa_login_module.MFALoginService(
        store=testing_module.InMemoryMFALoginChallengeStore(), mfa=mfa, pepper=b"p" * 32
    )
    record = accounts_module.MFALoginChallenge(
        challenge_digest=b"d" * 32,
        account_id="account-1",
        security_epoch=0,
        client_key=None,
        issued_at=_JWT_NOW,
        expires_at=_JWT_NOW + timedelta(minutes=5),
    )

    assert isinstance(
        await service.verify(record, method=method, method_id=method_id, code="123456"), AuthenticationEvidence
    )
    assert mfa.calls == [expected_call]
    assert await service.verify(record, method="unknown", method_id=None, code="123456") == InvalidCredentials()

    unavailable = mfa_login_module.MFALoginService(
        store=testing_module.InMemoryMFALoginChallengeStore(),
        mfa=_MFALoginVerificationService(fail=True),
        pepper=b"p" * 32,
    )
    assert (
        await unavailable.verify(record, method=method, method_id=method_id, code="123456") == VerificationUnavailable()
    )


@pytest.mark.anyio
async def test_local_auth_mfa_completion_gates_issuance_and_reuses_one_client_key() -> None:
    """MFA login burns before factor verification and delegates with merged evidence."""
    account = accounts_module.LocalAccount(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Person",
        active=True,
        verified=True,
        security_epoch=2,
        user={"id": "account-1"},
    )
    challenge = accounts_module.MFALoginChallenge(
        challenge_digest=b"d" * 32,
        account_id=account.account_id,
        security_epoch=account.security_epoch,
        client_key="client-complete",
        issued_at=_JWT_NOW,
        expires_at=_JWT_NOW + timedelta(minutes=5),
    )
    calls: list[str] = []

    class PasswordLogin:
        async def authenticate(self, *_args: object, **_kwargs: object) -> accounts_module.LocalAccount[dict[str, str]]:
            assert _kwargs["client_key"] in {"client-session", "client-token"}
            calls.append("password")
            return account

    class Accounts:
        async def get_by_id(self, account_id: str) -> accounts_module.LocalAccount[dict[str, str]]:
            assert account_id == account.account_id
            calls.append("account")
            return account

    class Guard:
        async def check(self, operation: str, *, client_key: str | None, identifier: str | None) -> None:
            assert operation == LOGIN_MFA
            assert client_key == "client-complete"
            assert identifier == account.account_id
            calls.append("limit")

    class MFA:
        async def issue(self, issued: object, *, client_key: str | None) -> MFARequired:
            assert issued is account
            assert client_key in {"client-session", "client-token"}
            calls.append("issue-challenge")
            return MFARequired("challenge", account.account_id, _JWT_NOW + timedelta(minutes=5), frozenset({"totp"}))

        async def consume(self, value: str, **kwargs: object) -> accounts_module.MFALoginChallenge:
            assert value == "challenge"
            assert kwargs == {
                "account_id": account.account_id,
                "security_epoch": account.security_epoch,
                "client_key": "client-complete",
            }
            calls.append("consume")
            return challenge

        async def verify(self, consumed: object, **kwargs: object) -> AuthenticationEvidence:
            assert consumed is challenge
            assert kwargs == {"method": "totp", "method_id": "method-1", "code": "123456"}
            calls.append("verify")
            return AuthenticationEvidence(
                mechanism="totp", slot="mfa", authenticated_at=_JWT_NOW, methods=frozenset({"totp"})
            )

    class Sessions:
        async def establish(
            self, _request: object, established: object, *, evidence: AuthenticationEvidence
        ) -> accounts_module.SessionAuthentication:
            assert established is account
            assert evidence.methods == frozenset({"password", "totp"})
            assert evidence.amr == ("pwd", "otp")
            calls.append("establish")
            return accounts_module.SessionAuthentication(
                session_id="c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M",
                binding_id="sb_aWlpaWlpaWlpaWlpaWlpaQ",
                account_id=account.account_id,
                security_epoch=account.security_epoch,
                authenticated_at=_JWT_NOW,
                expires_at=_JWT_NOW + timedelta(hours=1),
            )

    class Tokens:
        async def issue(self, *_args: object, **_kwargs: object) -> object:
            calls.append("token-issue")
            return object()

    # Each initial login and completion may derive its key once. Reusing a key
    # within either request is required because extractors can be stateful.
    client_keys = iter(("client-session", "client-token", "client-complete", "wrong-if-read-twice"))
    service = accounts_module.LocalAuthService(
        accounts=cast("Any", Accounts()),
        password_login=cast("Any", PasswordLogin()),
        password_reauthentication=cast("Any", object()),
        password_change=cast("Any", object()),
        verification=cast("Any", object()),
        recovery=cast("Any", object()),
        session_auth=cast("Any", Sessions()),
        refresh_tokens=cast("Any", Tokens()),
        rate_limits=cast("Any", Guard()),
        mfa_login=cast("Any", MFA()),
        client_key=lambda _request: next(client_keys),
    )
    request = cast("Any", object())
    credentials = accounts_module.LocalCredentials(identifier="person@example.com", password="password")  # noqa: S106

    assert isinstance(await service.session_login(request, credentials), MFARequired)
    assert calls == ["password", "issue-challenge"]
    assert isinstance(await service.token_login(request, credentials), MFARequired)
    assert calls == ["password", "issue-challenge", "password", "issue-challenge"]
    assert isinstance(
        await service.complete_mfa_login(
            request,
            "challenge",
            account_id=account.account_id,
            method="totp",
            method_id="method-1",
            code="123456",
            transport="session",
        ),
        accounts_module.LocalAccountResponse,
    )
    assert calls == [
        "password",
        "issue-challenge",
        "password",
        "issue-challenge",
        "limit",
        "account",
        "consume",
        "verify",
        "account",
        "establish",
    ]
    assert isinstance(
        await replace(service, rate_limits=None).complete_mfa_login(
            request, "challenge", account_id=account.account_id, method="totp", code="123456"
        ),
        VerificationUnavailable,
    )
    assert calls[-1] == "establish"


@pytest.mark.anyio
async def test_local_auth_mfa_completion_rejects_an_epoch_advance_before_issuance() -> None:
    """A reset racing completion invalidates the final authoritative account read."""
    account = accounts_module.LocalAccount(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Person",
        active=True,
        verified=True,
        security_epoch=2,
    )
    challenge = accounts_module.MFALoginChallenge(
        challenge_digest=b"d" * 32,
        account_id=account.account_id,
        security_epoch=account.security_epoch,
        client_key=None,
        issued_at=_JWT_NOW,
        expires_at=_JWT_NOW + timedelta(minutes=5),
    )

    class Accounts:
        reads = 0

        async def get_by_id(self, _account_id: str) -> accounts_module.LocalAccount[object]:
            self.reads += 1
            return account if self.reads == 1 else replace(account, security_epoch=account.security_epoch + 1)

    class Guard:
        async def check(self, *_args: object, **_kwargs: object) -> None:
            return None

    class MFA:
        async def consume(self, *_args: object, **_kwargs: object) -> accounts_module.MFALoginChallenge:
            return challenge

        async def verify(self, *_args: object, **_kwargs: object) -> AuthenticationEvidence:
            return AuthenticationEvidence(mechanism="totp", slot="mfa", authenticated_at=_JWT_NOW)

    class Sessions:
        issued = False

        async def establish(self, *_args: object, **_kwargs: object) -> object:
            self.issued = True
            return object()

    sessions = Sessions()
    service = accounts_module.LocalAuthService(
        accounts=cast("Any", Accounts()),
        password_login=cast("Any", object()),
        password_reauthentication=cast("Any", object()),
        password_change=cast("Any", object()),
        verification=cast("Any", object()),
        recovery=cast("Any", object()),
        session_auth=cast("Any", sessions),
        rate_limits=cast("Any", Guard()),
        mfa_login=cast("Any", MFA()),
    )

    assert isinstance(
        await service.complete_mfa_login(
            cast("Any", object()),
            "challenge",
            account_id=account.account_id,
            method="totp",
            code="123456",
            transport="session",
        ),
        InvalidCredentials,
    )
    assert not sessions.issued


async def _assert_http_exception(
    awaitable: Awaitable[object], exception_type: type[HTTPException], *, status_code: int, detail: str
) -> HTTPException:
    with pytest.raises(exception_type) as exc_info:
        await awaitable
    assert exc_info.value.status_code == status_code
    assert exc_info.value.detail == detail
    return exc_info.value


def test_jwks_worker_and_metrics_contracts_are_safe_by_default() -> None:
    limits = WorkerLimits()
    metrics = NoOpSecurityMetrics()

    assert limits.network_tokens == 8
    assert limits.crypto_tokens == 32
    assert limits.timeout == 10.0
    assert limits.network_limiter.total_tokens == 8
    assert limits.crypto_limiter.total_tokens == 32
    assert limits.network_limiter is not limits.crypto_limiter
    assert isinstance(metrics, SecurityMetrics)
    metrics.increment("security.jwks.fresh_hit")
    metrics.observe("security.jwks.fetch_duration", 0.1)


@pytest.mark.parametrize(
    "kwargs", [{"network_tokens": 0}, {"crypto_tokens": True}, {"timeout": 0}, {"timeout": inf}, {"timeout": nan}]
)
def test_jwks_worker_limits_reject_invalid_capacity(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        WorkerLimits(**kwargs)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_jwks_fetcher_normalization_selects_async_or_bounded_sync_once() -> None:
    response = JWKSFetchResponse(status_code=200, body=b'{"keys":[]}')
    metrics: list[str] = []

    class Metrics:
        def increment(self, name: str, *, attributes: Mapping[str, str] = {}) -> None:
            del attributes
            metrics.append(name)

        def observe(self, name: str, value: float, *, attributes: Mapping[str, str] = {}) -> None:
            del name, value, attributes

    class AsyncFetcher:
        async def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return response

    class SyncFetcher:
        def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return response

    request = JWKSFetchRequest(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI)
    async_fetcher = AsyncFetcher()
    normalized_async = normalize_fetcher(async_fetcher, limiter=CapacityLimiter(1))
    normalized_sync = normalize_fetcher(SyncFetcher(), limiter=CapacityLimiter(2), metrics=Metrics())

    assert normalized_async is async_fetcher
    assert isinstance(normalized_sync, AsyncJWKSFetcher)
    assert isinstance(SyncFetcher(), SyncJWKSFetcher)
    assert await normalized_async.fetch(request) is response
    assert await normalized_sync.fetch(request) is response
    assert "security.worker.saturation" not in metrics


def test_jwks_fetcher_normalization_rejects_invalid_configuration() -> None:
    cases = (
        (object(), 1.0, None, "must define fetch"),
        (_RecordingJWKSFetcher(), 0.0, None, "timeout must be finite and positive"),
        (_RecordingJWKSFetcher(), 1.0, object(), "must implement SecurityMetrics"),
        (_RecordingJWKSFetcher(), 1.0, None, "limiter must have finite bounded capacity"),
    )
    for index, (fetcher, timeout, metrics, match) in enumerate(cases):
        with pytest.raises(ImproperlyConfiguredException, match=match):
            normalize_fetcher(  # type: ignore[arg-type]
                fetcher,
                limiter=CapacityLimiter(inf if index == 3 else 1),
                timeout=timeout,
                metrics=metrics,  # type: ignore[arg-type]
            )


@pytest.mark.anyio
async def test_jwks_sync_fetcher_is_bounded_without_blocking_the_event_loop() -> None:
    started = ThreadEvent()
    release = ThreadEvent()
    calls: list[JWKSFetchResponse] = []

    class SyncFetcher:
        def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            started.set()
            release.wait(timeout=1)
            return JWKSFetchResponse(status_code=200, body=b'{"keys":[]}')

    normalized = normalize_fetcher(SyncFetcher(), limiter=CapacityLimiter(1))
    request = JWKSFetchRequest(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI)

    async def fetch() -> None:
        calls.append(await normalized.fetch(request))

    async with create_task_group() as task_group:
        task_group.start_soon(fetch)
        with fail_after(1):
            while not started.is_set():
                await checkpoint()
        task_group.start_soon(fetch)
        await checkpoint()
        assert calls == []
        release.set()

    assert len(calls) == 2


@pytest.mark.anyio
async def test_sync_crypto_normalization_is_bounded_and_keeps_the_event_loop_live() -> None:  # noqa: C901, PLR0915
    release = ThreadEvent()
    saturated = ThreadEvent()
    lock = ThreadLock()
    active = 0
    maximum_active = 0
    outcomes: list[InvalidCredentials] = []
    records: list[tuple[str, float | None]] = []
    stop_ticker = Event()
    ticker_count = 0

    class Metrics:
        def increment(self, name: str, *, attributes: Mapping[str, str] = {}) -> None:
            del attributes
            records.append((name, None))

        def observe(self, name: str, value: float, *, attributes: Mapping[str, str] = {}) -> None:
            del attributes
            records.append((name, value))

    class SyncVerifier:
        config = _jwt_config("EdDSA")

        def verify(self, _token: str, *, now: datetime) -> InvalidCredentials:
            nonlocal active, maximum_active
            assert now is _JWT_NOW
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
                if active == 2:
                    saturated.set()
            release.wait(timeout=1)
            with lock:
                active -= 1
            return InvalidCredentials()

    class AsyncVerifier:
        config = _jwt_config("EdDSA")

        async def verify(self, _token: str, *, now: datetime) -> InvalidCredentials:
            assert now is _JWT_NOW
            return InvalidCredentials()

    class AsyncSigner:
        async def sign(self, _claims: Mapping[str, object], *, now: datetime) -> str:
            assert now is _JWT_NOW
            return "async"

    class SyncSigner:
        def sign(self, _claims: Mapping[str, object], *, now: datetime) -> str:
            assert now is _JWT_NOW
            return "sync"

    workers = WorkerLimits(crypto_tokens=2)
    metrics = Metrics()
    verifier = normalize_verifier(SyncVerifier(), worker_limits=workers, metrics=metrics)
    async_verifier = AsyncVerifier()
    async_signer = AsyncSigner()
    normalized_async_signer = normalize_signer(async_signer, worker_limits=workers, metrics=metrics)
    normalized_sync_signer = normalize_signer(SyncSigner(), worker_limits=workers, metrics=metrics)

    async def verify() -> None:
        outcomes.append(cast("InvalidCredentials", await verifier.verify("token", now=_JWT_NOW)))

    async def ticker() -> None:
        nonlocal ticker_count
        while not stop_ticker.is_set():
            ticker_count += 1
            await checkpoint()

    async with create_task_group() as task_group:
        task_group.start_soon(ticker)
        for _ in range(2):
            task_group.start_soon(verify)
        with fail_after(1):
            while not saturated.is_set():
                await checkpoint()
        for _ in range(98):
            task_group.start_soon(verify)
        with fail_after(1):
            while not any(name == "security.worker.saturation" for name, _ in records):
                await checkpoint()
        observed_ticks = ticker_count
        release.set()
        with fail_after(5):
            while len(outcomes) != 100:
                await checkpoint()
        stop_ticker.set()

    assert observed_ticks > 0
    assert maximum_active == 2
    assert len(outcomes) == 100
    assert isinstance(SyncVerifier(), SyncJWTVerifier)
    assert isinstance(SyncSigner(), SyncTokenSigner)
    assert normalize_verifier(async_verifier, worker_limits=workers, metrics=metrics) is async_verifier
    assert normalized_async_signer is async_signer
    assert await normalized_sync_signer.sign({}, now=_JWT_NOW) == "sync"
    names = [name for name, _ in records]
    assert {
        "security.worker.saturation",
        "security.worker.wait",
        "security.worker.duration",
        "security.jwt.verify_duration",
        "security.jwt.sign_duration",
    } <= set(names)
    assert all(value is None or value >= 0 for _, value in records)


@pytest.mark.anyio
async def test_sync_crypto_timeout_is_sanitized() -> None:
    release = ThreadEvent()

    class SyncVerifier:
        config = _jwt_config("EdDSA")

        def verify(self, _token: str, *, now: datetime) -> InvalidCredentials:
            del now
            release.wait(timeout=1)
            return InvalidCredentials()

    class SyncSigner:
        def sign(self, _claims: Mapping[str, object], *, now: datetime) -> str:
            del now
            release.wait(timeout=1)
            return "token"

    workers = WorkerLimits(crypto_tokens=1, timeout=0.01)
    verifier = normalize_verifier(SyncVerifier(), worker_limits=workers)
    signer = normalize_signer(SyncSigner(), worker_limits=workers)

    outcome = await verifier.verify("token", now=_JWT_NOW)
    with pytest.raises(RuntimeError, match="Token signing unavailable"):
        await signer.sign({}, now=_JWT_NOW)
    release.set()

    assert isinstance(outcome, VerificationUnavailable)


def test_crypto_worker_configuration_rejects_invalid_values(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key = SigningKey(key_id="active", algorithm="EdDSA", private_key=jwt_key_material["EdDSA"][0])
    verification_key = VerificationKey(key_id="active", algorithm="EdDSA", key=jwt_key_material["EdDSA"][1])

    class SyncSigner:
        def sign(self, _claims: Mapping[str, object], *, now: datetime) -> str:
            del now
            return "token"

    class SyncVerifier:
        config = _jwt_config("EdDSA")

        def verify(self, _token: str, *, now: datetime) -> InvalidCredentials:
            del now
            return InvalidCredentials()

    cases = (
        (lambda: normalize_signer(object()), "must define sign"),
        (lambda: normalize_signer(SyncSigner(), worker_limits=object()), "worker limits must be WorkerLimits"),
        (lambda: normalize_signer(SyncSigner(), metrics=object()), "metrics must implement SecurityMetrics"),
        (lambda: normalize_verifier(object()), "must define verify"),
        (lambda: normalize_verifier(SyncVerifier(), worker_limits=object()), "worker limits must be WorkerLimits"),
        (
            lambda: VerificationKeySet(issuer=_JWT_ISSUER, keys=(verification_key,)).build_verifier(
                _jwt_config("EdDSA"),
                worker_limits=object(),  # type: ignore[arg-type]
            ),
            "worker limits must be WorkerLimits",
        ),
        (
            lambda: LocalKeyRing(
                issuer=_JWT_ISSUER,
                active_signing_key=signing_key,
                worker_limits=object(),  # type: ignore[arg-type]
            ),
            "worker limits must be WorkerLimits",
        ),
        (
            lambda: PyJWTVerifier(config=_jwt_config("EdDSA"), key=verification_key, limiter=CapacityLimiter(inf)),
            "limiter must have finite bounded capacity",
        ),
        (
            lambda: PyJWTVerifier(config=_jwt_config("EdDSA"), key=verification_key, worker_timeout=inf),
            "timeout must be finite and positive",
        ),
        (
            lambda: jwt_keyring._LocalJWTSigner(  # noqa: SLF001
                issuer=_JWT_ISSUER, signing_key=signing_key, worker_timeout=inf
            ),
            "timeout must be finite and positive",
        ),
    )
    for factory, match in cases:
        with pytest.raises(ImproperlyConfiguredException, match=match):
            factory()


@pytest.mark.anyio
async def test_jwks_sync_fetcher_timeout_maps_to_unavailable(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    release = ThreadEvent()

    class SyncFetcher:
        def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            release.wait(timeout=1)
            return _jwks_response(_verification_jwk(jwt_key_material))

    normalized = normalize_fetcher(SyncFetcher(), limiter=CapacityLimiter(1), timeout=0.01)
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=normalized)

    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    release.set()

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.anyio
async def test_jwks_metrics_are_vendor_neutral_and_redacted(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    records: list[tuple[str, float | None, dict[str, str]]] = []

    class Metrics:
        def increment(self, name: str, *, attributes: Mapping[str, str] = {}) -> None:
            records.append((name, None, dict(attributes)))

        def observe(self, name: str, value: float, *, attributes: Mapping[str, str] = {}) -> None:
            records.append((name, value, dict(attributes)))

    known = _verification_jwk(jwt_key_material, key_id="known")
    fetcher = _RecordingJWKSFetcher(_jwks_response(known, cache_control="max-age=60"), OSError("operational-detail"))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher, metrics=Metrics())

    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW)
    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "attacker-kid", "EdDSA", now=_JWT_NOW)
    rendered = repr(records)

    assert {"security.jwks.refresh_success", "security.jwks.unknown_key", "security.jwks.refresh_failure"} <= {
        name for name, _, _ in records
    }
    assert all(value is None or value >= 0 for _, value, _ in records)
    assert all(secret not in rendered for secret in (_JWT_ISSUER, _JWKS_URI, "attacker-kid", "operational-detail"))


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"metrics": object()}, "must implement SecurityMetrics"),
        ({"fetcher_owned": 1}, "ownership must be boolean"),
        ({"worker_limits": object()}, "worker limits must be WorkerLimits"),
    ],
)
def test_jwks_provider_rejects_invalid_runtime_configuration(kwargs: dict[str, object], match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        CachedJWKSProvider(
            entries=(_jwks_entry(),),
            fetcher=_RecordingJWKSFetcher(),
            **kwargs,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(("fetcher_owned", "expected_closes"), [(False, 0), (True, 1)])
@pytest.mark.anyio
async def test_jwks_provider_closes_only_owned_fetchers(
    *, fetcher_owned: bool, expected_closes: int, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    class Fetcher:
        def __init__(self) -> None:
            self.closes = 0

        async def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return _jwks_response(_verification_jwk(jwt_key_material))

        async def aclose(self) -> None:
            self.closes += 1

    fetcher = Fetcher()
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher, fetcher_owned=fetcher_owned)

    await provider.aclose()
    await provider.aclose()

    assert fetcher.closes == expected_closes


@pytest.mark.anyio
async def test_jwks_provider_closes_owned_sync_fetcher_in_worker() -> None:
    class SyncFetcher:
        def __init__(self) -> None:
            self.closes = 0

        def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return JWKSFetchResponse(status_code=200, body=b'{"keys":[]}')

        def close(self) -> None:
            self.closes += 1

    source = SyncFetcher()
    normalized = normalize_fetcher(source, limiter=CapacityLimiter(1))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=normalized, fetcher_owned=True)

    await provider.aclose()

    assert source.closes == 1


@pytest.mark.anyio
async def test_jwks_provider_accepts_owned_sync_fetcher_without_close() -> None:
    class SyncFetcher:
        def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return JWKSFetchResponse(status_code=200, body=b'{"keys":[]}')

    provider = CachedJWKSProvider(
        entries=(_jwks_entry(),),
        fetcher=normalize_fetcher(SyncFetcher(), limiter=CapacityLimiter(1)),
        fetcher_owned=True,
    )

    await provider.aclose()


@pytest.mark.parametrize("close_mode", ["absent", "sync"])
@pytest.mark.anyio
async def test_jwks_provider_accepts_owned_fetchers_without_async_close(close_mode: str) -> None:
    class Fetcher:
        async def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return JWKSFetchResponse(status_code=200, body=b'{"keys":[]}')

    class SyncCloseFetcher(Fetcher):
        def aclose(self) -> None:
            return None

    fetcher = Fetcher() if close_mode == "absent" else SyncCloseFetcher()
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher, fetcher_owned=True)

    await provider.aclose()


def _jwt_claims(**overrides: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": _JWT_ISSUER,
        "sub": "user-1",
        "aud": _JWT_AUDIENCE,
        "exp": int((_JWT_NOW + timedelta(minutes=10)).timestamp()),
        "iat": int(_JWT_NOW.timestamp()),
        "nbf": int((_JWT_NOW - timedelta(seconds=1)).timestamp()),
        "client_id": "client-1",
        "jti": "token-1",
        "scope": "reports:read profile",
        "metadata": {"groups": ["finance", "operations"]},
    }
    claims.update(overrides)
    return claims


def _jwt_config(
    algorithm: str,
    *,
    access_token_profile: bool = True,
    subject_required: bool = True,
    required_claims: frozenset[str] = frozenset({"iss", "sub", "aud", "exp", "iat"}),
    maximum_lifetime: timedelta | None = timedelta(hours=1),
) -> JWTValidationConfig:
    return JWTValidationConfig(
        issuer=_JWT_ISSUER,
        audiences=frozenset({_JWT_AUDIENCE}),
        algorithms=frozenset({algorithm}),
        required_claims=required_claims,
        access_token_profile=access_token_profile,
        subject_required=subject_required,
        maximum_lifetime=maximum_lifetime,
    )


def _encode_jwt(
    signing_key: bytes,
    algorithm: str,
    *,
    claims: Mapping[str, object] | None = None,
    headers: Mapping[str, object] | None = None,
    include_key_id: bool = True,
) -> str:
    protected: dict[str, object] = {"typ": "at+jwt"}
    if include_key_id:
        protected["kid"] = "key-1"
    if headers:
        protected.update(headers)
    encoded = jwt.encode(dict(claims or _jwt_claims()), signing_key, algorithm=algorithm, headers=protected)
    return encoded.decode() if isinstance(encoded, bytes) else encoded


def _jwt_segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _compact_jwt(header: bytes, payload: bytes, signature: bytes = b"signature") -> str:
    return ".".join((_jwt_segment(header), _jwt_segment(payload), _jwt_segment(signature)))


class _Slot:
    def __init__(self, name: str) -> None:
        self.name = name

    def extract(self, _connection: object) -> NoCredentials:
        return NoCredentials()


class _Authenticator:
    def __init__(self, name: str, slot: str, *, participates_by_default: bool = True) -> None:
        self.name = name
        self.slot = slot
        self.participates_by_default = participates_by_default

    async def authenticate(self, _credential: str, _connection: object) -> NoCredentials:
        return NoCredentials()


class _Resolver:
    async def resolve(self, claims: str) -> Principal[object]:
        return Principal(id=claims)


class _RecordingJWTVerifier:
    def __init__(self, outcome: object, config: JWTValidationConfig) -> None:
        self.outcome = outcome
        self.config = config
        self.calls: list[tuple[str, datetime]] = []

    async def verify(self, token: str, *, now: datetime) -> object:
        self.calls.append((token, now))
        return self.outcome


def _recording_jwt_verifier(
    outcome: object, *, issuer: str = _JWT_ISSUER, audiences: frozenset[str] = frozenset({_JWT_AUDIENCE})
) -> _RecordingJWTVerifier:
    return _RecordingJWTVerifier(
        outcome, JWTValidationConfig(issuer=issuer, audiences=audiences, algorithms=frozenset({"HS256"}))
    )


class _FakeOIDCResolver:
    def __init__(self, answers: Mapping[str, tuple[str, ...]]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, int]] = []

    async def __call__(self, hostname: str, port: int) -> tuple[str, ...]:
        self.calls.append((hostname, port))
        if hostname not in self.answers:
            msg = f"Unexpected DNS lookup for {hostname}:{port}"
            raise AssertionError(msg)
        return self.answers[hostname]


class _RecordingMockTransport(httpx.MockTransport):
    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        super().__init__(handler)
        self.requests: list[httpx.Request] = []
        self.was_closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return await super().handle_async_request(request)

    async def aclose(self) -> None:
        self.was_closed = True
        await super().aclose()


class _ChunkedOIDCStream(httpx.AsyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks
        self.was_iterated = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.was_iterated = True
        for chunk in self.chunks:
            yield chunk


def _oidc_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "issuer": _OIDC_ISSUER,
        "jwks_uri": f"{_OIDC_ISSUER}/jwks",
        "authorization_endpoint": f"{_OIDC_ISSUER}/authorize",
        "token_endpoint": f"{_OIDC_ISSUER}/token",
        "end_session_endpoint": f"{_OIDC_ISSUER}/logout",
        "id_token_signing_alg_values_supported": ["EdDSA", "RS256"],
    }
    document.update(overrides)
    return document


def _oidc_response(
    document: Mapping[str, object] | None = None,
    *,
    status_code: int = 200,
    content: bytes | None = None,
    content_type: str | None = "application/json",
) -> httpx.Response:
    headers = {} if content_type is None else {"content-type": content_type}
    body = (
        json.dumps(dict(document if document is not None else _oidc_document()), separators=(",", ":")).encode()
        if content is None
        else content
    )
    return httpx.Response(status_code, content=body, headers=headers)


def _oidc_client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    policy: DiscoveryPolicy | None = None,
    algorithms: frozenset[str] = frozenset({"EdDSA", "ES256"}),
    answers: Mapping[str, tuple[str, ...]] | None = None,
) -> tuple[OIDCDiscoveryClient, _RecordingMockTransport, _FakeOIDCResolver]:
    transport = _RecordingMockTransport(handler)
    resolver = _FakeOIDCResolver(
        {"issuer.example": (_OIDC_PUBLIC_IP,), "keys.example": (_OIDC_PUBLIC_IP,)} if answers is None else answers
    )
    client = OIDCDiscoveryClient(
        policy=policy or DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER})),
        algorithms=algorithms,
        transport=transport,
        resolver=resolver,
    )
    return client, transport, resolver


async def _discover_and_close(client: OIDCDiscoveryClient, issuer: str = _OIDC_ISSUER) -> OIDCMetadata:
    try:
        return await client.discover(issuer)
    finally:
        await client.aclose()


class _RecordingJWKSFetcher:
    def __init__(
        self, *responses: JWKSFetchResponse | Exception | Callable[[JWKSFetchRequest], JWKSFetchResponse]
    ) -> None:
        self.responses = list(responses)
        self.requests: list[JWKSFetchRequest] = []

    async def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResponse:
        self.requests.append(request)
        if not self.responses:
            message = "Unexpected JWKS fetch"
            raise AssertionError(message)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response(request) if callable(response) else response


class _BlockingJWKSFetcher:
    def __init__(
        self,
        *responses: JWKSFetchResponse | Exception | Callable[[JWKSFetchRequest], JWKSFetchResponse],
        immediate_calls: int = 0,
        maximum_calls: int = 1,
        issuers: tuple[str, ...] = (),
    ) -> None:
        self.responses = responses
        self.immediate_calls = immediate_calls
        self.maximum_calls = maximum_calls
        self.requests: list[JWKSFetchRequest] = []
        self.started = Event()
        self.started_by_issuer = {issuer: Event() for issuer in issuers}
        self.release = Event()
        self.finished = Event()
        self.active = 0
        self.cancelled = 0

    async def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResponse:
        self.requests.append(request)
        call_number = len(self.requests)
        if call_number > self.maximum_calls:
            message = "Concurrent JWKS fetch escaped single-flight coordination"
            raise AssertionError(message)
        if call_number > self.immediate_calls:
            self.active += 1
            self.started.set()
            if issuer_started := self.started_by_issuer.get(request.issuer):
                issuer_started.set()
            try:
                await self.release.wait()
            except get_cancelled_exc_class():
                self.cancelled += 1
                raise
            finally:
                self.active -= 1
                if self.active == 0:
                    self.finished.set()
        response = self.responses[call_number - 1]
        if isinstance(response, Exception):
            raise response
        return response(request) if callable(response) else response


def _verification_jwk(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], algorithm: str = "EdDSA", key_id: str = "key-1"
) -> dict[str, object]:
    key = VerificationKey(key_id=key_id, algorithm=algorithm, key=jwt_key_material[algorithm][1])  # type: ignore[arg-type]
    return dict(cast("Mapping[str, object]", key.public_jwk))


def _raw_public_jwk(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], source_algorithm: str, algorithm: str, key_id: str
) -> dict[str, object]:
    public_key = serialization.load_pem_public_key(jwt_key_material[source_algorithm][1])
    serializer_algorithm = {"ES384": "ES256", "RS1024": "RS256"}.get(source_algorithm, source_algorithm)
    jwk = cast("dict[str, object]", jwt.get_algorithm_by_name(serializer_algorithm).to_jwk(public_key, as_dict=True))
    jwk.update({"alg": algorithm, "kid": key_id, "key_ops": ["verify"], "use": "sig"})
    return jwk


def _jwks_body(*keys: Mapping[str, object]) -> bytes:
    return json.dumps({"keys": [dict(key) for key in keys]}, separators=(",", ":")).encode()


def _jwks_response(
    *keys: Mapping[str, object],
    status_code: int = 200,
    body: bytes | None = None,
    cache_control: str | None = None,
    etag: str | None = None,
) -> JWKSFetchResponse:
    headers: dict[str, str] = {"content-type": "application/json"}
    if cache_control is not None:
        headers["cache-control"] = cache_control
    if etag is not None:
        headers["etag"] = etag
    return JWKSFetchResponse(status_code=status_code, body=_jwks_body(*keys) if body is None else body, headers=headers)


def _jwks_entry(
    issuer: str = _JWT_ISSUER, jwks_uri: str = _JWKS_URI, algorithms: frozenset[str] = frozenset({"EdDSA"})
) -> JWKSCacheEntry:
    return JWKSCacheEntry(issuer=issuer, jwks_uri=jwks_uri, algorithms=algorithms)


def _jwks_performance_baseline() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "benchmark": "jwks-runtime-foundation",
        "interpretation": "relative regression gates; not absolute cross-machine claims",
        "budgets": {
            "fresh_hit_p95_ratio": {
                "comparison": "fresh_selection_and_verify/direct_lookup_and_verify",
                "maximum": 1.2,
            },
            "sync_ticker_delay_p95_ms": {"comparison": "event_loop_tick_overshoot", "maximum": 10.0},
        },
        "observed": {"fresh_hit_p95_ratio": 1.2, "sync_ticker_delay_p95_ms": 10.0},
    }


_PERFORMANCE_TRIALS = 3


def _p95(values: list[float]) -> float:
    return sorted(values)[max(0, (len(values) * 95 + 99) // 100 - 1)]


@pytest.mark.performance
def test_jwks_performance_baseline_has_relative_budget_schema() -> None:
    baseline = _jwks_performance_baseline()

    assert baseline["schema_version"] == 1
    assert baseline["benchmark"] == "jwks-runtime-foundation"
    assert baseline["interpretation"] == "relative regression gates; not absolute cross-machine claims"
    assert baseline["budgets"] == {
        "fresh_hit_p95_ratio": {"comparison": "fresh_selection_and_verify/direct_lookup_and_verify", "maximum": 1.2},
        "sync_ticker_delay_p95_ms": {"comparison": "event_loop_tick_overshoot", "maximum": 10.0},
    }
    assert set(baseline["observed"]) == {"fresh_hit_p95_ratio", "sync_ticker_delay_p95_ms"}
    assert all(baseline["observed"][name] <= budget["maximum"] for name, budget in baseline["budgets"].items())


@pytest.mark.performance
@pytest.mark.anyio
async def test_jwks_performance_fresh_issuer_path_is_lock_and_fetch_free(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    second_issuer = "https://fresh.example"
    second_uri = f"{second_issuer}/jwks"
    first = _jwks_response(_verification_jwk(jwt_key_material, key_id="first"), cache_control="max-age=30")
    second = _jwks_response(_verification_jwk(jwt_key_material, key_id="second"), cache_control="max-age=300")
    fetcher = _BlockingJWKSFetcher(first, second, first, immediate_calls=2, maximum_calls=3)

    class FailingLock:
        async def __aenter__(self) -> None:
            message = "fresh selection acquired the entry lock"
            raise AssertionError(message)

        async def __aexit__(self, *_args: object) -> None:
            return None

    provider = CachedJWKSProvider(entries=(_jwks_entry(), _jwks_entry(second_issuer, second_uri)), fetcher=fetcher)
    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "first", "EdDSA", now=_JWT_NOW)
    await provider.select_key(second_issuer, second_uri, "second", "EdDSA", now=_JWT_NOW)
    state = cast("Any", provider)._entries[(second_issuer, second_uri)]  # noqa: SLF001
    state.lock = FailingLock()
    fresh_result: list[object] = []

    async def refresh_expired() -> None:
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "first", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))

    async with create_task_group() as task_group:
        task_group.start_soon(refresh_expired)
        await fetcher.started.wait()
        with fail_after(0.1):
            fresh_result.append(
                await provider.select_key(
                    second_issuer, second_uri, "second", "EdDSA", now=_JWT_NOW + timedelta(seconds=30)
                )
            )
        fetcher.release.set()

    assert isinstance(fresh_result[0], VerificationKey)
    assert len(fetcher.requests) == 3


@pytest.mark.performance
@pytest.mark.anyio
async def test_jwks_performance_single_flight_and_cache_bounds(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    keys = tuple(_verification_jwk(jwt_key_material, key_id=f"known-{index}") for index in range(4))
    response = _jwks_response(*keys, cache_control="max-age=60")
    blocking_fetcher = _BlockingJWKSFetcher(response)
    cold_provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=blocking_fetcher)
    cold_results: list[object | None] = [None] * 100

    async def select_cold(index: int) -> None:
        cold_results[index] = await cold_provider.select_key(_JWT_ISSUER, _JWKS_URI, "known-0", "EdDSA", now=_JWT_NOW)

    async with create_task_group() as task_group:
        for index in range(len(cold_results)):
            task_group.start_soon(select_cold, index)
        await blocking_fetcher.started.wait()
        await checkpoint()
        blocking_fetcher.release.set()

    policy = JWKSCachePolicy(maximum_keys=4, maximum_unknown_keys=64)
    not_modified = JWKSFetchResponse(status_code=304, headers={"cache-control": "max-age=60"})
    bounded_fetcher = _RecordingJWKSFetcher(response, not_modified)
    bounded_provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=bounded_fetcher, policy=policy)
    await bounded_provider.select_key(_JWT_ISSUER, _JWKS_URI, "known-0", "EdDSA", now=_JWT_NOW)
    for _ in range(1_000):
        await bounded_provider.select_key(
            _JWT_ISSUER, _JWKS_URI, "repeated-unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=1)
        )
    for index in range(1_000):
        await bounded_provider.select_key(
            _JWT_ISSUER, _JWKS_URI, f"unknown-{index}", "EdDSA", now=_JWT_NOW + timedelta(seconds=1)
        )
    state = cast("Any", bounded_provider)._entries[(_JWT_ISSUER, _JWKS_URI)]  # noqa: SLF001

    assert len(blocking_fetcher.requests) == 1
    assert all(result is cold_results[0] for result in cold_results)
    assert len(bounded_fetcher.requests) == 2
    assert len(cast("Any", bounded_provider)._entries) == 1  # noqa: SLF001
    assert len(state.snapshot.keys) <= policy.maximum_keys
    assert len(state.negative) <= policy.maximum_unknown_keys


@pytest.mark.performance
@pytest.mark.anyio
async def test_jwks_performance_fresh_hit_p95_is_relative_to_direct_verification(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    private_key, _public_key = jwt_key_material["EdDSA"]
    token = _encode_jwt(private_key, "EdDSA")
    fetcher = _RecordingJWKSFetcher(_jwks_response(_verification_jwk(jwt_key_material), cache_control="max-age=300"))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)
    selected = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    assert isinstance(selected, VerificationKey)
    decode_options = {"verify_exp": False, "verify_iat": False, "verify_nbf": False}

    def verify(key: bytes) -> None:
        jwt.decode(token, key, algorithms=["EdDSA"], audience=_JWT_AUDIENCE, issuer=_JWT_ISSUER, options=decode_options)

    for _ in range(20):
        verify(selected.key)
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    direct = {("key-1", "EdDSA"): selected}

    async def measure_ratio() -> float:
        direct_samples: list[float] = []
        fresh_samples: list[float] = []
        for index in range(300):
            if index % 2:
                started = perf_counter_ns()
                fresh = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
                assert isinstance(fresh, VerificationKey)
                verify(fresh.key)
                fresh_samples.append(float(perf_counter_ns() - started))
            started = perf_counter_ns()
            verify(direct[("key-1", "EdDSA")].key)
            direct_samples.append(float(perf_counter_ns() - started))
            if not index % 2:
                started = perf_counter_ns()
                fresh = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
                assert isinstance(fresh, VerificationKey)
                verify(fresh.key)
                fresh_samples.append(float(perf_counter_ns() - started))
        return _p95(fresh_samples) / _p95(direct_samples)

    # One trial's p95 is tail-sensitive: unrelated CPU contention can inflate the fresh
    # samples alone and cross the budget without any regression. The median of independent
    # trials keeps the budget honest while requiring most trials to regress before failing.
    ratios = sorted([await measure_ratio() for _ in range(_PERFORMANCE_TRIALS)])
    ratio = ratios[len(ratios) // 2]
    maximum = _jwks_performance_baseline()["budgets"]["fresh_hit_p95_ratio"]["maximum"]

    assert ratio <= maximum


@pytest.mark.performance
@pytest.mark.anyio
async def test_jwks_performance_saturated_sync_verification_keeps_ticker_under_budget() -> None:
    pending = 100
    tick_overshoots_ms: list[float] = []

    class SyncVerifier:
        config = _jwt_config("EdDSA")

        def verify(self, _token: str, *, now: datetime) -> InvalidCredentials:
            assert now is _JWT_NOW
            sleep(0.002)
            return InvalidCredentials()

    verifier = normalize_verifier(SyncVerifier(), worker_limits=WorkerLimits(crypto_tokens=2))

    async def verify() -> None:
        nonlocal pending
        await verifier.verify("token", now=_JWT_NOW)
        pending -= 1

    async def ticker() -> None:
        interval = 0.001
        last_tick = perf_counter()
        while pending:
            await asyncio.sleep(interval)
            tick = perf_counter()
            tick_overshoots_ms.append(max(0.0, tick - last_tick - interval) * 1_000)
            last_tick = tick

    async with create_task_group() as task_group:
        task_group.start_soon(ticker)
        for _ in range(pending):
            task_group.start_soon(verify)

    maximum = _jwks_performance_baseline()["budgets"]["sync_ticker_delay_p95_ms"]["maximum"]
    observed_p95 = _p95(tick_overshoots_ms)

    assert len(tick_overshoots_ms) >= 10
    assert observed_p95 <= maximum


def _mechanism(
    name: str, slot: str, *, participates_by_default: bool = True
) -> AuthenticationMechanism[str, str, object]:
    return AuthenticationMechanism(
        authenticator=_Authenticator(name, slot, participates_by_default=participates_by_default),  # type: ignore[arg-type]
        resolver=_Resolver(),
    )


def test_outcomes_are_distinct_immutable_and_secret_safe() -> None:
    evidence = AuthenticationEvidence(
        mechanism="local", slot="authorization.bearer", authenticated_at=datetime(2026, 7, 26, tzinfo=timezone.utc)
    )
    presented = PresentedCredential("secret-token")
    outcomes = (
        NoCredentials(),
        Authenticated(claims={"sub": "user-1"}, evidence=evidence),
        InvalidCredentials(),
        VerificationUnavailable(retry_after=30),
    )

    assert tuple(type(outcome) for outcome in outcomes) == (
        NoCredentials,
        Authenticated,
        InvalidCredentials,
        VerificationUnavailable,
    )
    assert "secret-token" not in repr(presented)
    with pytest.raises(FrozenInstanceError):
        outcomes[2].code = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("slots", "mechanisms", "match"),
    [
        ([_Slot(" ")], [], "slot name"),
        ([_Slot("cookie"), _Slot(" cookie ")], [], "Duplicate credential slot"),
        ([_Slot("cookie")], [_mechanism(" ", "cookie")], "mechanism name"),
        (
            [_Slot("cookie"), _Slot("header")],
            [_mechanism("local", "cookie"), _mechanism(" local ", "header")],
            "Duplicate authentication mechanism",
        ),
        ([_Slot("cookie")], [_mechanism("local", "missing")], "undefined credential slot"),
        (
            [_Slot("cookie")],
            [_mechanism("local", "cookie"), _mechanism("backup", "cookie")],
            "Duplicate owner for credential slot",
        ),
        (
            [_Slot("authorization.bearer")],
            [_mechanism("local-jwt", "authorization.bearer"), _mechanism("oidc", "authorization.bearer")],
            "authorization.bearer",
        ),
    ],
)
def test_registry_rejects_invalid_or_ambiguous_ownership(
    slots: list[_Slot], mechanisms: list[AuthenticationMechanism[str, str, object]], match: str
) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        AuthenticationRegistry(slots=slots, mechanisms=mechanisms)  # type: ignore[arg-type]


def test_registry_normalizes_order_and_default_participation() -> None:
    registry = AuthenticationRegistry(
        slots=[_Slot(" cookie "), _Slot(" x-api-key ")],  # type: ignore[list-item]
        mechanisms=[
            _mechanism(" local ", " cookie "),
            _mechanism(" api-key ", " x-api-key ", participates_by_default=False),
        ],
    )

    assert registry.slot_names == ("cookie", "x-api-key")
    assert registry.mechanism_names == ("local", "api-key")
    assert registry.default_mechanism_names == ("local",)
    assert registry.get_slot(" cookie ").name == " cookie "
    assert registry.get_mechanism(" api-key ").authenticator.name == " api-key "
    assert registry.get_mechanism_for_slot("cookie") is registry.get_mechanism("local")
    assert registry.get_mechanism_for_slot("unused") is None


def test_required_default_plan_rejects_zero_participants() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="required default authentication"):
        AuthenticationRegistry(
            slots=[_Slot("x-api-key")],  # type: ignore[list-item]
            mechanisms=[_mechanism("api-key", "x-api-key", participates_by_default=False)],
            require_default=True,
        )


def test_policy_helpers_are_immutable_hashable_and_deterministic() -> None:
    oidc = mechanism(" oidc ", " reports:read ", "profile")
    policies = (
        public(),
        required(),
        required("session"),
        any_of("session", oidc),
        all_of("session", oidc),
        at_least(2, "session", oidc, "api-key"),
        optional(all_of("session", oidc)),
    )

    assert oidc == MechanismRequirement("oidc", ("reports:read", "profile"))
    assert required("session") == any_of("session")
    assert policies == tuple(policies)
    assert len(set(policies)) == len(policies)
    with pytest.raises(FrozenInstanceError):
        oidc.name = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (AuthenticationPolicy, "policy helper"),
        (lambda: optional(object()), "policy helper"),  # type: ignore[arg-type]  # test invalid runtime input
        (lambda: mechanism(" "), "mechanism name"),
        (lambda: mechanism("oidc", " "), "scope"),
        (lambda: mechanism("oidc", "read", " read "), "Duplicate scope"),
        (any_of, "at least one"),
        (lambda: any_of("session", " session "), "Duplicate mechanism"),
        (all_of, "at least one"),
        (lambda: all_of("session", mechanism("session")), "Duplicate mechanism"),
        (lambda: optional(public()), "positive"),
        (lambda: optional(optional(required("session"))), "nested optional"),
        (lambda: at_least(0, "a"), "between 1 and"),
        (lambda: at_least(2, "a"), "between 1 and"),
        (lambda: at_least(1, "a", " a "), "Duplicate mechanism"),
    ],
)
def test_policy_helpers_reject_invalid_or_unfaithful_expressions(factory: Callable[[], object], match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        factory()


def test_required_without_arguments_is_the_implicit_secure_policy() -> None:
    config = SecurityConfig()

    assert not hasattr(config, "default_policy")
    assert not hasattr(config, "openapi_policy")
    assert required() != required("session")


@pytest.mark.parametrize(
    "kwargs", [{"scheme_name": "bearer"}, {"security_scheme": SecurityScheme(type="http", scheme="bearer")}]
)
def test_authentication_mechanism_requires_complete_openapi_scheme_pair(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="configured together"):
        AuthenticationMechanism(
            authenticator=_Authenticator("a", "slot-a"),  # type: ignore[arg-type]
            resolver=_Resolver(),
            **kwargs,
        )


def test_authentication_mechanism_declares_session_capability() -> None:
    mechanism_value = AuthenticationMechanism(
        authenticator=_Authenticator("session", "session"),  # type: ignore[arg-type]
        resolver=_Resolver(),
        session_capable=True,
    )

    assert mechanism_value.session_capable is True


def test_external_csrf_requires_a_named_integration() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="name must not be blank"):
        ExternalCSRF(name=" ", validate=lambda _path, _method, _policy: True)
    with pytest.raises(ImproperlyConfiguredException, match="name must be text"):
        ExternalCSRF(name=cast("Any", object()), validate=lambda _path, _method, _policy: True)
    with pytest.raises(ImproperlyConfiguredException, match="hook must be callable"):
        ExternalCSRF(name="edge", validate=cast("Any", object()))

    async def validate(_path: str, _method: str, _policy: AuthenticationPolicy) -> bool:
        return True

    with pytest.raises(ImproperlyConfiguredException, match="hook must be synchronous"):
        ExternalCSRF(name="edge", validate=cast("Any", validate))


@pytest.mark.parametrize("limit", [0, -1])
def test_security_config_requires_positive_openapi_combination_limit(limit: int) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=r"max_openapi_combinations.*positive"):
        SecurityConfig(max_openapi_combinations=limit)


@pytest.mark.anyio
async def test_composite_bearer_dispatcher_selects_only_one_verifier() -> None:
    calls: list[tuple[str, str]] = []

    class _CompositeBearer(_Authenticator):
        async def authenticate(self, credential: str, _connection: object) -> Authenticated[str]:
            issuer, claims = credential.split(":", maxsplit=1)
            calls.append((issuer, claims))
            return Authenticated(
                claims=claims,
                evidence=AuthenticationEvidence(
                    mechanism=f"bearer:{issuer}",
                    slot=self.slot,
                    authenticated_at=datetime(2026, 7, 26, tzinfo=timezone.utc),
                ),
            )

    authenticator = _CompositeBearer("bearer", "authorization.bearer")
    registry = AuthenticationRegistry(
        slots=[_Slot("authorization.bearer")],  # type: ignore[list-item]
        mechanisms=[AuthenticationMechanism(authenticator=authenticator, resolver=_Resolver())],
    )

    outcome = await registry.get_mechanism("bearer").authenticator.authenticate(
        "local:user-1",
        None,  # type: ignore[arg-type]
    )

    assert isinstance(outcome, Authenticated)
    assert calls == [("local", "user-1")]


@pytest.mark.parametrize(
    ("headers", "expected_type", "expected_value"),
    [
        ([], NoCredentials, None),
        ([(b"authorization", b"Bearer compact.jwt.value")], PresentedCredential, "compact.jwt.value"),
        ([(b"authorization", b"bEaReR compact.jwt.value")], PresentedCredential, "compact.jwt.value"),
        (
            [(b"authorization", b"Bearer one.two.three"), (b"Authorization", b"Bearer four.five.six")],
            InvalidCredentials,
            None,
        ),
        ([(b"authorization", b"")], InvalidCredentials, None),
        ([(b"authorization", b"Basic credential")], InvalidCredentials, None),
        ([(b"authorization", b" Bearer one.two.three")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer  one.two.three")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer\tone.two.three")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer one.two.three\x7f")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer \xff")], InvalidCredentials, None),
    ],
    ids=[
        "absent",
        "bearer",
        "case-insensitive-scheme",
        "duplicate",
        "empty",
        "wrong-scheme",
        "leading-space",
        "double-space",
        "tab",
        "control",
        "non-ascii",
    ],
)
def test_composite_bearer_extracts_the_raw_authorization_namespace_once(
    headers: list[tuple[bytes, bytes]],
    expected_type: type[NoCredentials] | type[PresentedCredential[object]] | type[InvalidCredentials],
    expected_value: str | None,
) -> None:
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
    )
    physical_slot, _ = composite.build(_Resolver())

    extraction = physical_slot.extract(SimpleNamespace(scope={"headers": headers}))  # type: ignore[arg-type]

    assert isinstance(extraction, expected_type)
    assert getattr(extraction, "value", None) == expected_value


def test_composite_bearer_rejects_oversized_credentials_during_extraction() -> None:
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
        maximum_token_bytes=5,
    )
    physical_slot, _ = composite.build(_Resolver())

    extraction = physical_slot.extract(
        SimpleNamespace(scope={"headers": [(b"authorization", b"Bearer longer")]})  # type: ignore[arg-type]
    )

    assert extraction == InvalidCredentials()


def _routing_token(*, issuer: str, audiences: str | list[str], token_type: str | None = None) -> str:
    return _compact_jwt(
        json.dumps({"alg": "RS256", "kid": "shared", "typ": token_type or "at+jwt"}, separators=(",", ":")).encode(),
        json.dumps({"iss": issuer, "aud": audiences}, separators=(",", ":")).encode(),
    )


@pytest.mark.parametrize(
    ("issuer", "audience", "selected_name"),
    [("https://local.example", "local-api", "local"), ("https://oidc.example", "oidc-api", "oidc")],
)
@pytest.mark.anyio
async def test_composite_bearer_selects_exactly_one_trust_slot(issuer: str, audience: str, selected_name: str) -> None:
    grants = AuthorizationSnapshot(
        scopes=frozenset({"reports:read"}),
        roles=frozenset({"analyst"}),
        capabilities=frozenset({"reports"}),
        team_roles={"team-1": frozenset({"viewer"})},
        tenant_ids=frozenset({"tenant-1"}),
        attributes={"region": "north"},
    )
    restrictions = CredentialRestrictions(
        scopes=frozenset({"reports:read"}), roles=frozenset({"analyst"}), tenant_ids=frozenset({"tenant-1"})
    )
    authenticated = Authenticated(
        claims=JWTClaims(
            issuer=_JWT_ISSUER,
            subject="user-1",
            audiences=frozenset({_JWT_AUDIENCE}),
            expires_at=_JWT_NOW + timedelta(minutes=10),
            issued_at=_JWT_NOW,
            not_before=None,
            token_id="token-1",  # noqa: S106
            client_id="client-1",
            scopes=frozenset(),
            raw={},
        ),
        evidence=AuthenticationEvidence(
            mechanism="provider",
            slot="provider-slot",
            authenticated_at=_JWT_NOW,
            expires_at=_JWT_NOW + timedelta(1),
            methods=frozenset({"jwt"}),
            traits=frozenset({"phishing-resistant"}),
            acr="urn:example:acr:2",
            amr=("pwd", "otp"),
        ),
        grants=grants,
        restrictions=restrictions,
    )
    local = _recording_jwt_verifier(authenticated, issuer="https://local.example", audiences=frozenset({"local-api"}))
    oidc = _recording_jwt_verifier(authenticated, issuer="https://oidc.example", audiences=frozenset({"oidc-api"}))
    token = _routing_token(issuer=issuer, audiences=audience)
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(
                    issuers=frozenset({"https://local.example"}), audiences=frozenset({"local-api"})
                ),
                verifier=local,  # type: ignore[arg-type]
            ),
            BearerTokenSlot(
                name="oidc",
                selector=BearerSlotSelector(
                    issuers=frozenset({"https://oidc.example"}), audiences=frozenset({"oidc-api"})
                ),
                verifier=oidc,  # type: ignore[arg-type]
            ),
        ),
    )
    _, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)

    outcome = await mechanism_value.authenticator.authenticate(token, SimpleNamespace())  # type: ignore[arg-type]

    assert isinstance(outcome, Authenticated)
    assert outcome.evidence.mechanism == "bearer"
    assert outcome.evidence.slot == selected_name
    assert outcome.evidence == AuthenticationEvidence(
        mechanism="bearer",
        slot=selected_name,
        authenticated_at=_JWT_NOW,
        expires_at=_JWT_NOW + timedelta(1),
        methods=frozenset({"jwt"}),
        traits=frozenset({"phishing-resistant"}),
        acr="urn:example:acr:2",
        amr=("pwd", "otp"),
    )
    assert outcome.grants == grants
    assert outcome.restrictions == restrictions
    assert len(local.calls) + len(oidc.calls) == 1
    assert (local.calls if selected_name == "local" else oidc.calls) == [(token, _JWT_NOW)]


@pytest.mark.anyio
async def test_composite_bearer_cryptographically_isolates_same_kid_trust_domains(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    local_signing_key, local_verification_key = jwt_key_material["RS256"]
    oidc_signing_key, oidc_verification_key = jwt_key_material["RS256_ALT"]
    profiles = (
        ("local", "https://local.example", "local-api", local_signing_key, local_verification_key),
        ("oidc", "https://oidc.example", "oidc-api", oidc_signing_key, oidc_verification_key),
    )
    slots = tuple(
        BearerTokenSlot(
            name=name,
            selector=BearerSlotSelector(issuers=frozenset({issuer}), audiences=frozenset({audience})),
            verifier=PyJWTVerifier(
                config=JWTValidationConfig(
                    issuer=issuer, audiences=frozenset({audience}), algorithms=frozenset({"RS256"})
                ),
                key=verification_key,
                require_key_id=True,
            ),
        )
        for name, issuer, audience, _signing_key, verification_key in profiles
    )
    _, mechanism_value = CompositeBearerConfig(mechanism_name="bearer", slots=slots).build(
        _Resolver(), clock=lambda: _JWT_NOW
    )

    for name, issuer, audience, signing_key, _verification_key in profiles:
        token = _encode_jwt(signing_key, "RS256", claims=_jwt_claims(iss=issuer, aud=audience))
        outcome = await mechanism_value.authenticator.authenticate(token, SimpleNamespace())  # type: ignore[arg-type]

        assert isinstance(outcome, Authenticated)
        assert outcome.claims.issuer == issuer
        assert outcome.claims.bearer_slot == name
        assert outcome.evidence.slot == name

    cross_domain_token = _encode_jwt(
        local_signing_key, "RS256", claims=_jwt_claims(iss="https://oidc.example", aud="oidc-api")
    )
    cross_domain_outcome = await mechanism_value.authenticator.authenticate(
        cross_domain_token,
        SimpleNamespace(),  # type: ignore[arg-type]
    )

    assert cross_domain_outcome == InvalidCredentials()


@pytest.mark.parametrize(
    ("selectors", "audiences"),
    [
        (
            (
                BearerSlotSelector(issuers=frozenset({"https://issuer.example"}), audiences=frozenset({"one", "two"})),
                BearerSlotSelector(issuers=frozenset({"https://issuer.example"}), audiences=frozenset({"one"})),
            ),
            "one",
        ),
        (
            (
                BearerSlotSelector(issuers=frozenset({"https://issuer.example"}), audiences=frozenset({"one"})),
                BearerSlotSelector(issuers=frozenset({"https://issuer.example"}), audiences=frozenset({"two"})),
            ),
            ["one", "two"],
        ),
        (
            (
                BearerSlotSelector(issuers=frozenset({"https://one.example"})),
                BearerSlotSelector(issuers=frozenset({"https://other.example"})),
            ),
            "unknown",
        ),
    ],
    ids=["overlapping-audience-ambiguity", "multi-audience-ambiguity", "unknown"],
)
@pytest.mark.anyio
async def test_composite_bearer_rejects_unknown_or_ambiguous_routes_without_verification(
    selectors: tuple[BearerSlotSelector, BearerSlotSelector], audiences: str | list[str]
) -> None:
    verifiers = tuple(
        _recording_jwt_verifier(
            InvalidCredentials(),
            issuer=next(iter(selector.issuers)),
            audiences=selector.audiences
            or (frozenset({audiences}) if isinstance(audiences, str) else frozenset(audiences)),
        )
        for selector in selectors
    )
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=tuple(
            BearerTokenSlot(name=f"slot-{index}", selector=selector, verifier=verifiers[index])  # type: ignore[arg-type]
            for index, selector in enumerate(selectors)
        ),
    )
    _, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)

    outcome = await mechanism_value.authenticator.authenticate(
        _routing_token(issuer="https://issuer.example", audiences=audiences),
        SimpleNamespace(),  # type: ignore[arg-type]
    )

    assert outcome == InvalidCredentials(code="unknown_or_ambiguous_bearer_slot")
    assert not verifiers[0].calls
    assert not verifiers[1].calls


@pytest.mark.parametrize(
    ("verifier_outcome", "expected"),
    [
        (InvalidCredentials(code="provider_invalid"), InvalidCredentials(code="provider_invalid")),
        (
            VerificationUnavailable(code="provider_unavailable", retry_after=2),
            VerificationUnavailable(code="provider_unavailable", retry_after=2),
        ),
        (NoCredentials(), InvalidCredentials()),
    ],
    ids=["invalid", "unavailable", "unexpected-no-credentials"],
)
@pytest.mark.anyio
async def test_composite_bearer_preserves_selected_terminal_outcomes(
    verifier_outcome: InvalidCredentials | VerificationUnavailable | NoCredentials,
    expected: InvalidCredentials | VerificationUnavailable,
) -> None:
    verifier = _recording_jwt_verifier(verifier_outcome)
    token = _routing_token(issuer=_JWT_ISSUER, audiences=_JWT_AUDIENCE)
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=verifier,  # type: ignore[arg-type]
            ),
        ),
    )
    _, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)

    outcome = await mechanism_value.authenticator.authenticate(token, SimpleNamespace())  # type: ignore[arg-type]

    assert outcome == expected
    assert verifier.calls == [(token, _JWT_NOW)]


@pytest.mark.anyio
async def test_composite_bearer_rejects_malformed_routes_before_verification() -> None:
    verifier = _recording_jwt_verifier(InvalidCredentials())
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=verifier,  # type: ignore[arg-type]
            ),
        ),
    )
    _, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)

    outcome = await mechanism_value.authenticator.authenticate("malformed", SimpleNamespace())  # type: ignore[arg-type]

    assert outcome == InvalidCredentials()
    assert not verifier.calls


@pytest.mark.anyio
async def test_composite_bearer_uses_an_aware_utc_clock_by_default() -> None:
    verifier = _recording_jwt_verifier(InvalidCredentials())
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=verifier,  # type: ignore[arg-type]
            ),
        ),
    )
    _, mechanism_value = composite.build(_Resolver())

    await mechanism_value.authenticator.authenticate(
        _routing_token(issuer=_JWT_ISSUER, audiences=_JWT_AUDIENCE),
        SimpleNamespace(),  # type: ignore[arg-type]
    )

    assert verifier.calls[0][1].tzinfo is timezone.utc


def test_composite_bearer_builds_one_native_registry_mechanism() -> None:
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
    )

    physical_slot, mechanism_value = composite.build(_Resolver())
    registry = AuthenticationRegistry(slots=(physical_slot,), mechanisms=(mechanism_value,))  # type: ignore[arg-type]

    assert registry.slot_names == ("authorization.bearer",)
    assert registry.mechanism_names == ("bearer",)
    assert mechanism_value.scheme_name == "bearer"
    assert mechanism_value.security_scheme == SecurityScheme(type="http", scheme="bearer", bearer_format="JWT")


@pytest.mark.anyio
async def test_composite_bearer_extension_dispatches_local_and_external_identity_resolvers() -> None:
    class ClaimsResolver:
        def __init__(self, prefix: str) -> None:
            self.prefix = prefix
            self.calls: list[str] = []

        async def resolve(self, claims: JWTClaims) -> Principal[object]:
            self.calls.append(claims.subject)
            return Principal(id=f"{self.prefix}:{claims.subject}")

    external_resolver = ClaimsResolver("external")
    local_resolver = ClaimsResolver("local")
    external_slot = BearerTokenSlot(
        name="external",
        selector=BearerSlotSelector(
            issuers=frozenset({"https://external.example"}), audiences=frozenset({"external-api"})
        ),
        verifier=_recording_jwt_verifier(
            InvalidCredentials(), issuer="https://external.example", audiences=frozenset({"external-api"})
        ),  # type: ignore[arg-type]
    )
    physical_slot, mechanism_value = CompositeBearerConfig(mechanism_name="bearer", slots=(external_slot,)).build(
        external_resolver
    )
    local_slot = BearerTokenSlot(
        name="local",
        selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER}), audiences=frozenset({_JWT_AUDIENCE})),
        verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
    )

    extended = extend_composite_bearer(mechanism_value, local_slot, local_resolver)
    base_claims = JWTClaims(
        issuer=_JWT_ISSUER,
        subject="user-1",
        audiences=frozenset({_JWT_AUDIENCE}),
        expires_at=_JWT_NOW + timedelta(minutes=10),
        issued_at=_JWT_NOW,
        not_before=None,
        token_id="token-1",  # noqa: S106
        client_id="client-1",
        scopes=frozenset(),
        raw={},
    )

    local = await extended.resolver.resolve(replace(base_claims, bearer_slot="local"))
    external = await extended.resolver.resolve(replace(base_claims, bearer_slot="external"))

    assert isinstance(local, Principal)
    assert isinstance(external, Principal)
    assert (local.id, external.id) == ("local:user-1", "external:user-1")
    assert local_resolver.calls == ["user-1"]
    assert external_resolver.calls == ["user-1"]
    assert physical_slot.name == "authorization.bearer"
    assert tuple(slot.name for slot in extended.authenticator.config.slots) == ("external", "local")  # type: ignore[attr-defined]


@pytest.mark.anyio
async def test_composite_bearer_never_retains_or_represents_the_raw_token() -> None:
    verifier = _recording_jwt_verifier(InvalidCredentials())
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=verifier,  # type: ignore[arg-type]
            ),
        ),
    )
    physical_slot, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)
    token = _routing_token(issuer=_JWT_ISSUER, audiences=_JWT_AUDIENCE)
    extraction = physical_slot.extract(
        SimpleNamespace(scope={"headers": [(b"authorization", f"Bearer {token}".encode())]})  # type: ignore[arg-type]
    )
    outcome = await mechanism_value.authenticator.authenticate(token, SimpleNamespace())  # type: ignore[arg-type]

    assert isinstance(extraction, PresentedCredential)
    assert outcome == InvalidCredentials()
    assert all(
        token not in repr(value)
        for value in (composite, physical_slot, mechanism_value, mechanism_value.authenticator, extraction, outcome)
    )


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (lambda: BearerSlotSelector(issuers=frozenset()), "issuer"),
        (lambda: BearerSlotSelector(issuers=frozenset({_JWT_ISSUER}), token_types=frozenset()), "token types"),
        (lambda: CompositeBearerConfig(mechanism_name="bearer", slots=()), "at least one"),
        (
            lambda: CompositeBearerConfig(
                mechanism_name="bearer",
                slots=(
                    BearerTokenSlot(
                        name="duplicate",
                        selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                        verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
                    ),
                    BearerTokenSlot(
                        name="duplicate",
                        selector=BearerSlotSelector(issuers=frozenset({"https://other.example"})),
                        verifier=_recording_jwt_verifier(InvalidCredentials(), issuer="https://other.example"),  # type: ignore[arg-type]
                    ),
                ),
            ),
            "Duplicate bearer slot",
        ),
        (
            lambda: CompositeBearerConfig(
                mechanism_name="bearer",
                slots=tuple(
                    BearerTokenSlot(
                        name=f"slot-{index}",
                        selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                        verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
                    )
                    for index in range(2)
                ),
            ),
            "identical selector",
        ),
        (
            lambda: CompositeBearerConfig(
                mechanism_name="bearer",
                slots=(
                    BearerTokenSlot(
                        name="local",
                        selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                        verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
                    ),
                ),
                maximum_token_bytes=0,
            ),
            "maximum token bytes",
        ),
        (
            lambda: BearerTokenSlot(
                name="missing-config",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=cast("Any", SimpleNamespace()),
            ),
            "must expose JWTValidationConfig",
        ),
        (
            lambda: BearerTokenSlot(
                name="issuer-mismatch",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials(), issuer="https://other.example"),  # type: ignore[arg-type]
            ),
            "does not match verifier",
        ),
        (
            lambda: BearerTokenSlot(
                name="audience-mismatch",
                selector=BearerSlotSelector(
                    issuers=frozenset({_JWT_ISSUER}), audiences=frozenset({"another-audience"})
                ),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
            "does not match verifier",
        ),
        (
            lambda: BearerTokenSlot(
                name="type-mismatch",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER}), token_types=frozenset({"id+jwt"})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
            "does not match verifier",
        ),
    ],
)
def test_composite_bearer_configuration_rejects_ambiguous_or_unsafe_values(
    factory: Callable[[], object], match: str
) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        factory()


def test_composite_bearer_requires_a_callable_clock() -> None:
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
    )

    with pytest.raises(ImproperlyConfiguredException, match="clock must be callable"):
        composite.build(_Resolver(), clock=None)  # type: ignore[arg-type]


@pytest.mark.parametrize("algorithm", ["EdDSA", "ES256", "RS256", "HS256"])
@pytest.mark.anyio
async def test_local_key_ring_signs_and_verifies_every_supported_algorithm(
    algorithm: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    private_key, _public_key = jwt_key_material[algorithm]
    signing_key = SigningKey(key_id=f"{algorithm.lower()}-active", algorithm=algorithm, private_key=private_key)
    ring = LocalKeyRing(issuer=_JWT_ISSUER, active_signing_key=signing_key)
    claims = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=3,
        scopes=frozenset({"profile", "reports:read"}),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=10),
        jti="token-1",
        not_before=_JWT_NOW - timedelta(seconds=1),
    )

    token = await ring.build_signer().sign(claims, now=_JWT_NOW)
    outcome = await ring.build_verifier(_jwt_config(algorithm)).verify(token, now=_JWT_NOW)

    assert jwt.get_unverified_header(token) == {"alg": algorithm, "kid": f"{algorithm.lower()}-active", "typ": "at+jwt"}
    assert isinstance(outcome, Authenticated)
    assert outcome.claims.raw["se"] == 3
    assert outcome.claims.scopes == frozenset({"profile", "reports:read"})
    assert (
        signing_key.public_jwk is None if algorithm == "HS256" else signing_key.public_jwk["kid"] == signing_key.key_id
    )


@pytest.mark.anyio
async def test_local_key_ring_rotation_accepts_retained_keys_and_rejects_removed_keys(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    old_private, old_public = jwt_key_material["RS256"]
    new_private, _new_public = jwt_key_material["RS256_ALT"]
    old_ring = LocalKeyRing(
        issuer=_JWT_ISSUER, active_signing_key=SigningKey(key_id="old", algorithm="RS256", private_key=old_private)
    )
    new_active = SigningKey(key_id="new", algorithm="RS256", private_key=new_private)
    retained = VerificationKey(key_id="old", algorithm="RS256", key=old_public)
    rotated_ring = LocalKeyRing(issuer=_JWT_ISSUER, active_signing_key=new_active, verification_keys=(retained,))
    claims = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=1,
        scopes=frozenset(),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=10),
        jti="rotation-token",
    )
    old_token = await old_ring.build_signer().sign(claims, now=_JWT_NOW)
    new_token = await rotated_ring.build_signer().sign(claims, now=_JWT_NOW)
    config = _jwt_config("RS256")

    assert isinstance(await rotated_ring.build_verifier(config).verify(old_token, now=_JWT_NOW), Authenticated)
    assert isinstance(await rotated_ring.build_verifier(config).verify(new_token, now=_JWT_NOW), Authenticated)
    assert rotated_ring.verification_key_set.keys == rotated_ring.all_verification_keys
    replacement_without_old = LocalKeyRing(issuer=_JWT_ISSUER, active_signing_key=new_active)
    assert await replacement_without_old.build_verifier(config).verify(old_token, now=_JWT_NOW) == InvalidCredentials()
    verifier = rotated_ring.build_verifier(config)
    assert await verifier.verify("malformed", now=_JWT_NOW) == InvalidCredentials()
    missing_algorithm = _compact_jwt(
        b'{"kid":"old","typ":"at+jwt"}', json.dumps(dict(claims), separators=(",", ":")).encode()
    )
    assert await verifier.verify(missing_algorithm, now=_JWT_NOW) == InvalidCredentials()


@pytest.mark.parametrize(
    ("case", "match"),
    [
        ("blank-kid", "key id"),
        ("public-signing-key", "signing key"),
        ("weak-rsa", "RS256"),
        ("wrong-curve", "ES256"),
        ("wrong-ed-key", "EdDSA"),
        ("short-hmac", "HS256"),
        ("short-hmac-verification", "HS256"),
        ("mismatched-jwk", "correspond"),
        ("private-jwk", "public JWK"),
        ("wrong-jwk-alg", "public JWK"),
        ("wrong-jwk-use", "public JWK"),
        ("wrong-jwk-ops", "public JWK"),
        ("private-verification-key", "verification key"),
        ("wrong-verification-type", "verification key"),
        ("non-bytes-signing-key", "signing key"),
        ("non-bytes-verification-key", "verification key"),
        ("unsupported-signing-algorithm", "Unsupported local signing algorithm"),
        ("unsupported-verification-algorithm", "Unsupported local verification algorithm"),
        ("empty-key-set", "at least one key"),
        ("hmac-public-jwk", "public JWK"),
        ("mismatched-jwk-kid", "public JWK"),
        ("duplicate-kid", "Duplicate local key id"),
        ("issuer-mismatch", "issuer"),
        ("active-algorithm-excluded", "active signing algorithm"),
        ("no-compatible-key-set", "no key accepted"),
    ],
)
def test_local_key_ring_rejects_unsafe_startup_configuration(  # noqa: C901
    case: str, match: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    rsa_private, rsa_public = jwt_key_material["RS256"]
    alt_private, _alt_public = jwt_key_material["RS256_ALT"]
    valid = SigningKey(key_id="valid", algorithm="RS256", private_key=rsa_private)
    public_jwk = dict(cast("Mapping[str, object]", valid.public_jwk))

    def build_invalid() -> object:  # noqa: C901, PLR0911, PLR0912
        if case == "blank-kid":
            return SigningKey(key_id=" ", algorithm="RS256", private_key=rsa_private)
        if case == "public-signing-key":
            return SigningKey(key_id="public", algorithm="RS256", private_key=rsa_public)
        if case == "weak-rsa":
            return SigningKey(key_id="weak", algorithm="RS256", private_key=jwt_key_material["RS1024"][0])
        if case == "wrong-curve":
            return SigningKey(key_id="curve", algorithm="ES256", private_key=jwt_key_material["ES384"][0])
        if case == "wrong-ed-key":
            return SigningKey(key_id="wrong-ed", algorithm="EdDSA", private_key=rsa_private)
        if case == "short-hmac":
            return SigningKey(key_id="short", algorithm="HS256", private_key=b"too-short")
        if case == "short-hmac-verification":
            return VerificationKey(key_id="short", algorithm="HS256", key=b"too-short")
        if case == "mismatched-jwk":
            return SigningKey(key_id="valid", algorithm="RS256", private_key=alt_private, public_jwk=public_jwk)
        if case == "private-jwk":
            return SigningKey(
                key_id="valid", algorithm="RS256", private_key=rsa_private, public_jwk={**public_jwk, "d": "secret"}
            )
        if case == "wrong-jwk-alg":
            return SigningKey(
                key_id="valid", algorithm="RS256", private_key=rsa_private, public_jwk={**public_jwk, "alg": "ES256"}
            )
        if case == "wrong-jwk-use":
            return SigningKey(
                key_id="valid", algorithm="RS256", private_key=rsa_private, public_jwk={**public_jwk, "use": "enc"}
            )
        if case == "wrong-jwk-ops":
            return SigningKey(
                key_id="valid",
                algorithm="RS256",
                private_key=rsa_private,
                public_jwk={**public_jwk, "key_ops": ["sign"]},
            )
        if case == "private-verification-key":
            return VerificationKey(key_id="private", algorithm="RS256", key=rsa_private)
        if case == "wrong-verification-type":
            return VerificationKey(key_id="wrong-type", algorithm="ES256", key=rsa_public)
        if case == "non-bytes-signing-key":
            return SigningKey(key_id="type", algorithm="RS256", private_key=cast("Any", "not-bytes"))
        if case == "non-bytes-verification-key":
            return VerificationKey(key_id="type", algorithm="RS256", key=cast("Any", "not-bytes"))
        if case == "unsupported-signing-algorithm":
            return SigningKey(key_id="unsupported", algorithm=cast("Any", "ES384"), private_key=rsa_private)
        if case == "unsupported-verification-algorithm":
            return VerificationKey(key_id="unsupported", algorithm=cast("Any", "ES384"), key=rsa_public)
        if case == "empty-key-set":
            return VerificationKeySet(issuer=_JWT_ISSUER, keys=())
        if case == "hmac-public-jwk":
            return SigningKey(
                key_id="hmac", algorithm="HS256", private_key=jwt_key_material["HS256"][0], public_jwk=public_jwk
            )
        if case == "mismatched-jwk-kid":
            return SigningKey(
                key_id="valid", algorithm="RS256", private_key=rsa_private, public_jwk={**public_jwk, "kid": "other"}
            )
        if case == "duplicate-kid":
            return LocalKeyRing(
                issuer=_JWT_ISSUER,
                active_signing_key=valid,
                verification_keys=(VerificationKey(key_id="valid", algorithm="RS256", key=rsa_public),),
            )
        ring = LocalKeyRing(issuer=_JWT_ISSUER, active_signing_key=valid)
        if case == "issuer-mismatch":
            return ring.build_verifier(
                JWTValidationConfig(
                    issuer="https://other.example",
                    audiences=frozenset({_JWT_AUDIENCE}),
                    algorithms=frozenset({"RS256"}),
                )
            )
        if case == "active-algorithm-excluded":
            retained = VerificationKey(key_id="retained-ec", algorithm="ES256", key=jwt_key_material["ES256"][1])
            return LocalKeyRing(
                issuer=_JWT_ISSUER, active_signing_key=valid, verification_keys=(retained,)
            ).build_verifier(_jwt_config("ES256"))
        return VerificationKeySet(
            issuer=_JWT_ISSUER, keys=(VerificationKey(key_id="rsa-only", algorithm="RS256", key=rsa_public),)
        ).build_verifier(_jwt_config("ES256"))

    with pytest.raises(ImproperlyConfiguredException, match=match):
        build_invalid()


def test_access_token_claim_builder_is_deterministic_minimal_and_validated() -> None:
    claims = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=7,
        scopes=frozenset({"z:write", "a:read"}),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=5),
        jti="token-1",
        not_before=_JWT_NOW + timedelta(seconds=2),
    )

    assert dict(claims) == {
        "iss": _JWT_ISSUER,
        "sub": "user-1",
        "aud": _JWT_AUDIENCE,
        "exp": int((_JWT_NOW + timedelta(minutes=5)).timestamp()),
        "iat": int(_JWT_NOW.timestamp()),
        "nbf": int((_JWT_NOW + timedelta(seconds=2)).timestamp()),
        "client_id": "client-1",
        "jti": "token-1",
        "scope": "a:read z:write",
        "se": 7,
    }
    assert not {"email", "password", "roles", "teams", "user"}.intersection(claims)
    with pytest.raises(TypeError):
        claims["sub"] = "changed"  # type: ignore[index]
    random_one = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=0,
        scopes=frozenset(),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=1),
    )
    random_two = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=0,
        scopes=frozenset(),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=1),
    )
    assert random_one["jti"] != random_two["jti"]
    assert "scope" not in random_one


def test_capability_claims_reject_reserved_claim_names() -> None:
    capabilities = importlib.import_module("litestar_security.providers.jwt._capabilities")

    with pytest.raises(ValueError, match="reserved"):
        capabilities.build_capability_claims(
            issuer=_JWT_ISSUER,
            purpose="download",
            subject="user-1",
            audience="files",
            lifetime=timedelta(minutes=5),
            claims={"aud": "hijack"},
            now=_JWT_NOW,
        )


def test_capability_claim_builder_returns_detached_json_payload() -> None:
    capabilities = importlib.import_module("litestar_security.providers.jwt._capabilities")
    application_claims = {"resource": {"parts": ["one"]}, "weight": 1.5}

    payload = capabilities.build_capability_claims(
        issuer=_JWT_ISSUER,
        purpose="download",
        subject="user-1",
        audience="files",
        lifetime=timedelta(minutes=5),
        claims=application_claims,
        now=_JWT_NOW,
    )
    application_claims["resource"]["parts"].append("two")

    assert isinstance(payload, dict)
    assert payload["resource"] == {"parts": ["one"]}
    assert payload["weight"] == 1.5
    assert json.loads(json.dumps(payload))["resource"] == {"parts": ["one"]}


def test_capability_claim_builder_rejects_non_json_application_values() -> None:
    capabilities = importlib.import_module("litestar_security.providers.jwt._capabilities")

    with pytest.raises(ValueError, match="JSON"):
        capabilities.build_capability_claims(
            issuer=_JWT_ISSUER,
            purpose="download",
            subject="user-1",
            audience="files",
            lifetime=timedelta(minutes=5),
            claims={"created_at": _JWT_NOW},
            now=_JWT_NOW,
        )


@pytest.mark.parametrize(
    ("claims", "lifetime", "match"),
    [
        ({1: "value"}, timedelta(minutes=5), "object keys"),
        ({"nested": {1: "value"}}, timedelta(minutes=5), "object keys"),
        ({"value": nan}, timedelta(minutes=5), "finite"),
        ({"value": inf}, timedelta(minutes=5), "finite"),
        ({}, timedelta(milliseconds=500), "whole second"),
    ],
)
def test_capability_claim_builder_rejects_noncanonical_json_values(
    claims: Mapping[object, object], lifetime: timedelta, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        jwt_capabilities.build_capability_claims(
            issuer=_JWT_ISSUER,
            purpose="download",
            subject="user-1",
            audience="files",
            lifetime=lifetime,
            claims=cast("Mapping[str, jwt_capabilities.JSONValue]", claims),
            now=_JWT_NOW,
        )


def test_capability_claim_builder_rejects_excessive_json_depth() -> None:
    nested: object = "value"
    for _ in range(33):
        nested = [nested]

    with pytest.raises(ValueError, match="bounded"):
        jwt_capabilities.build_capability_claims(
            issuer=_JWT_ISSUER,
            purpose="download",
            subject="user-1",
            audience="files",
            lifetime=timedelta(minutes=5),
            claims={"nested": cast("jwt_capabilities.JSONValue", nested)},
            now=_JWT_NOW,
        )


@pytest.mark.parametrize(
    ("mutation", "now"),
    [
        ("missing", _JWT_NOW),
        ("invalid-numeric", _JWT_NOW),
        ("overflow-numeric", _JWT_NOW),
        ("expired-lifetime", _JWT_NOW),
        ("not-before-after-expiry", _JWT_NOW),
        ("invalid-now", cast("datetime", None)),
    ],
)
def test_normalize_capability_claims_rejects_malformed_temporal_claims(mutation: str, now: datetime) -> None:
    payload: dict[str, jwt_capabilities.JSONValue] = {
        "iss": _JWT_ISSUER,
        "sub": "user-1",
        "aud": "files",
        "purpose": "download",
        "jti": "capability-1",
        "iat": int(_JWT_NOW.timestamp()),
        "exp": int((_JWT_NOW + timedelta(minutes=5)).timestamp()),
    }
    if mutation == "missing":
        del payload["jti"]
    elif mutation == "invalid-numeric":
        payload["iat"] = True
    elif mutation == "overflow-numeric":
        payload["exp"] = inf
    elif mutation == "expired-lifetime":
        payload["exp"] = payload["iat"]
    elif mutation == "not-before-after-expiry":
        payload["nbf"] = payload["exp"]

    assert (
        jwt_capabilities.normalize_capability_claims(
            payload, purpose="download", audience="files", issuer=_JWT_ISSUER, now=now
        )
        == InvalidCredentials()
    )


@pytest.mark.anyio
async def test_mint_capability_header_is_never_accepted_by_the_access_verifier(local_key_ring: LocalKeyRing) -> None:
    with pytest.raises(ValueError, match="24 hours"):
        await local_key_ring.mint_capability(
            purpose="download", subject="user-1", audience="files", lifetime=timedelta(hours=25)
        )

    token = await local_key_ring.mint_capability(
        purpose="download", subject="user-1", audience="files", lifetime=timedelta(minutes=5)
    )

    assert jwt.get_unverified_header(token)["typ"] == "capability+jwt"
    verifier = local_key_ring.build_verifier(
        JWTValidationConfig(
            issuer=local_key_ring.issuer,
            audiences=frozenset({"files"}),
            algorithms=frozenset(key.algorithm for key in local_key_ring.all_verification_keys),
        )
    )
    assert isinstance(await verifier.verify(token, now=_JWT_NOW), InvalidCredentials)


@pytest.mark.anyio
@pytest.mark.parametrize("case", ["access-token", "purpose", "audience", "expired", "naive-now"])
async def test_verify_capability_rejects_untrusted_or_mismatched_tokens_as_one_outcome(
    case: str, local_key_ring: LocalKeyRing
) -> None:
    now = datetime.now(timezone.utc)
    capability = await local_key_ring.mint_capability(
        purpose="download", subject="user-1", audience="files", lifetime=timedelta(minutes=1)
    )
    if case == "access-token":
        token = await local_key_ring.build_signer().sign(
            build_access_token_claims(
                issuer=local_key_ring.issuer,
                audience="files",
                subject="user-1",
                client_id="client-1",
                security_epoch=0,
                scopes=frozenset(),
                now=now,
                lifetime=timedelta(minutes=1),
                jti="access-token-1",
            ),
            now=now,
        )
        purpose, audience, verification_now = "download", "files", now
    elif case == "purpose":
        token, purpose, audience, verification_now = capability, "upload", "files", now
    elif case == "audience":
        token, purpose, audience, verification_now = capability, "download", "images", now
    elif case == "expired":
        token, purpose, audience, verification_now = (
            capability,
            "download",
            "files",
            now + timedelta(minutes=1, seconds=31),
        )
    else:
        token, purpose, audience, verification_now = capability, "download", "files", _NAIVE_JWT_NOW

    assert (
        await local_key_ring.verify_capability(token, purpose=purpose, audience=audience, now=verification_now)
        == InvalidCredentials()
    )


@pytest.mark.anyio
async def test_verify_capability_accepts_a_retained_rotation_key(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    old_private, old_public = jwt_key_material["RS256"]
    new_private, _new_public = jwt_key_material["RS256_ALT"]
    old_ring = LocalKeyRing(
        issuer=_JWT_ISSUER, active_signing_key=SigningKey(key_id="old", algorithm="RS256", private_key=old_private)
    )
    token = await old_ring.mint_capability(
        purpose="download", subject="user-1", audience="files", lifetime=timedelta(minutes=5)
    )
    rotated_ring = LocalKeyRing(
        issuer=_JWT_ISSUER,
        active_signing_key=SigningKey(key_id="new", algorithm="RS256", private_key=new_private),
        verification_keys=(VerificationKey(key_id="old", algorithm="RS256", key=old_public),),
    )

    result = await rotated_ring.verify_capability(
        token, purpose="download", audience="files", now=datetime.now(timezone.utc)
    )

    assert isinstance(result, jwt_capabilities.VerifiedCapability)
    assert result.subject == "user-1"


@pytest.mark.anyio
async def test_capability_worker_failures_are_sanitized(
    local_key_ring: LocalKeyRing, monkeypatch: pytest.MonkeyPatch
) -> None:
    capability = await local_key_ring.mint_capability(
        purpose="download", subject="user-1", audience="files", lifetime=timedelta(minutes=5)
    )

    async def failure(*_args: object, **_kwargs: object) -> object:
        message = "internal failure"
        raise OSError(message)

    monkeypatch.setattr(jwt_keyring, "run_worker", failure)
    with pytest.raises(RuntimeError, match="Capability minting unavailable") as exc_info:
        await local_key_ring.mint_capability(
            purpose="download", subject="user-1", audience="files", lifetime=timedelta(minutes=5)
        )
    assert "internal failure" not in str(exc_info.value)

    outcome = await local_key_ring.verify_capability(
        capability, purpose="download", audience="files", now=datetime.now(timezone.utc)
    )

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("raw", "failure", "outcome_type"),
    [("not-a-jwt", None, InvalidCredentials), (None, jwt.InvalidTokenError(), InvalidCredentials)],
)
async def test_verify_capability_sanitizes_untrusted_routes_and_crypto_failures(
    raw: str | None,
    failure: Exception | None,
    outcome_type: type[InvalidCredentials],
    local_key_ring: LocalKeyRing,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if raw is None:
        raw = await local_key_ring.mint_capability(
            purpose="download", subject="user-1", audience="files", lifetime=timedelta(minutes=5)
        )

        async def fail_worker(*_args: object, **_kwargs: object) -> object:
            raise cast("Exception", failure)

        monkeypatch.setattr(jwt_keyring, "run_worker", fail_worker)

    outcome = await local_key_ring.verify_capability(
        raw, purpose="download", audience="files", now=datetime.now(timezone.utc)
    )

    assert isinstance(outcome, outcome_type)


@pytest.mark.anyio
async def test_verify_capability_rejects_an_unknown_key_id(local_key_ring: LocalKeyRing) -> None:
    now = datetime.now(timezone.utc)
    payload = jwt_capabilities.build_capability_claims(
        issuer=local_key_ring.issuer,
        purpose="download",
        subject="user-1",
        audience="files",
        lifetime=timedelta(minutes=5),
        claims={},
        now=now,
    )
    raw = jwt.encode(
        dict(payload),
        cast("Any", local_key_ring.active_signing_key)._prepared_key,  # noqa: SLF001 - exercise untrusted key routing
        algorithm=local_key_ring.active_signing_key.algorithm,
        headers={"kid": "unknown", "typ": jwt_capabilities.CAPABILITY_TOKEN_TYPE},
    )

    outcome = await local_key_ring.verify_capability(raw, purpose="download", audience="files", now=now)

    assert isinstance(outcome, InvalidCredentials)


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"issuer": " "}, "identifier"),
        ({"audience": " "}, "identifier"),
        ({"subject": " "}, "identifier"),
        ({"client_id": " "}, "identifier"),
        ({"security_epoch": -1}, "security epoch"),
        ({"security_epoch": True}, "security epoch"),
        ({"lifetime": timedelta(0)}, "lifetime"),
        ({"lifetime": timedelta(milliseconds=500)}, "whole second"),
        ({"now": _NAIVE_JWT_NOW}, "timezone-aware"),
        ({"not_before": _NAIVE_JWT_NOW}, "timezone-aware"),
        ({"not_before": _JWT_NOW + timedelta(minutes=6)}, "expiry"),
        ({"jti": " "}, "identifier"),
        ({"scopes": frozenset({" "})}, "scope"),
    ],
)
def test_access_token_claim_builder_rejects_invalid_inputs(overrides: dict[str, object], match: str) -> None:
    kwargs: dict[str, object] = {
        "issuer": _JWT_ISSUER,
        "audience": _JWT_AUDIENCE,
        "subject": "user-1",
        "client_id": "client-1",
        "security_epoch": 0,
        "scopes": frozenset({"profile"}),
        "now": _JWT_NOW,
        "lifetime": timedelta(minutes=5),
        "jti": "token-1",
    }
    kwargs.update(overrides)

    with pytest.raises(ValueError, match=match):
        build_access_token_claims(**kwargs)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_local_signer_runs_crypto_in_a_worker_and_supports_custom_signers(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, object]] = []
    observations: list[str] = []

    async def run_sync(function: Callable[[], object], **kwargs: object) -> object:
        calls.append(kwargs)
        return function()

    class Metrics:
        def increment(self, name: str, *, attributes: Mapping[str, str] = {}) -> None:
            del name, attributes

        def observe(self, name: str, value: float, *, attributes: Mapping[str, str] = {}) -> None:
            del value, attributes
            observations.append(name)

    monkeypatch.setattr(jwt_workers.to_thread, "run_sync", run_sync)
    ring = LocalKeyRing(
        issuer=_JWT_ISSUER,
        active_signing_key=SigningKey(key_id="active", algorithm="EdDSA", private_key=jwt_key_material["EdDSA"][0]),
        metrics=Metrics(),
    )
    claims = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=0,
        scopes=frozenset(),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=5),
        jti="worker-token",
    )

    token = await ring.build_signer().sign(claims, now=_JWT_NOW)

    class _CustomSigner:
        async def sign(self, custom_claims: Mapping[str, object], *, now: datetime) -> str:
            assert custom_claims is claims
            assert now is _JWT_NOW
            encoded = jwt.encode(
                dict(custom_claims),
                jwt_key_material["EdDSA"][0],
                algorithm="EdDSA",
                headers={"kid": "kms", "typ": "at+jwt"},
            )
            return encoded.decode() if isinstance(encoded, bytes) else encoded

    custom_signer: TokenSigner = _CustomSigner()  # type: ignore[assignment]
    custom_token = await custom_signer.sign(claims, now=_JWT_NOW)  # type: ignore[arg-type]
    custom_keys = VerificationKeySet(
        issuer=_JWT_ISSUER, keys=(VerificationKey(key_id="kms", algorithm="EdDSA", key=jwt_key_material["EdDSA"][1]),)
    )

    assert token.count(".") == 2
    assert len(calls) == 1
    assert calls[0]["abandon_on_cancel"] is True
    assert cast("CapacityLimiter", calls[0]["limiter"]).total_tokens == 32
    assert isinstance(await ring.build_verifier(_jwt_config("EdDSA")).verify(token, now=_JWT_NOW), Authenticated)
    assert {"security.jwt.sign_duration", "security.jwt.verify_duration"} <= set(observations)
    assert isinstance(custom_signer, TokenSigner)
    assert isinstance(
        await custom_keys.build_verifier(_jwt_config("EdDSA")).verify(custom_token, now=_JWT_NOW), Authenticated
    )

    async def unavailable(_function: Callable[[], object], **_kwargs: object) -> object:
        message = "private failure detail"
        raise OSError(message)

    monkeypatch.setattr(jwt_workers.to_thread, "run_sync", unavailable)
    with pytest.raises(RuntimeError, match="Token signing unavailable") as exc_info:
        await ring.build_signer().sign(claims, now=_JWT_NOW)
    assert "private failure detail" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("missing", "sub"),
        ("forbidden", ("email", "private@example.com")),
        ("issuer", "https://other.example"),
        ("issued_at", int(_JWT_NOW.timestamp()) + 1),
        ("not_before", int((_JWT_NOW + timedelta(hours=1)).timestamp())),
        ("scope", "profile  reports:read"),
    ],
)
@pytest.mark.anyio
async def test_local_signer_rejects_nonconforming_access_claims(
    mutation: str, value: object, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    ring = LocalKeyRing(
        issuer=_JWT_ISSUER,
        active_signing_key=SigningKey(key_id="active", algorithm="EdDSA", private_key=jwt_key_material["EdDSA"][0]),
    )
    claims = dict(
        build_access_token_claims(
            issuer=_JWT_ISSUER,
            audience=_JWT_AUDIENCE,
            subject="user-1",
            client_id="client-1",
            security_epoch=0,
            scopes=frozenset({"profile"}),
            now=_JWT_NOW,
            lifetime=timedelta(minutes=5),
            jti="invalid-shape",
        )
    )
    if mutation == "missing":
        claims.pop(cast("str", value))
    elif mutation == "forbidden":
        key, item = cast("tuple[str, object]", value)
        claims[key] = item
    elif mutation == "issuer":
        claims["iss"] = value
    elif mutation == "issued_at":
        claims["iat"] = value
    elif mutation == "not_before":
        claims["nbf"] = value
    else:
        claims["scope"] = value

    with pytest.raises(ValueError, match="Invalid local access-token claims"):
        await ring.build_signer().sign(cast("Mapping[str, object]", claims), now=_JWT_NOW)  # type: ignore[arg-type]


def test_local_key_material_is_secret_safe(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    private_key, public_key = jwt_key_material["RS256"]
    signing_key = SigningKey(key_id="active", algorithm="RS256", private_key=private_key)
    verification_key = VerificationKey(key_id="retained", algorithm="RS256", key=public_key)
    ring = LocalKeyRing(issuer=_JWT_ISSUER, active_signing_key=signing_key, verification_keys=(verification_key,))

    assert all(
        private_key.decode() not in repr(value) and public_key.decode() not in repr(value)
        for value in (signing_key, verification_key, ring, ring.build_signer())
    )
    for public_jwk in (signing_key.public_jwk, verification_key.public_jwk):
        assert public_jwk is not None
        assert not {"d", "dp", "dq", "k", "oth", "p", "q", "qi"}.intersection(public_jwk)


def test_local_keys_canonicalize_null_public_jwk_metadata(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    private_key, public_key = jwt_key_material["RS256"]
    generated = SigningKey(key_id="generated", algorithm="RS256", private_key=private_key)
    null_metadata = {
        **dict(cast("Mapping[str, object]", generated.public_jwk)),
        "alg": None,
        "key_ops": None,
        "kid": None,
        "use": None,
    }

    signing_key = SigningKey(
        key_id="active", algorithm="RS256", private_key=private_key, public_jwk=cast("Any", null_metadata)
    )
    verification_key = VerificationKey(
        key_id="retained", algorithm="RS256", key=public_key, public_jwk=cast("Any", null_metadata)
    )

    for public_jwk, key_id in ((signing_key.public_jwk, "active"), (verification_key.public_jwk, "retained")):
        assert public_jwk is not None
        assert public_jwk["alg"] == "RS256"
        assert public_jwk["key_ops"] == ("verify",)
        assert public_jwk["kid"] == key_id
        assert public_jwk["use"] == "sig"


@pytest.mark.parametrize(
    ("algorithm", "require_key_id"), [("EdDSA", True), ("ES256", True), ("RS256", True), ("HS256", False)]
)
@pytest.mark.anyio
async def test_pyjwt_verifier_accepts_supported_algorithms_and_normalizes_claims(
    algorithm: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]], *, require_key_id: bool
) -> None:
    signing_key, verification_key = jwt_key_material[algorithm]
    token = _encode_jwt(signing_key, algorithm, claims=_jwt_claims(sub="user-\u0430"), include_key_id=require_key_id)
    verifier = PyJWTVerifier(config=_jwt_config(algorithm), key=verification_key, require_key_id=require_key_id)

    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert isinstance(outcome, Authenticated)
    claims = outcome.claims
    assert isinstance(claims, JWTClaims)
    assert claims.issuer == _JWT_ISSUER
    assert claims.subject == "user-\u0430"
    assert claims.audiences == frozenset({_JWT_AUDIENCE})
    assert claims.scopes == frozenset({"reports:read", "profile"})
    assert claims.client_id == "client-1"
    assert claims.token_id == "token-1"  # noqa: S105 - public token identifier, not a credential
    assert claims.expires_at == _JWT_NOW + timedelta(minutes=10)


@pytest.mark.parametrize(
    ("scope_claims", "expected"),
    [
        ({"scope": "reports:read profile"}, frozenset({"reports:read", "profile"})),
        ({"scp": ["reports:read", "profile"]}, frozenset({"reports:read", "profile"})),
        ({"aud": [_JWT_AUDIENCE]}, frozenset()),
    ],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_accepts_only_documented_scope_shapes(
    scope_claims: dict[str, object], expected: frozenset[str], jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    claims = _jwt_claims()
    claims.pop("scope")
    claims.update(scope_claims)
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=verification_key, require_key_id=False)

    outcome = await verifier.verify(
        _encode_jwt(signing_key, "HS256", claims=claims, include_key_id=False), now=_JWT_NOW
    )

    assert isinstance(outcome, Authenticated)
    assert outcome.claims.scopes == expected


def test_unverified_jwt_route_is_explicit_and_immutable() -> None:
    token = _compact_jwt(
        json.dumps({"alg": "HS256", "typ": "at+jwt"}, separators=(",", ":")).encode(),
        json.dumps({"iss": _JWT_ISSUER, "aud": [_JWT_AUDIENCE]}, separators=(",", ":")).encode(),
    )

    route = parse_unverified_jwt_route(token)

    assert isinstance(route, UnverifiedJWTRoute)
    assert route.header == {"alg": "HS256", "typ": "at+jwt"}
    assert route.payload == {"iss": _JWT_ISSUER, "aud": (_JWT_AUDIENCE,)}
    with pytest.raises(TypeError):
        route.header["alg"] = "none"  # type: ignore[index]


@pytest.mark.parametrize(
    "token",
    [
        "",
        "one.two",
        "one.two.three.four",
        "one..three",
        _compact_jwt(b"[]", b"{}"),
        _compact_jwt(b"{}", b"[]"),
        _compact_jwt(b"\xff", b"{}"),
        _compact_jwt(b'{"alg":"HS256","alg":"none"}', b"{}"),
        _compact_jwt(b"{}", b'{"iss":"one","iss":"two"}'),
        _compact_jwt(b"{}", b'{"value":NaN}'),
        _compact_jwt(b"{}", (b'{"nested":' * 33) + b"null" + (b"}" * 33)),
        _compact_jwt(b"{}", json.dumps({"value": "x" * 16_384}).encode()),
        "*.e30.c2ln",
        "é.e30.c2ln",
        "e30.e30.A",
        "e30.e30.AB",
    ],
    ids=[
        "empty",
        "two-segments",
        "four-segments",
        "empty-segment",
        "header-not-object",
        "payload-not-object",
        "invalid-utf8",
        "duplicate-header-member",
        "duplicate-payload-member",
        "non-finite-number",
        "excessive-json-depth",
        "excessive-token-size",
        "invalid-base64url",
        "non-ascii",
        "invalid-base64url-length",
        "non-canonical-base64url",
    ],
)
def test_unverified_jwt_route_rejects_malformed_or_ambiguous_json(token: str) -> None:
    assert parse_unverified_jwt_route(token) == InvalidCredentials()


@pytest.mark.parametrize("limits", [{"maximum_token_bytes": 0}, {"maximum_json_depth": 0}])
def test_unverified_jwt_route_rejects_invalid_parser_limits(limits: dict[str, int]) -> None:
    assert parse_unverified_jwt_route("e30.e30.c2ln", **limits) == InvalidCredentials()  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "protected_header",
    [
        {"crit": ["unknown"]},
        {"b64": True},
        {"jwk": {"kty": "oct", "k": "embedded"}},
        {"jku": "https://attacker.invalid/jwks"},
        {"x5u": "https://attacker.invalid/certificate"},
        {"x5c": ["certificate"]},
        {"x5t": "certificate-thumbprint"},
        {"x5t#S256": "certificate-thumbprint"},
    ],
    ids=["crit", "b64", "jwk", "jku", "x5u", "x5c", "x5t", "x5t-s256"],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_forbidden_jose_headers(
    protected_header: dict[str, object], jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=verification_key, require_key_id=False)
    if "b64" in protected_header:
        header = {"alg": "HS256", "typ": "at+jwt", **protected_header}
        token = _compact_jwt(
            json.dumps(header, separators=(",", ":")).encode(),
            json.dumps(_jwt_claims(), separators=(",", ":")).encode(),
        )
    else:
        token = _encode_jwt(signing_key, "HS256", headers=protected_header, include_key_id=False)

    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert outcome == InvalidCredentials()


@pytest.mark.parametrize(
    ("header", "algorithm"),
    [
        ({"alg": "none", "typ": "at+jwt"}, "none"),
        ({"typ": "at+jwt"}, "missing"),
        ({"alg": "HS256", "typ": "JWT"}, "HS256"),
        ({"alg": "HS256"}, "HS256"),
        ({"alg": "RS256", "typ": "at+jwt"}, "RS256"),
        ({"alg": "HS256", "typ": "at+jwt", "kid": 7}, "HS256"),
    ],
    ids=["none", "missing-alg", "id-token-type", "missing-type", "missing-asymmetric-kid", "malformed-key-id"],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_algorithm_type_and_key_id_confusion(
    header: dict[str, object], algorithm: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    verification_algorithm = "RS256" if algorithm == "RS256" else "HS256"
    verification_key = jwt_key_material[verification_algorithm][1]
    verifier = PyJWTVerifier(
        config=_jwt_config(verification_algorithm),
        key=verification_key,
        require_key_id=verification_algorithm == "RS256",
    )
    token = _compact_jwt(
        json.dumps(header, separators=(",", ":")).encode(), json.dumps(_jwt_claims(), separators=(",", ":")).encode()
    )

    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert outcome == InvalidCredentials()


@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_hmac_rsa_algorithm_confusion(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    token = _encode_jwt(jwt_key_material["HS256"][0], "HS256", include_key_id=False)
    verifier = PyJWTVerifier(config=_jwt_config("RS256"), key=jwt_key_material["RS256"][1], require_key_id=True)

    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert outcome == InvalidCredentials()


@pytest.mark.parametrize(
    ("overrides", "removed"),
    [
        ({"iss": "https://issuer.examp\u043be"}, frozenset()),
        ({"aud": "another-service"}, frozenset()),
        ({"aud": []}, frozenset()),
        ({"aud": 7}, frozenset()),
        ({"aud": [_JWT_AUDIENCE, 7]}, frozenset()),
        ({"aud": [_JWT_AUDIENCE, " "]}, frozenset()),
        ({"aud": [_JWT_AUDIENCE, _JWT_AUDIENCE]}, frozenset()),
        ({"exp": int((_JWT_NOW - timedelta(seconds=31)).timestamp())}, frozenset()),
        ({"nbf": int((_JWT_NOW + timedelta(seconds=31)).timestamp())}, frozenset()),
        ({"iat": int((_JWT_NOW + timedelta(seconds=31)).timestamp())}, frozenset()),
        (
            {
                "nbf": int((_JWT_NOW + timedelta(seconds=5)).timestamp()),
                "exp": int((_JWT_NOW + timedelta(seconds=5)).timestamp()),
            },
            frozenset(),
        ),
        ({"exp": True}, frozenset()),
        ({"iat": 1.5}, frozenset()),
        ({"exp": 10**100}, frozenset()),
        (
            {
                "iat": int((_JWT_NOW - timedelta(hours=2)).timestamp()),
                "exp": int((_JWT_NOW + timedelta(minutes=1)).timestamp()),
            },
            frozenset(),
        ),
        ({"sub": ""}, frozenset()),
        ({"client_id": ""}, frozenset()),
        ({"jti": ""}, frozenset()),
        ({"scope": 7}, frozenset()),
        ({"scope": "reports:read reports:read"}, frozenset()),
        ({"scp": "reports:read"}, frozenset({"scope"})),
        ({"scp": ["reports:read", 7]}, frozenset({"scope"})),
        ({"scp": ["admin read"]}, frozenset({"scope"})),
        ({"scp": ["reports:read"], "scope": "profile"}, frozenset()),
        ({}, frozenset({"iss"})),
        ({}, frozenset({"sub"})),
        ({}, frozenset({"exp"})),
        ({}, frozenset({"iat"})),
    ],
    ids=[
        "issuer-unicode-lookalike",
        "audience-mismatch",
        "audience-empty",
        "audience-malformed",
        "audience-member-malformed",
        "audience-member-blank",
        "audience-duplicate",
        "expired",
        "not-before-in-future",
        "issued-at-in-future",
        "not-before-at-expiry",
        "boolean-numeric-date",
        "float-numeric-date",
        "numeric-date-overflow",
        "excessive-lifetime",
        "empty-subject",
        "empty-client-id",
        "empty-token-id",
        "scalar-scope",
        "duplicate-scope",
        "string-scp",
        "mixed-scp",
        "space-containing-scp-member",
        "ambiguous-scope-claims",
        "missing-issuer",
        "missing-subject",
        "missing-expiry",
        "missing-issued-at",
    ],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_invalid_rfc_9068_claims(
    overrides: dict[str, object], removed: frozenset[str], jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    claims = _jwt_claims(**overrides)
    for claim in removed:
        claims.pop(claim)
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=verification_key, require_key_id=False)

    outcome = await verifier.verify(
        _encode_jwt(signing_key, "HS256", claims=claims, include_key_id=False), now=_JWT_NOW
    )

    assert outcome == InvalidCredentials()


@pytest.mark.anyio
async def test_pyjwt_verifier_enforces_explicit_non_access_token_required_claims(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    verifier = PyJWTVerifier(
        config=_jwt_config(
            "HS256",
            access_token_profile=False,
            required_claims=frozenset({"iss", "sub", "aud", "exp", "iat", "tenant"}),
        ),
        key=verification_key,
        require_key_id=False,
    )

    outcome = await verifier.verify(_encode_jwt(signing_key, "HS256", include_key_id=False), now=_JWT_NOW)

    assert outcome == InvalidCredentials()


@pytest.mark.anyio
async def test_pyjwt_verifier_accepts_non_access_profile_without_optional_access_claims(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    claims = _jwt_claims()
    claims.pop("client_id")
    claims.pop("jti")
    verifier = PyJWTVerifier(
        config=_jwt_config("HS256", access_token_profile=False, maximum_lifetime=None),
        key=verification_key,
        require_key_id=False,
    )

    outcome = await verifier.verify(
        _encode_jwt(signing_key, "HS256", claims=claims, include_key_id=False), now=_JWT_NOW
    )

    assert isinstance(outcome, Authenticated)
    assert outcome.claims.client_id is None
    assert outcome.claims.token_id is None


@pytest.mark.parametrize("claim", ["client_id", "jti"])
@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_malformed_optional_access_claims_in_non_access_profiles(
    claim: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    verifier = PyJWTVerifier(
        config=_jwt_config("HS256", access_token_profile=False), key=verification_key, require_key_id=False
    )

    outcome = await verifier.verify(
        _encode_jwt(signing_key, "HS256", claims=_jwt_claims(**{claim: 7}), include_key_id=False), now=_JWT_NOW
    )

    assert outcome == InvalidCredentials()


@pytest.mark.parametrize(
    ("token", "now"),
    [("malformed", _JWT_NOW), ("malformed", _JWT_NOW.replace(tzinfo=None))],
    ids=["malformed-compact", "naive-now"],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_invalid_verification_inputs(
    token: str, now: datetime, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=jwt_key_material["HS256"][1], require_key_id=False)

    assert await verifier.verify(token, now=now) == InvalidCredentials()


@pytest.mark.anyio
async def test_verified_claims_are_frozen_recursively_and_secret_safe(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    token = _encode_jwt(signing_key, "HS256", include_key_id=False)
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=verification_key, require_key_id=False)

    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert isinstance(outcome, Authenticated)
    claims = outcome.claims
    with pytest.raises(FrozenInstanceError):
        claims.subject = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        verifier.config.issuer = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        claims.raw["sub"] = "changed"  # type: ignore[index]
    metadata = claims.raw["metadata"]
    assert isinstance(metadata, Mapping)
    with pytest.raises(TypeError):
        metadata["groups"] = []  # type: ignore[index]
    assert tuple(metadata["groups"]) == ("finance", "operations")  # type: ignore[arg-type]
    assert token not in repr(claims)
    assert token not in repr(verifier)
    assert verification_key.decode() not in repr(verifier)


@pytest.mark.parametrize(
    ("algorithm", "key_name", "key"),
    [
        ("HS256", None, b"short"),
        ("EdDSA", None, b"not-an-ed25519-key"),
        ("ES256", "ES384", None),
        ("RS256", "RS1024", None),
        ("RS256", "ES256", None),
    ],
    ids=["short-hmac", "invalid-ed25519", "wrong-ec-curve", "weak-rsa", "algorithm-key-mismatch"],
)
def test_pyjwt_verifier_validates_fixed_keys_at_startup_without_secret_repr(
    algorithm: str, key_name: str | None, key: bytes | None, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    verification_key = key if key is not None else jwt_key_material[cast("str", key_name)][1]

    with pytest.raises(ImproperlyConfiguredException, match=algorithm):
        PyJWTVerifier(config=_jwt_config(algorithm), key=verification_key, require_key_id=algorithm != "HS256")


@pytest.mark.parametrize(
    ("algorithm", "key"),
    [
        ("RS256", {"kty": "RSA", "alg": "RS256", "use": "sig", "d": "private"}),
        ("RS256", {"kty": "RSA", "alg": "ES256", "use": "sig"}),
        ("RS256", {"kty": "RSA", "alg": "RS256", "use": "enc"}),
        ("RS256", {"kty": "RSA", "alg": "RS256", "use": "sig", "key_ops": ["sign"]}),
        ("RS256", {"kty": "RSA", "alg": "RS256", "use": "sig", "key_ops": ["verify", "sign"]}),
        ("ES256", {"kty": "RSA", "alg": "ES256", "use": "sig"}),
        ("HS256", {"kty": "oct", "alg": "HS256", "use": "sig"}),
    ],
    ids=[
        "private-member",
        "alg-mismatch",
        "wrong-use",
        "wrong-key-op",
        "mixed-key-ops",
        "wrong-key-type",
        "remote-hmac",
    ],
)
def test_pyjwt_verifier_rejects_untrusted_or_incompatible_jwk_metadata(algorithm: str, key: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=algorithm):
        PyJWTVerifier(
            config=_jwt_config(algorithm),
            key=key,  # type: ignore[arg-type]
            require_key_id=algorithm != "HS256",
        )


@pytest.mark.anyio
async def test_pyjwt_verifier_accepts_valid_public_jwk(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    signing_key, verification_key = jwt_key_material["RS256"]
    public_key = serialization.load_pem_public_key(verification_key)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    public_jwk.update({"alg": "RS256", "use": "sig"})
    verifier = PyJWTVerifier(config=_jwt_config("RS256"), key=public_jwk)

    outcome = await verifier.verify(_encode_jwt(signing_key, "RS256"), now=_JWT_NOW)

    assert isinstance(outcome, Authenticated)


@pytest.mark.anyio
async def test_pyjwt_verifier_accepts_subject_optional_logout_profile(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    payload = _jwt_claims()
    payload.pop("sub")
    payload["sid"] = "provider-session-1"
    config = _jwt_config(
        "HS256",
        access_token_profile=False,
        subject_required=False,
        required_claims=frozenset({"iss", "aud", "exp", "iat", "jti"}),
    )
    verifier = PyJWTVerifier(config=config, key=verification_key, require_key_id=False)

    outcome = await verifier.verify(
        _encode_jwt(signing_key, "HS256", claims=payload, include_key_id=False), now=_JWT_NOW
    )

    assert isinstance(outcome, Authenticated)
    assert outcome.claims.subject is None
    assert outcome.claims.raw["sid"] == "provider-session-1"


@pytest.mark.parametrize(
    ("algorithm", "prepared_key"),
    [
        ("ES256", ec.generate_private_key(ec.SECP384R1()).public_key()),
        ("EdDSA", ec.generate_private_key(ec.SECP256R1()).public_key()),
    ],
)
def test_pyjwt_verifier_rejects_incompatible_prepared_backend_keys(
    algorithm: str, prepared_key: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Algorithm:
        @staticmethod
        def prepare_key(_key: object) -> object:
            return prepared_key

    monkeypatch.setattr(jwt, "get_algorithm_by_name", lambda _algorithm: _Algorithm())

    with pytest.raises(ImproperlyConfiguredException, match=algorithm):
        PyJWTVerifier(config=_jwt_config(algorithm), key=b"configured-key")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"issuer": " "},
        {"audiences": frozenset()},
        {"algorithms": frozenset()},
        {"algorithms": frozenset({"none"})},
        {"clock_skew": timedelta(seconds=-1)},
        {"maximum_lifetime": timedelta(0)},
        {"required_claims": frozenset({" "})},
        {"token_types": frozenset()},
        {"subject_required": 1},
        {"subject_required": False},
    ],
)
def test_jwt_validation_config_rejects_unsafe_or_ambiguous_values(kwargs: dict[str, object]) -> None:
    values: dict[str, object] = {
        "issuer": _JWT_ISSUER,
        "audiences": frozenset({_JWT_AUDIENCE}),
        "algorithms": frozenset({"HS256"}),
    }
    values.update(kwargs)

    with pytest.raises(ImproperlyConfiguredException):
        JWTValidationConfig(**values)  # type: ignore[arg-type]


def test_pyjwt_verifier_rejects_non_positive_token_limit(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="maximum token bytes"):
        PyJWTVerifier(
            config=_jwt_config("HS256"), key=jwt_key_material["HS256"][1], require_key_id=False, maximum_token_bytes=0
        )


@pytest.mark.parametrize(
    ("error", "outcome_type"),
    [
        (jwt.InvalidTokenError("provider detail must not escape"), InvalidCredentials),
        (OSError("worker detail must not escape"), VerificationUnavailable),
    ],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_maps_and_sanitizes_verification_failures(
    error: Exception,
    outcome_type: type[InvalidCredentials] | type[VerificationUnavailable],
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    token = _encode_jwt(signing_key, "HS256", include_key_id=False)
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=verification_key, require_key_id=False)

    def fail_verification(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(jwt, "decode_complete", fail_verification)
    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert isinstance(outcome, outcome_type)
    assert "provider detail" not in repr(outcome)
    assert "worker detail" not in repr(outcome)


@pytest.mark.anyio
async def test_oidc_discovery_derives_one_exact_url_and_returns_pinned_metadata() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert str(request.url) == _OIDC_DISCOVERY_URL
        return _oidc_response(content_type="application/json; charset=utf-8")

    client, transport, resolver = _oidc_client(handler)

    metadata = await _discover_and_close(client)

    assert metadata == OIDCMetadata(
        issuer=_OIDC_ISSUER,
        jwks_uri=f"{_OIDC_ISSUER}/jwks",
        authorization_endpoint=f"{_OIDC_ISSUER}/authorize",
        token_endpoint=f"{_OIDC_ISSUER}/token",
        end_session_endpoint=f"{_OIDC_ISSUER}/logout",
        algorithms=frozenset({"EdDSA"}),
    )
    assert transport.was_closed is True
    assert transport.requests[0].url == httpx.URL(_OIDC_DISCOVERY_URL)
    assert ("issuer.example", 443) in resolver.calls
    with pytest.raises(FrozenInstanceError):
        metadata.issuer = "changed"  # type: ignore[misc]


@pytest.mark.anyio
async def test_oidc_discovery_client_context_returns_itself_and_closes_transport() -> None:
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response())

    async with client as entered:
        assert entered is client
        metadata = await entered.discover(_OIDC_ISSUER)

    assert metadata.issuer == _OIDC_ISSUER
    assert transport.was_closed is True


def test_discovery_policy_normalizes_configured_trust_boundaries_once() -> None:
    policy = DiscoveryPolicy(
        allowed_issuers=frozenset({"https://BÜCHER.example:443/", "https://EXAMPLE.com/tenant"}),
        allowed_jwks_origins=frozenset({"https://KEYS.example:443"}),
    )

    assert policy.allowed_issuers == frozenset({"https://xn--bcher-kva.example", "https://example.com/tenant"})
    assert policy.allowed_jwks_origins == frozenset({"https://keys.example"})
    with pytest.raises(FrozenInstanceError):
        policy.require_https = False  # type: ignore[misc]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"allowed_issuers": frozenset()},
        {"allowed_issuers": frozenset({""})},
        {"allowed_issuers": frozenset({7})},
        {"allowed_issuers": frozenset({"issuer.example"})},
        {"allowed_issuers": frozenset({"http://issuer.example"})},
        {"allowed_issuers": frozenset({"https://user@issuer.example"})},
        {"allowed_issuers": frozenset({"https://issuer.example?tenant=one"})},
        {"allowed_issuers": frozenset({"https://issuer.example#tenant"})},
        {"allowed_issuers": frozenset({"https://issuer.example:8443"})},
        {"allowed_issuers": frozenset({"https://issuer.example/tenant/"})},
        {"allowed_issuers": frozenset({"https://issuer.example/tenant/../other"})},
        {"allowed_issuers": frozenset({"https://issuer.example/tenant/%2e%2e/other"})},
        {
            "allowed_issuers": frozenset({_OIDC_ISSUER}),
            "allowed_jwks_origins": frozenset({"https://keys.example/path"}),
        },
        {"allowed_issuers": frozenset({_OIDC_ISSUER}), "allowed_ports": frozenset()},
        {"allowed_issuers": frozenset({_OIDC_ISSUER}), "allowed_ports": frozenset({0})},
        {"allowed_issuers": frozenset({_OIDC_ISSUER}), "connect_timeout": 0},
        {"allowed_issuers": frozenset({_OIDC_ISSUER}), "read_timeout": -1},
        {"allowed_issuers": frozenset({_OIDC_ISSUER}), "maximum_document_bytes": 0},
    ],
    ids=[
        "empty-allowlist",
        "empty-url",
        "non-string-url",
        "relative",
        "http",
        "userinfo",
        "query",
        "fragment",
        "port",
        "non-root-trailing-slash",
        "dot-segment",
        "encoded-dot-segment",
        "jwks-origin-path",
        "empty-ports",
        "invalid-port",
        "connect-timeout",
        "read-timeout",
        "body-limit",
    ],
)
def test_discovery_policy_rejects_ambiguous_or_unsafe_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        DiscoveryPolicy(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "algorithms",
    [frozenset(), frozenset({"none"}), frozenset({""}), frozenset({" RS256"}), frozenset({7})],
    ids=["empty", "unsupported", "empty-member", "unnormalized", "non-string"],
)
def test_oidc_discovery_client_rejects_invalid_pinned_algorithms(algorithms: frozenset[object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        OIDCDiscoveryClient(
            policy=DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER})),
            algorithms=algorithms,  # type: ignore[arg-type]
            transport=_RecordingMockTransport(lambda _request: _oidc_response()),
            resolver=_FakeOIDCResolver({"issuer.example": (_OIDC_PUBLIC_IP,)}),
        )


@pytest.mark.parametrize(
    "issuer",
    ["https://issuer.example/tenant/", "https://issuer.example/other", "https://unconfigured.example/tenant"],
    ids=["trailing-slash", "different-path", "different-host"],
)
@pytest.mark.anyio
async def test_oidc_discovery_rejects_non_exact_issuer_without_dns_or_network(issuer: str) -> None:
    def fail_request(_request: httpx.Request) -> httpx.Response:
        msg = "Discovery transport must not run"
        raise AssertionError(msg)

    client, transport, resolver = _oidc_client(fail_request, answers={})

    with pytest.raises(ImproperlyConfiguredException):
        await _discover_and_close(client, issuer)

    assert transport.requests == []
    assert resolver.calls == []


@pytest.mark.parametrize("issuer", ["https://ISSUER.example/tenant", "https://issuer.example:443/tenant"])
@pytest.mark.anyio
async def test_oidc_discovery_canonicalizes_equivalent_allowed_issuer_forms(issuer: str) -> None:
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response())

    metadata = await _discover_and_close(client, issuer)

    assert metadata.issuer == _OIDC_ISSUER
    assert transport.requests[0].url == httpx.URL(_OIDC_DISCOVERY_URL)


@pytest.mark.parametrize(
    ("addresses", "accepted"),
    [
        (("93.184.216.34",), True),
        (("2001:4860:4860::8888",), True),
        (("93.184.216.34", "10.0.0.1"), False),
        (("127.0.0.1",), False),
        (("10.0.0.1",), False),
        (("172.16.0.1",), False),
        (("192.168.0.1",), False),
        (("169.254.1.1",), False),
        (("224.0.0.1",), False),
        (("0.0.0.0",), False),  # noqa: S104 - SSRF rejection fixture
        (("240.0.0.1",), False),
        (("::1",), False),
        (("fc00::1",), False),
        (("fe80::1",), False),
        (("ff00::1",), False),
        (("::",), False),
        (("::ffff:10.0.0.1",), False),
        (("not-an-ip",), False),
    ],
    ids=[
        "public-ipv4",
        "public-ipv6",
        "mixed-public-private",
        "loopback-v4",
        "private-10",
        "private-172",
        "private-192",
        "link-local-v4",
        "multicast-v4",
        "unspecified-v4",
        "reserved-v4",
        "loopback-v6",
        "private-v6",
        "link-local-v6",
        "multicast-v6",
        "unspecified-v6",
        "mapped-private-v4",
        "malformed-answer",
    ],
)
@pytest.mark.anyio
async def test_oidc_discovery_classifies_every_dns_answer(addresses: tuple[str, ...], *, accepted: bool) -> None:
    client, transport, _resolver = _oidc_client(
        lambda _request: _oidc_response(), answers={"issuer.example": addresses}
    )

    if accepted:
        metadata = await _discover_and_close(client)
        assert metadata.issuer == _OIDC_ISSUER
        assert len(transport.requests) == 1
    else:
        with pytest.raises(OIDCDiscoveryError):
            await _discover_and_close(client)
        assert transport.requests == []


@pytest.mark.anyio
async def test_oidc_discovery_maps_resolver_runtime_failures_without_network() -> None:
    async def fail_resolution(_hostname: str, _port: int) -> tuple[str, ...]:
        message = "resolver detail must not escape"
        raise RuntimeError(message)

    transport = _RecordingMockTransport(lambda _request: _oidc_response())
    client = OIDCDiscoveryClient(
        policy=DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER})),
        algorithms=frozenset({"EdDSA"}),
        transport=transport,
        resolver=fail_resolution,
    )

    with pytest.raises(OIDCDiscoveryError) as exc_info:
        await _discover_and_close(client)

    assert transport.requests == []
    assert "resolver detail" not in repr(exc_info.value)


@pytest.mark.anyio
async def test_oidc_discovery_rejects_an_empty_dns_result_without_network() -> None:
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response(), answers={"issuer.example": ()})

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)

    assert transport.requests == []


@pytest.mark.anyio
async def test_oidc_discovery_classifies_literal_public_ip_without_resolving() -> None:
    issuer = "https://93.184.216.34"
    resolver_calls: list[tuple[str, int]] = []

    async def fail_if_resolved(hostname: str, port: int) -> tuple[str, ...]:
        resolver_calls.append((hostname, port))
        message = "Literal addresses must not reach DNS"
        raise AssertionError(message)

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == f"{issuer}/.well-known/openid-configuration"
        return _oidc_response(
            _oidc_document(
                issuer=issuer,
                jwks_uri=f"{issuer}/jwks",
                authorization_endpoint=None,
                token_endpoint=None,
                end_session_endpoint=None,
            )
        )

    transport = _RecordingMockTransport(handler)
    client = OIDCDiscoveryClient(
        policy=DiscoveryPolicy(allowed_issuers=frozenset({issuer})),
        algorithms=frozenset({"EdDSA"}),
        transport=transport,
        resolver=fail_if_resolved,
    )

    metadata = await _discover_and_close(client, issuer)

    assert metadata.issuer == issuer
    assert resolver_calls == []


@pytest.mark.anyio
async def test_oidc_discovery_default_resolver_deduplicates_getaddrinfo_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int, int]] = []

    async def fake_getaddrinfo(host: str, port: int, **kwargs: int) -> list[tuple[object, ...]]:
        calls.append((host, port, kwargs["type"]))
        address = (_OIDC_PUBLIC_IP, port)
        return [(object(), object(), object(), "", address), (object(), object(), object(), "", address)]

    monkeypatch.setattr(oidc_urls, "getaddrinfo", fake_getaddrinfo)
    transport = _RecordingMockTransport(lambda _request: _oidc_response())
    client = OIDCDiscoveryClient(
        policy=DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER})),
        algorithms=frozenset({"EdDSA"}),
        transport=transport,
    )

    metadata = await _discover_and_close(client)

    assert metadata.issuer == _OIDC_ISSUER
    assert calls == [("issuer.example", 443, oidc_urls.socket.SOCK_STREAM)]


@pytest.mark.anyio
async def test_oidc_discovery_allows_explicit_controlled_private_keycloak_hosts() -> None:
    issuer = "http://keycloak.internal:8080/realms/application"
    policy = DiscoveryPolicy(
        allowed_issuers=frozenset({issuer}),
        require_https=False,
        allow_private_hosts=True,
        allowed_ports=frozenset({8080}),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == f"{issuer}/.well-known/openid-configuration"
        return _oidc_response(
            _oidc_document(
                issuer=issuer,
                jwks_uri=f"{issuer}/protocol/openid-connect/certs",
                authorization_endpoint=None,
                token_endpoint=None,
                end_session_endpoint=None,
            )
        )

    client, _transport, _resolver = _oidc_client(handler, policy=policy, answers={"keycloak.internal": ("10.0.0.10",)})

    metadata = await _discover_and_close(client, issuer)

    assert metadata.issuer == issuer
    assert metadata.jwks_uri == f"{issuer}/protocol/openid-connect/certs"


@pytest.mark.parametrize("allowed", [False, True])
@pytest.mark.anyio
async def test_oidc_discovery_requires_explicit_cross_origin_jwks(*, allowed: bool) -> None:
    policy = DiscoveryPolicy(
        allowed_issuers=frozenset({_OIDC_ISSUER}),
        allowed_jwks_origins=frozenset({"https://keys.example"}) if allowed else frozenset(),
    )
    client, _transport, resolver = _oidc_client(
        lambda _request: _oidc_response(_oidc_document(jwks_uri="https://keys.example/jwks")), policy=policy
    )

    if allowed:
        metadata = await _discover_and_close(client)
        assert metadata.jwks_uri == "https://keys.example/jwks"
        assert ("keys.example", 443) in resolver.calls
    else:
        with pytest.raises(OIDCDiscoveryError):
            await _discover_and_close(client)
        assert resolver.calls == [("issuer.example", 443)]


@pytest.mark.parametrize(
    ("jwks_uri", "answers"),
    [
        ("http://issuer.example/tenant/jwks", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://issuer.example:8443/tenant/jwks", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://user@issuer.example/tenant/jwks", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://issuer.example/tenant/jwks?version=1", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://issuer.example/tenant/jwks#keys", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://issuer.example/tenant/../jwks", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://private.example/jwks", {"issuer.example": (_OIDC_PUBLIC_IP,), "private.example": ("192.168.1.10",)}),
    ],
    ids=["http", "port", "userinfo", "query", "fragment", "dot-segment", "private-dns"],
)
@pytest.mark.anyio
async def test_oidc_discovery_revalidates_untrusted_jwks_targets(
    jwks_uri: str, answers: Mapping[str, tuple[str, ...]]
) -> None:
    allowed_origins = frozenset({"https://private.example"}) if "private.example" in jwks_uri else frozenset()
    policy = DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER}), allowed_jwks_origins=allowed_origins)
    client, _transport, _resolver = _oidc_client(
        lambda _request: _oidc_response(_oidc_document(jwks_uri=jwks_uri)), policy=policy, answers=answers
    )

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.anyio
async def test_oidc_discovery_refuses_redirects_without_following_location() -> None:
    client, transport, resolver = _oidc_client(
        lambda _request: httpx.Response(302, headers={"location": "https://private.example/metadata"}),
        answers={"issuer.example": (_OIDC_PUBLIC_IP,)},
    )

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)

    assert len(transport.requests) == 1
    assert resolver.calls == [("issuer.example", 443)]


@pytest.mark.anyio
async def test_oidc_discovery_ignores_proxy_environment_with_injected_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8080")
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response())

    metadata = await _discover_and_close(client)

    assert metadata.issuer == _OIDC_ISSUER
    assert len(transport.requests) == 1


@pytest.mark.anyio
async def test_oidc_discovery_requests_identity_response_encoding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept-encoding"] == "identity"
        return _oidc_response()

    client, _transport, _resolver = _oidc_client(handler)

    metadata = await _discover_and_close(client)

    assert metadata.issuer == _OIDC_ISSUER


@pytest.mark.anyio
async def test_oidc_discovery_rejects_compressed_response_before_decoding() -> None:
    encoded = json.dumps(_oidc_document(), separators=(",", ":")).encode()
    stream = _ChunkedOIDCStream(gzip.compress(encoded))
    response = httpx.Response(
        200, headers={"content-type": "application/json", "content-encoding": "gzip"}, stream=stream
    )
    client, _transport, _resolver = _oidc_client(lambda _request: response)

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)

    assert stream.was_iterated is False


@pytest.mark.anyio
async def test_oidc_discovery_checks_streaming_capacity_before_extending(monkeypatch: pytest.MonkeyPatch) -> None:
    class _CapacityCheckedBytearray(bytearray):
        def extend(self, chunk: bytes) -> None:
            if len(self) + len(chunk) > 64:
                message = "Streaming chunk was appended before its size was checked"
                raise AssertionError(message)
            super().extend(chunk)

    monkeypatch.setattr(oidc_discovery, "bytearray", _CapacityCheckedBytearray, raising=False)
    policy = DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER}), maximum_document_bytes=64)
    response = httpx.Response(
        200, headers={"content-type": "application/json"}, stream=_ChunkedOIDCStream(b"x" * 40, b"x" * 40)
    )
    client, _transport, _resolver = _oidc_client(lambda _request: response, policy=policy)

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.anyio
async def test_oidc_discovery_enforces_streaming_body_limit_without_content_length() -> None:
    policy = DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER}), maximum_document_bytes=64)
    response = httpx.Response(
        200, headers={"content-type": "application/json"}, stream=_ChunkedOIDCStream(b"x" * 40, b"x" * 40)
    )
    assert "content-length" not in response.headers
    client, _transport, _resolver = _oidc_client(lambda _request: response, policy=policy)

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.anyio
async def test_oidc_discovery_rejects_excessive_json_depth() -> None:
    nested: object = None
    for _ in range(65):
        nested = {"nested": nested}
    document = _oidc_document(extension=nested)
    client, _transport, _resolver = _oidc_client(lambda _request: _oidc_response(document))

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.parametrize(
    ("response", "case"),
    [
        (httpx.Response(404, json={"error": "missing"}), "status-4xx"),
        (httpx.Response(503, json={"error": "unavailable"}), "status-5xx"),
        (_oidc_response(content_type=None), "missing-content-type"),
        (_oidc_response(content_type="text/plain"), "wrong-content-type"),
        (_oidc_response(content=b"{"), "invalid-json"),
        (_oidc_response(content=b'{"issuer":"one","issuer":"two"}'), "duplicate-json-member"),
        (_oidc_response(content=b"[]"), "non-object-json"),
        (_oidc_response(content=b'{"unsupported":NaN}'), "non-finite-json"),
        (_oidc_response(content=b"x" * 65_537), "body-limit"),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
@pytest.mark.anyio
async def test_oidc_discovery_rejects_untrusted_http_or_document_shapes(response: httpx.Response, case: str) -> None:
    del case
    client, _transport, _resolver = _oidc_client(lambda _request: response)

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.parametrize(
    "document",
    [
        _oidc_document(issuer="https://issuer.examp\u043be/tenant"),
        {key: value for key, value in _oidc_document().items() if key != "issuer"},
        {key: value for key, value in _oidc_document().items() if key != "jwks_uri"},
        _oidc_document(issuer=7),
        _oidc_document(jwks_uri=["https://issuer.example/jwks"]),
        _oidc_document(authorization_endpoint=7),
        _oidc_document(token_endpoint=[]),
        _oidc_document(end_session_endpoint={}),
        _oidc_document(id_token_signing_alg_values_supported="EdDSA"),  # noqa: S106 - algorithm type fixture
        _oidc_document(id_token_signing_alg_values_supported=["EdDSA", 7]),
        _oidc_document(id_token_signing_alg_values_supported=[]),
        _oidc_document(id_token_signing_alg_values_supported=["RS256"]),
    ],
    ids=[
        "issuer-mismatch",
        "missing-issuer",
        "missing-jwks-uri",
        "issuer-type",
        "jwks-type",
        "authorization-endpoint-type",
        "token-endpoint-type",
        "end-session-endpoint-type",
        "algorithm-type",
        "algorithm-member-type",
        "empty-provider-algorithms",
        "empty-pinned-intersection",
    ],
)
@pytest.mark.anyio
async def test_oidc_discovery_rejects_mismatched_or_unsupported_metadata(document: dict[str, object]) -> None:
    client, _transport, _resolver = _oidc_client(lambda _request: _oidc_response(document))

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.anyio
async def test_oidc_discovery_preserves_absent_optional_endpoints() -> None:
    client, _transport, _resolver = _oidc_client(
        lambda _request: _oidc_response(
            _oidc_document(authorization_endpoint=None, token_endpoint=None, end_session_endpoint=None)
        )
    )

    metadata = await _discover_and_close(client)

    assert metadata.authorization_endpoint is None
    assert metadata.token_endpoint is None
    assert metadata.end_session_endpoint is None


@pytest.mark.parametrize(
    ("field", "value", "answers"),
    [
        ("authorization_endpoint", "/authorize", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("token_endpoint", "http://issuer.example/token", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("end_session_endpoint", "https://user@issuer.example/logout", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        (
            "authorization_endpoint",
            "https://issuer.example/authorize?prompt=login",
            {"issuer.example": (_OIDC_PUBLIC_IP,)},
        ),
        ("token_endpoint", "https://issuer.example/token#fragment", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("end_session_endpoint", "https://issuer.example/tenant/../logout", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        (
            "token_endpoint",
            "https://private.example/token",
            {"issuer.example": (_OIDC_PUBLIC_IP,), "private.example": ("10.0.0.10",)},
        ),
    ],
    ids=["relative", "http", "userinfo", "query", "fragment", "dot-segment", "private-dns"],
)
@pytest.mark.anyio
async def test_oidc_discovery_rejects_unsafe_optional_endpoint_urls(
    field: str, value: str, answers: Mapping[str, tuple[str, ...]]
) -> None:
    client, _transport, _resolver = _oidc_client(
        lambda _request: _oidc_response(_oidc_document(**{field: value})), answers=answers
    )

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.anyio
async def test_oidc_discovery_allows_public_cross_origin_optional_endpoints() -> None:
    endpoints = {
        "authorization_endpoint": "https://login.example/authorize",
        "token_endpoint": "https://login.example/token",
        "end_session_endpoint": "https://login.example/logout",
    }
    client, _transport, resolver = _oidc_client(
        lambda _request: _oidc_response(_oidc_document(**endpoints)),
        answers={"issuer.example": (_OIDC_PUBLIC_IP,), "login.example": (_OIDC_PUBLIC_IP,)},
    )

    metadata = await _discover_and_close(client)

    assert metadata.authorization_endpoint == endpoints["authorization_endpoint"]
    assert metadata.token_endpoint == endpoints["token_endpoint"]
    assert metadata.end_session_endpoint == endpoints["end_session_endpoint"]
    assert ("login.example", 443) in resolver.calls


@pytest.mark.anyio
async def test_oidc_discovery_sanitizes_transport_failures() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        message = "internal-host.example must not escape"
        raise httpx.ConnectError(message, request=request)

    client, _transport, _resolver = _oidc_client(fail)

    with pytest.raises(OIDCDiscoveryError) as exc_info:
        await _discover_and_close(client)

    assert "internal-host.example" not in repr(exc_info.value)


@pytest.mark.anyio
async def test_oidc_discovery_close_is_idempotent_and_closes_injected_transport() -> None:
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response())

    await client.aclose()
    await client.aclose()

    assert transport.was_closed is True
    with pytest.raises(OIDCDiscoveryError):
        await client.discover(_OIDC_ISSUER)


def test_jwks_public_cache_contracts_are_frozen_and_fetcher_is_runtime_checkable() -> None:
    policy = JWKSCachePolicy()
    request = JWKSFetchRequest(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI, etag=None)
    response = JWKSFetchResponse(status_code=304, body=b"", headers={"cache-control": "max-age=60"})
    default_response = JWKSFetchResponse(status_code=304)
    entry = _jwks_entry()
    fetcher = _RecordingJWKSFetcher(response)

    assert isinstance(fetcher, AsyncJWKSFetcher)
    assert policy.default_ttl == timedelta(minutes=15)
    assert policy.minimum_ttl == timedelta(seconds=30)
    assert policy.maximum_ttl == timedelta(hours=24)
    assert policy.unknown_kid_cooldown == timedelta(seconds=30)
    assert policy.stale_if_error == timedelta(0)
    assert policy.warm_on_startup is False
    assert policy.maximum_unknown_keys == 1024
    assert default_response.body == b""
    assert default_response.headers == {}
    with pytest.raises(FrozenInstanceError):
        request.etag = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        entry.issuer = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        response.headers["cache-control"] = "changed"  # type: ignore[index]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"default_ttl": 30},
        {"default_ttl": timedelta(0)},
        {"minimum_ttl": timedelta(0)},
        {"maximum_ttl": timedelta(0)},
        {"minimum_ttl": timedelta(minutes=2), "maximum_ttl": timedelta(minutes=1)},
        {"default_ttl": timedelta(seconds=29)},
        {"default_ttl": timedelta(hours=25)},
        {"unknown_kid_cooldown": timedelta(0)},
        {"stale_if_error": timedelta(seconds=-1)},
        {"warm_on_startup": 1},
        {"maximum_document_bytes": 0},
        {"maximum_document_bytes": True},
        {"maximum_document_bytes": 1_048_577},
        {"maximum_keys": 0},
        {"maximum_keys": True},
        {"maximum_keys": 129},
        {"maximum_unknown_keys": 0},
        {"maximum_unknown_keys": True},
    ],
    ids=[
        "duration-type",
        "default-ttl",
        "minimum-ttl",
        "maximum-ttl",
        "ttl-order",
        "default-below-minimum",
        "default-above-maximum",
        "unknown-kid-cooldown",
        "negative-stale",
        "warmup-type",
        "document-bytes-zero",
        "document-bytes-bool",
        "document-bytes-maximum",
        "keys-zero",
        "keys-bool",
        "keys-maximum",
        "unknown-keys-zero",
        "unknown-keys-bool",
    ],
)
def test_jwks_cache_policy_rejects_unsafe_bounds(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        JWKSCachePolicy(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status_code": True},
        {"status_code": 99},
        {"status_code": 600},
        {"status_code": 200, "body": "body"},
        {"status_code": 200, "headers": {1: "value"}},
        {"status_code": 200, "headers": {"": "value"}},
        {"status_code": 200, "headers": {"name": 1}},
        {"status_code": 200, "headers": object()},
    ],
    ids=[
        "status-bool",
        "status-low",
        "status-high",
        "body-type",
        "header-name-type",
        "header-name-empty",
        "header-value-type",
        "header-mapping-type",
    ],
)
def test_jwks_fetch_response_rejects_invalid_transport_values(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        JWKSFetchResponse(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "factory",
    [
        lambda: JWKSCacheEntry(issuer=" ", jwks_uri=_JWKS_URI, algorithms=frozenset({"EdDSA"})),
        lambda: JWKSCacheEntry(issuer=_JWT_ISSUER, jwks_uri=" ", algorithms=frozenset({"EdDSA"})),
        lambda: JWKSCacheEntry(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI, algorithms=frozenset()),
        lambda: JWKSCacheEntry(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI, algorithms=frozenset({"none"})),
        lambda: CachedJWKSProvider(entries=(), fetcher=_RecordingJWKSFetcher()),
        lambda: CachedJWKSProvider(entries=(_jwks_entry(), _jwks_entry()), fetcher=_RecordingJWKSFetcher()),
        lambda: CachedJWKSProvider(
            entries=(object(),),  # type: ignore[arg-type]
            fetcher=_RecordingJWKSFetcher(),
        ),
        lambda: CachedJWKSProvider(
            entries=(_jwks_entry(),),
            fetcher=object(),  # type: ignore[arg-type]
        ),
    ],
    ids=[
        "issuer",
        "uri",
        "empty-algorithms",
        "unsupported-algorithm",
        "empty-entries",
        "duplicate-entry",
        "entry-type",
        "fetcher-type",
    ],
)
def test_jwks_provider_rejects_invalid_configured_entries(factory: Callable[[], object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        factory()


@pytest.mark.anyio
async def test_jwks_cold_load_uses_default_ttl_and_fresh_hit_does_no_fetch(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, etag='"generation-1"'), _jwks_response(jwk, etag='"generation-2"')
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    cold = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    fresh = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(minutes=14, seconds=59)
    )
    boundary = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(minutes=15))

    assert isinstance(cold, VerificationKey)
    assert fresh is cold
    assert isinstance(boundary, VerificationKey)
    assert fetcher.requests == [
        JWKSFetchRequest(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI, etag=None),
        JWKSFetchRequest(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI, etag='"generation-1"'),
    ]


@pytest.mark.parametrize("cache_state", ["cold", "expired"])
@pytest.mark.anyio
async def test_jwks_concurrent_callers_share_one_refresh(
    cache_state: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    expired = cache_state == "expired"
    jwk = _verification_jwk(jwt_key_material)
    response = _jwks_response(jwk, cache_control="max-age=30", etag='"generation-1"')
    fetcher = _BlockingJWKSFetcher(
        response, response, immediate_calls=1 if expired else 0, maximum_calls=2 if expired else 1
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)
    now = _JWT_NOW
    if expired:
        assert isinstance(await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=now), VerificationKey)
        now += timedelta(seconds=30)
    outcomes: list[object | None] = [None] * 100

    async def select(index: int) -> None:
        outcomes[index] = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=now)

    async with create_task_group() as task_group:
        for index in range(len(outcomes)):
            task_group.start_soon(select, index)
        await fetcher.started.wait()
        await checkpoint()
        fetcher.release.set()

    expected_fetches = 2 if expired else 1
    assert len(fetcher.requests) == expected_fetches
    assert isinstance(outcomes[0], VerificationKey)
    assert all(outcome is outcomes[0] for outcome in outcomes)


@pytest.mark.anyio
async def test_jwks_cancelling_one_waiter_preserves_shared_refresh(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    fetcher = _BlockingJWKSFetcher(_jwks_response(_verification_jwk(jwt_key_material), cache_control="max-age=60"))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)
    cancelled_scope: list[CancelScope] = []
    cancelled_outcomes: list[object] = []
    survivor_outcomes: list[object] = []
    survivor_started = Event()
    cancelled_finished = Event()

    async def cancelled_waiter() -> None:
        try:
            with CancelScope() as scope:
                cancelled_scope.append(scope)
                cancelled_outcomes.append(
                    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
                )
        finally:
            cancelled_finished.set()

    async def survivor() -> None:
        survivor_started.set()
        survivor_outcomes.append(await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW))

    async with create_task_group() as task_group:
        task_group.start_soon(cancelled_waiter)
        await fetcher.started.wait()
        task_group.start_soon(survivor)
        await survivor_started.wait()
        await checkpoint()
        cancelled_scope[0].cancel()
        with fail_after(1):
            await cancelled_finished.wait()
        assert fetcher.active == 1
        fetcher.release.set()

    assert cancelled_outcomes == []
    assert len(fetcher.requests) == 1
    assert len(survivor_outcomes) == 1
    assert isinstance(survivor_outcomes[0], VerificationKey)


@pytest.mark.anyio
async def test_jwks_independent_issuer_refreshes_proceed_concurrently(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    second_issuer = "https://issuer-two.example"
    second_uri = f"{second_issuer}/jwks"
    first = _verification_jwk(jwt_key_material, "EdDSA", "first")
    second = _verification_jwk(jwt_key_material, "ES256", "second")

    def respond(request: JWKSFetchRequest) -> JWKSFetchResponse:
        return _jwks_response(first if request.issuer == _JWT_ISSUER else second, cache_control="max-age=60")

    fetcher = _BlockingJWKSFetcher(respond, respond, maximum_calls=2, issuers=(_JWT_ISSUER, second_issuer))
    provider = CachedJWKSProvider(
        entries=(_jwks_entry(), _jwks_entry(second_issuer, second_uri, frozenset({"ES256"}))), fetcher=fetcher
    )
    outcomes: list[object] = []

    async def select(issuer: str, uri: str, kid: str, algorithm: str) -> None:
        outcomes.append(await provider.select_key(issuer, uri, kid, algorithm, now=_JWT_NOW))

    async with create_task_group() as task_group:
        task_group.start_soon(select, _JWT_ISSUER, _JWKS_URI, "first", "EdDSA")
        await fetcher.started_by_issuer[_JWT_ISSUER].wait()
        task_group.start_soon(select, second_issuer, second_uri, "second", "ES256")
        with fail_after(1):
            await fetcher.started_by_issuer[second_issuer].wait()
        fetcher.release.set()

    assert len(fetcher.requests) == 2
    assert {outcome.algorithm for outcome in outcomes if isinstance(outcome, VerificationKey)} == {"EdDSA", "ES256"}


@pytest.mark.anyio
async def test_jwks_fresh_unknown_key_forces_one_refresh_and_retries(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="known")
    rotated = _verification_jwk(jwt_key_material, key_id="rotated")
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=60", etag='"generation-1"'),
        _jwks_response(known, rotated, cache_control="max-age=60", etag='"generation-2"'),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "rotated", "EdDSA", now=_JWT_NOW + timedelta(seconds=1))

    assert isinstance(outcome, VerificationKey)
    assert outcome.key_id == "rotated"
    assert len(fetcher.requests) == 2


@pytest.mark.anyio
async def test_jwks_unknown_selection_negative_cache_is_per_generation_tuple(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="shared")
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=60", etag='"generation-1"'),
        JWKSFetchResponse(status_code=304, headers={"cache-control": "max-age=60"}),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(algorithms=frozenset({"EdDSA", "ES256"})),), fetcher=fetcher)

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "shared", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    first = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "shared", "ES256", now=_JWT_NOW + timedelta(seconds=1))
    second = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "shared", "ES256", now=_JWT_NOW + timedelta(seconds=2))
    valid_tuple = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "shared", "EdDSA", now=_JWT_NOW + timedelta(seconds=2)
    )

    assert isinstance(first, InvalidCredentials)
    assert isinstance(second, InvalidCredentials)
    assert isinstance(valid_tuple, VerificationKey)
    assert len(fetcher.requests) == 2


@pytest.mark.anyio
async def test_jwks_expired_unknown_selection_is_cached_after_refresh(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="known")
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=30", etag='"generation-1"'),
        JWKSFetchResponse(status_code=304, headers={"cache-control": "max-age=60"}),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    outcome = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=30)
    )
    repeated = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=31)
    )

    assert isinstance(outcome, InvalidCredentials)
    assert isinstance(repeated, InvalidCredentials)
    assert len(fetcher.requests) == 2


@pytest.mark.anyio
async def test_jwks_failed_forced_refresh_is_generation_limited_and_prunes_expired_negative(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="known")
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=60", etag='"generation-1"'), OSError("temporary")
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    failed = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=1))
    suppressed = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=2)
    )
    after_cooldown = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=32)
    )

    assert isinstance(failed, VerificationUnavailable)
    assert isinstance(suppressed, InvalidCredentials)
    assert isinstance(after_cooldown, InvalidCredentials)
    assert len(fetcher.requests) == 2


@pytest.mark.anyio
async def test_jwks_generation_replacement_invalidates_unknown_key_negatives(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="known")
    replacement = _verification_jwk(jwt_key_material, key_id="replacement")
    formerly_unknown = _verification_jwk(jwt_key_material, key_id="absent")
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=30", etag='"generation-1"'),
        JWKSFetchResponse(status_code=304, headers={"cache-control": "max-age=30"}),
        _jwks_response(replacement, cache_control="max-age=30", etag='"generation-2"'),
        _jwks_response(replacement, formerly_unknown, cache_control="max-age=30", etag='"generation-3"'),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "absent", "EdDSA", now=_JWT_NOW + timedelta(seconds=1)),
        InvalidCredentials,
    )
    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "replacement", "EdDSA", now=_JWT_NOW + timedelta(seconds=31)),
        VerificationKey,
    )
    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "absent", "EdDSA", now=_JWT_NOW + timedelta(seconds=32))

    assert isinstance(outcome, VerificationKey)
    assert len(fetcher.requests) == 4


@pytest.mark.anyio
async def test_jwks_unknown_key_negative_cache_is_bounded_lru(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="known")
    not_modified = JWKSFetchResponse(status_code=304, headers={"cache-control": "max-age=60"})
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=60", etag='"generation-1"'), *(not_modified for _ in range(5))
    )
    provider = CachedJWKSProvider(
        entries=(_jwks_entry(),), fetcher=fetcher, policy=JWKSCachePolicy(maximum_unknown_keys=3)
    )

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    for kid in ("unknown-a", "unknown-b", "unknown-c", "unknown-d"):
        assert isinstance(
            await provider.select_key(_JWT_ISSUER, _JWKS_URI, kid, "EdDSA", now=_JWT_NOW + timedelta(seconds=1)),
            InvalidCredentials,
        )
    state = cast("Any", provider)._entries[(_JWT_ISSUER, _JWKS_URI)]  # noqa: SLF001
    assert tuple((generation, kid, algorithm) for generation, kid, algorithm in state.negative) == (
        (1, "unknown-b", "EdDSA"),
        (1, "unknown-c", "EdDSA"),
        (1, "unknown-d", "EdDSA"),
    )
    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "unknown-a", "EdDSA", now=_JWT_NOW + timedelta(seconds=2)),
        InvalidCredentials,
    )

    assert len(state.negative) == 3
    assert tuple(key[1] for key in state.negative) == ("unknown-c", "unknown-d", "unknown-a")
    assert len(fetcher.requests) == 2


@pytest.mark.anyio
async def test_jwks_shared_refresh_failure_is_consistent_for_all_waiters(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    del jwt_key_material
    fetcher = _BlockingJWKSFetcher(OSError("shared fetch detail"))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)
    outcomes: list[object | None] = [None] * 100

    async def select(index: int) -> None:
        outcomes[index] = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    async with create_task_group() as task_group:
        for index in range(len(outcomes)):
            task_group.start_soon(select, index)
        await fetcher.started.wait()
        await checkpoint()
        fetcher.release.set()

    assert len(fetcher.requests) == 1
    assert isinstance(outcomes[0], VerificationUnavailable)
    assert all(outcome is outcomes[0] for outcome in outcomes)


@pytest.mark.anyio
async def test_jwks_pending_refresh_cancellation_is_sanitized() -> None:
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=_RecordingJWKSFetcher())
    cancelled_task = asyncio.create_task(checkpoint())
    cancelled_task.cancel()
    await checkpoint()
    state = cast("Any", provider)._entries[(_JWT_ISSUER, _JWKS_URI)]  # noqa: SLF001
    state.refresh = SimpleNamespace(task=cancelled_task)

    outcome = await cast("Any", provider)._refresh_singleflight(state, _JWT_NOW)  # noqa: SLF001

    assert isinstance(outcome, VerificationUnavailable)
    await provider.aclose()


@pytest.mark.anyio
async def test_jwks_close_cancels_and_awaits_live_refresh_tasks(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    fetcher = _BlockingJWKSFetcher(_jwks_response(_verification_jwk(jwt_key_material)))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    async def select() -> None:
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    async with create_task_group() as task_group:
        task_group.start_soon(select)
        await fetcher.started.wait()
        task_group.start_soon(provider.aclose)
        with fail_after(1):
            await fetcher.finished.wait()

    assert fetcher.active == 0
    assert fetcher.cancelled == 1
    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW), VerificationUnavailable
    )


@pytest.mark.parametrize(
    ("cache_control", "fresh_offset", "expired_offset"),
    [
        ("public, max-age=1", timedelta(seconds=29), timedelta(seconds=30)),
        ("max-age=999999", timedelta(minutes=59, seconds=59), timedelta(hours=1)),
        ("public, malformed=value", timedelta(minutes=14, seconds=59), timedelta(minutes=15)),
    ],
    ids=["minimum-clamp", "maximum-clamp", "default-fallback"],
)
@pytest.mark.anyio
async def test_jwks_cache_control_ttl_is_clamped_or_defaults(
    cache_control: str,
    fresh_offset: timedelta,
    expired_offset: timedelta,
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    policy = JWKSCachePolicy(maximum_ttl=timedelta(hours=1))
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control=cache_control), _jwks_response(jwk, cache_control=cache_control)
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher, policy=policy)

    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + fresh_offset)
    assert len(fetcher.requests) == 1

    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + expired_offset)
    assert len(fetcher.requests) == 2


@pytest.mark.parametrize("directive", ["no-cache", "no-store"])
@pytest.mark.anyio
async def test_jwks_no_cache_and_no_store_revalidate_immediately(
    directive: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control=directive, etag='"generation-1"'),
        _jwks_response(jwk, cache_control="max-age=60", etag='"generation-2"'),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    first = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    second = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    assert isinstance(first, VerificationKey)
    assert isinstance(second, VerificationKey)
    assert len(fetcher.requests) == 2
    assert fetcher.requests[1].etag == '"generation-1"'


@pytest.mark.anyio
async def test_jwks_conditional_304_retains_snapshot_and_recomputes_freshness(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control="max-age=30", etag='"generation-1"'),
        JWKSFetchResponse(status_code=304, body=b"", headers={"cache-control": "max-age=60"}),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    original = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    retained = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))
    fresh = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=89))

    assert retained is original
    assert fresh is original
    assert len(fetcher.requests) == 2
    assert fetcher.requests[1].etag == '"generation-1"'


@pytest.mark.anyio
async def test_jwks_304_without_a_live_snapshot_is_unavailable() -> None:
    fetcher = _RecordingJWKSFetcher(JWKSFetchResponse(status_code=304, body=b"", headers={}))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.anyio
async def test_jwks_fetcher_returning_wrong_response_type_is_unavailable() -> None:
    class _WrongResponseFetcher:
        async def fetch(self, _request: JWKSFetchRequest) -> object:
            return object()

    provider = CachedJWKSProvider(
        entries=(_jwks_entry(),),
        fetcher=_WrongResponseFetcher(),  # type: ignore[arg-type]
    )

    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.anyio
async def test_jwks_atomic_replacement_exposes_new_and_removes_old_keys(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    old = _verification_jwk(jwt_key_material, "EdDSA", "old")
    new = _verification_jwk(jwt_key_material, "ES256", "new")
    replacement = _jwks_response(new, cache_control="max-age=60", etag='"generation-2"')
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(old, cache_control="max-age=30", etag='"generation-1"'), replacement, replacement
    )
    entry = _jwks_entry(algorithms=frozenset({"EdDSA", "ES256"}))
    provider = CachedJWKSProvider(entries=(entry,), fetcher=fetcher)

    old_key = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "old", "EdDSA", now=_JWT_NOW)
    new_key = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "new", "ES256", now=_JWT_NOW + timedelta(seconds=30))
    removed = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "old", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))

    assert isinstance(old_key, VerificationKey)
    assert isinstance(new_key, VerificationKey)
    assert new_key.key_id == "new"
    assert isinstance(removed, InvalidCredentials)


@pytest.mark.parametrize(
    "failure",
    [
        OSError("fetch detail"),
        _jwks_response(status_code=500, body=b"upstream detail"),
        _jwks_response(status_code=404, body=b"upstream detail"),
        _jwks_response(body=b"{"),
        _jwks_response({"alg": "EdDSA", "crv": "Ed25519", "kid": "new", "kty": "OKP", "use": "sig", "x": "bad"}),
    ],
    ids=["fetch", "http-5xx", "http-4xx", "parse", "partial-key-parse"],
)
@pytest.mark.anyio
async def test_jwks_failed_refresh_does_not_mutate_live_snapshot(
    failure: JWKSFetchResponse | Exception, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control="max-age=30", etag='"generation-1"'),
        failure,
        JWKSFetchResponse(status_code=304, body=b"", headers={"cache-control": "max-age=60"}),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)
    original = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    failed = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))
    retained = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=31))

    assert isinstance(failed, VerificationUnavailable)
    assert retained is original
    assert fetcher.requests[1].etag == '"generation-1"'
    assert fetcher.requests[2].etag == '"generation-1"'
    assert "detail" not in repr(failed)


@pytest.mark.anyio
async def test_jwks_stale_if_error_is_local_explicit_and_bounded(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control="max-age=30, stale-if-error=999", etag='"generation-1"'),
        OSError("temporary"),
        OSError("still unavailable"),
    )
    policy = JWKSCachePolicy(stale_if_error=timedelta(seconds=60))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher, policy=policy)

    original = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    stale = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))
    expired = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=90))

    assert stale is original
    assert isinstance(expired, VerificationUnavailable)


@pytest.mark.anyio
async def test_jwks_stale_if_error_never_accepts_an_unknown_key(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(_verification_jwk(jwt_key_material), cache_control="max-age=30"), OSError("temporary")
    )
    provider = CachedJWKSProvider(
        entries=(_jwks_entry(),), fetcher=fetcher, policy=JWKSCachePolicy(stale_if_error=timedelta(seconds=60))
    )

    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    outcome = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=30)
    )

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.anyio
async def test_jwks_remote_stale_directive_cannot_enable_local_stale_use(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control="max-age=30, stale-if-error=999"), OSError("temporary")
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.parametrize(
    "case",
    [
        "body-limit",
        "key-limit",
        "duplicate-json",
        "invalid-json",
        "non-object-json",
        "non-finite-json",
        "excessive-json-depth",
        "keys-not-array",
        "key-not-object",
        "empty-keys",
        "private-member",
        "algorithm-not-configured",
        "wrong-use",
        "wrong-key-ops",
        "duplicate-selection-tuple",
        "missing-kid",
        "unsupported-key-type",
        "weak-rsa",
        "wrong-ec-curve",
    ],
)
@pytest.mark.anyio
async def test_jwks_rejects_unsafe_or_ambiguous_documents(  # noqa: C901, PLR0912, PLR0915
    case: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    valid = _verification_jwk(jwt_key_material)
    body: bytes
    entry_algorithms = frozenset({"EdDSA"})
    selected_algorithm = "EdDSA"
    if case == "body-limit":
        body = b"x" * 1_048_577
    elif case == "key-limit":
        keys = [{**valid, "kid": f"key-{index}"} for index in range(129)]
        body = _jwks_body(*keys)
    elif case == "duplicate-json":
        body = b'{"keys":[],"keys":[]}'
    elif case == "invalid-json":
        body = b"{"
    elif case == "non-object-json":
        body = b"[]"
    elif case == "non-finite-json":
        body = b'{"keys":[],"value":NaN}'
    elif case == "excessive-json-depth":
        nested: object = None
        for _ in range(65):
            nested = {"nested": nested}
        body = json.dumps({"keys": [valid], "extension": nested}, separators=(",", ":")).encode()
    elif case == "keys-not-array":
        body = b'{"keys":{}}'
    elif case == "key-not-object":
        body = b'{"keys":["key"]}'
    elif case == "empty-keys":
        body = _jwks_body()
    elif case == "private-member":
        body = _jwks_body({**valid, "d": "private"})
    elif case == "algorithm-not-configured":
        body = _jwks_body({**valid, "alg": "RS256"})
    elif case == "wrong-use":
        body = _jwks_body({**valid, "use": "enc"})
    elif case == "wrong-key-ops":
        body = _jwks_body({**valid, "key_ops": ["sign"]})
    elif case == "duplicate-selection-tuple":
        body = _jwks_body(valid, valid)
    elif case == "missing-kid":
        body = _jwks_body({key: value for key, value in valid.items() if key != "kid"})
    elif case == "unsupported-key-type":
        body = _jwks_body({**valid, "kty": "unsupported"})
    elif case == "weak-rsa":
        body = _jwks_body(_raw_public_jwk(jwt_key_material, "RS1024", "RS256", "key-1"))
        entry_algorithms = frozenset({"RS256"})
        selected_algorithm = "RS256"
    else:
        body = _jwks_body(_raw_public_jwk(jwt_key_material, "ES384", "ES256", "key-1"))
        entry_algorithms = frozenset({"ES256"})
        selected_algorithm = "ES256"
    fetcher = _RecordingJWKSFetcher(_jwks_response(body=body))
    provider = CachedJWKSProvider(entries=(_jwks_entry(algorithms=entry_algorithms),), fetcher=fetcher)

    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", selected_algorithm, now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.anyio
async def test_jwks_rejects_unsupported_prepared_key_type(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], monkeypatch: pytest.MonkeyPatch
) -> None:
    class _UnsupportedPyJWK:
        @staticmethod
        def from_dict(_value: dict[str, object], *, algorithm: str) -> SimpleNamespace:
            del algorithm
            return SimpleNamespace(key=object())

    monkeypatch.setattr(jwks_documents, "PyJWK", _UnsupportedPyJWK)
    fetcher = _RecordingJWKSFetcher(_jwks_response(_verification_jwk(jwt_key_material)))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.anyio
async def test_jwks_entries_isolate_same_kid_by_issuer_uri_and_algorithm(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    second_issuer = "https://issuer-two.example"
    second_uri = f"{second_issuer}/jwks"
    first = _verification_jwk(jwt_key_material, "EdDSA", "shared")
    second = _verification_jwk(jwt_key_material, "ES256", "shared")

    def respond(request: JWKSFetchRequest) -> JWKSFetchResponse:
        return _jwks_response(first if request.issuer == _JWT_ISSUER else second, cache_control="max-age=60")

    fetcher = _RecordingJWKSFetcher(respond, respond)
    provider = CachedJWKSProvider(
        entries=(_jwks_entry(), _jwks_entry(second_issuer, second_uri, frozenset({"ES256"}))), fetcher=fetcher
    )

    first_key = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "shared", "EdDSA", now=_JWT_NOW)
    second_key = await provider.select_key(second_issuer, second_uri, "shared", "ES256", now=_JWT_NOW)

    assert isinstance(first_key, VerificationKey)
    assert isinstance(second_key, VerificationKey)
    assert first_key.algorithm == "EdDSA"
    assert second_key.algorithm == "ES256"
    assert tuple((request.issuer, request.jwks_uri) for request in fetcher.requests) == (
        (_JWT_ISSUER, _JWKS_URI),
        (second_issuer, second_uri),
    )


@pytest.mark.parametrize(
    ("issuer", "jwks_uri", "algorithm"),
    [
        ("https://unconfigured.example", _JWKS_URI, "EdDSA"),
        (_JWT_ISSUER, "https://unconfigured.example/jwks", "EdDSA"),
        (_JWT_ISSUER, _JWKS_URI, "RS256"),
    ],
    ids=["issuer", "uri", "algorithm"],
)
@pytest.mark.anyio
async def test_jwks_unconfigured_entry_coordinates_fail_without_fetch(
    issuer: str, jwks_uri: str, algorithm: str
) -> None:
    fetcher = _RecordingJWKSFetcher()
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    outcome = await provider.select_key(issuer, jwks_uri, "key-1", algorithm, now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert fetcher.requests == []


@pytest.mark.anyio
async def test_jwks_rejects_naive_time_without_fetch() -> None:
    fetcher = _RecordingJWKSFetcher()
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    with pytest.raises(ImproperlyConfiguredException):
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_NAIVE_JWT_NOW)

    assert fetcher.requests == []


@pytest.mark.parametrize(("warm_on_startup", "failure"), [(False, False), (True, False), (True, True)])
@pytest.mark.anyio
async def test_jwks_warmup_is_explicit_complete_and_failure_aware(
    *, warm_on_startup: bool, failure: bool, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    second_issuer = "https://issuer-two.example"
    second_uri = f"{second_issuer}/jwks"
    first_response: JWKSFetchResponse | Exception = (
        OSError("warmup unavailable")
        if failure
        else _jwks_response(_verification_jwk(jwt_key_material, "EdDSA", "first"))
    )
    second_response = _jwks_response(_verification_jwk(jwt_key_material, "ES256", "second"))
    fetcher = _RecordingJWKSFetcher(first_response, second_response)
    provider = CachedJWKSProvider(
        entries=(_jwks_entry(), _jwks_entry(second_issuer, second_uri, frozenset({"ES256"}))),
        fetcher=fetcher,
        policy=JWKSCachePolicy(warm_on_startup=warm_on_startup),
    )

    outcome = await provider.warmup(now=_JWT_NOW)
    repeated = outcome if failure else await provider.warmup(now=_JWT_NOW + timedelta(seconds=1))

    if not warm_on_startup:
        assert outcome is None
        assert repeated is None
        assert fetcher.requests == []
    else:
        assert isinstance(outcome, VerificationUnavailable) if failure else outcome is None
        assert isinstance(repeated, VerificationUnavailable) if failure else repeated is None
        assert tuple((request.issuer, request.jwks_uri) for request in fetcher.requests) == (
            (_JWT_ISSUER, _JWKS_URI),
            (second_issuer, second_uri),
        )


@pytest.mark.anyio
async def test_jwks_close_is_idempotent_and_prevents_selection_fetch(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    fetcher = _RecordingJWKSFetcher(_jwks_response(_verification_jwk(jwt_key_material)))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    await provider.aclose()
    await provider.aclose()
    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    warmup = await provider.warmup(now=_JWT_NOW)
    state = cast("Any", provider)._entries[(_JWT_ISSUER, _JWKS_URI)]  # noqa: SLF001
    refresh = await cast("Any", provider)._refresh_singleflight(state, _JWT_NOW)  # noqa: SLF001

    assert isinstance(outcome, VerificationUnavailable)
    assert isinstance(warmup, VerificationUnavailable)
    assert isinstance(refresh, VerificationUnavailable)
    assert fetcher.requests == []


@pytest.mark.anyio
async def test_argon2_hasher_uses_locked_id_parameters_and_detects_rehash(
    password_hasher: "accounts_module.Argon2PasswordHasher",
) -> None:
    candidate = "correct horse battery staple"
    encoded = await password_hasher.hash(candidate)
    current = await password_hasher.verify(encoded, candidate)
    legacy_engine = Argon2Engine(memory_cost=8_192, time_cost=1, parallelism=1, salt_len=16, hash_len=32)
    legacy = await to_thread.run_sync(legacy_engine.hash, candidate)
    legacy_result = await password_hasher.verify(legacy, candidate)

    parameters = extract_argon2_parameters(encoded)
    assert (
        parameters.type.name,
        parameters.version,
        parameters.memory_cost,
        parameters.time_cost,
        parameters.parallelism,
        parameters.salt_len,
        parameters.hash_len,
    ) == ("ID", 19, 19_456, 2, 1, 16, 32)
    assert (
        password_hasher.memory_cost,
        password_hasher.time_cost,
        password_hasher.parallelism,
        password_hasher.salt_len,
        password_hasher.hash_len,
    ) == (19_456, 2, 1, 16, 32)
    assert current == accounts_module.PasswordVerificationResult(
        status=accounts_module.PasswordVerificationStatus.VERIFIED
    )
    assert legacy_result.verified
    assert legacy_result.replacement_hash is not None
    assert legacy_result.replacement_hash.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    assert legacy not in repr(legacy_result)
    assert legacy_result.replacement_hash not in repr(legacy_result)


@pytest.mark.anyio
async def test_argon2_hasher_supports_strengthening_without_sync_startup_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    original = Argon2Engine.hash

    def reject_sync_hash(_engine: Argon2Engine, _candidate: str | bytes, **_kwargs: object) -> str:
        raise AssertionError

    monkeypatch.setattr(Argon2Engine, "hash", reject_sync_hash)
    default_hasher = accounts_module.Argon2PasswordHasher()
    monkeypatch.setattr(Argon2Engine, "hash", original)
    strengthened = await accounts_module.Argon2PasswordHasher.create(time_cost=3)

    assert default_hasher.time_cost == 2
    assert extract_argon2_parameters(strengthened.dummy_hash).time_cost == 3
    assert (await strengthened.verify(None, "constant-work candidate")).status is (
        accounts_module.PasswordVerificationStatus.INVALID
    )


@pytest.mark.parametrize("operation", ["create", "hash"])
@pytest.mark.anyio
async def test_argon2_hasher_maps_worker_hash_failures(monkeypatch: pytest.MonkeyPatch, operation: str) -> None:
    def unavailable(_engine: Argon2Engine, _candidate: str | bytes, **_kwargs: object) -> str:
        raise RuntimeError

    monkeypatch.setattr(Argon2Engine, "hash", unavailable)
    operation_call = (
        accounts_module.Argon2PasswordHasher.create(time_cost=3)
        if operation == "create"
        else accounts_module.Argon2PasswordHasher().hash("sufficiently long candidate")
    )

    with pytest.raises(accounts_module.PasswordHashingUnavailableError):
        await operation_call


@pytest.mark.parametrize(
    "kwargs",
    [
        {"memory_cost": 19_455},
        {"memory_cost": 262_145},
        {"time_cost": True},
        {"time_cost": 11},
        {"parallelism": 9},
        {"salt_len": 65},
        {"hash_len": 65},
        {"worker_limits": object()},
        {"worker_limits": WorkerLimits(crypto_tokens=54)},
        {"dummy_hash": "not-an-argon2-hash"},
    ],
)
def test_argon2_hasher_rejects_weak_unsafe_or_mismatched_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Argon2"):
        accounts_module.Argon2PasswordHasher(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("memory_cost", [40_000, 999_999_999])
@pytest.mark.anyio
async def test_argon2_hasher_rejects_hostile_parameters_before_real_verification(
    monkeypatch: pytest.MonkeyPatch, password_hasher: "accounts_module.Argon2PasswordHasher", memory_cost: int
) -> None:
    hostile = password_hasher.dummy_hash.replace("m=19456", f"m={memory_cost}")
    calls: list[str | bytes] = []
    original = Argon2Engine.verify

    def tracked(engine: Argon2Engine, candidate_hash: str | bytes, candidate: str | bytes) -> bool:
        calls.append(candidate_hash)
        return original(engine, candidate_hash, candidate)

    monkeypatch.setattr(Argon2Engine, "verify", tracked)

    result = await password_hasher.verify(hostile, "constant-work candidate")

    assert result.status is accounts_module.PasswordVerificationStatus.MALFORMED
    assert calls == [password_hasher.dummy_hash]
    assert hostile not in repr(result)


@pytest.mark.anyio
async def test_argon2_hasher_accepts_exact_utf8_byte_boundary(
    password_hasher: "accounts_module.Argon2PasswordHasher",
) -> None:
    candidate = "a" * 1_024

    encoded = await password_hasher.hash(candidate)
    result = await password_hasher.verify(encoded, candidate)

    assert result.verified


@pytest.mark.anyio
async def test_argon2_hasher_equalizes_absent_wrong_and_malformed_verification_work(
    monkeypatch: pytest.MonkeyPatch, password_hasher: "accounts_module.Argon2PasswordHasher"
) -> None:
    presented = "incorrect passphrase"
    encoded = await password_hasher.hash("correct horse battery staple")
    calls: list[str | bytes] = []
    original = Argon2Engine.verify

    def tracked(engine: Argon2Engine, candidate_hash: str | bytes, candidate: str | bytes) -> bool:
        calls.append(candidate_hash)
        return original(engine, candidate_hash, candidate)

    monkeypatch.setattr(Argon2Engine, "verify", tracked)

    absent = await password_hasher.verify(None, presented)
    absent_calls = len(calls)
    calls.clear()
    wrong = await password_hasher.verify(encoded, presented)
    wrong_calls = len(calls)
    calls.clear()
    malformed = await password_hasher.verify("not-an-argon2-hash", presented)

    assert absent.status is accounts_module.PasswordVerificationStatus.INVALID
    assert wrong.status is accounts_module.PasswordVerificationStatus.INVALID
    assert malformed.status is accounts_module.PasswordVerificationStatus.MALFORMED
    assert (absent_calls, wrong_calls, len(calls)) == (1, 1, 1)
    assert all("incorrect passphrase" not in repr(result) for result in (absent, wrong, malformed))


@pytest.mark.anyio
async def test_argon2_hasher_maps_verification_library_failures_to_sanitized_outcomes(
    monkeypatch: pytest.MonkeyPatch, password_hasher: "accounts_module.Argon2PasswordHasher"
) -> None:
    encoded = await password_hasher.hash("correct horse battery staple")
    original = Argon2Engine.verify

    def malformed(engine: Argon2Engine, candidate_hash: str | bytes, candidate: str | bytes) -> bool:
        if candidate_hash == password_hasher.dummy_hash:
            return original(engine, candidate_hash, candidate)
        raise VerificationError

    monkeypatch.setattr(Argon2Engine, "verify", malformed)

    result = await password_hasher.verify(encoded, "constant-work candidate")

    assert result.status is accounts_module.PasswordVerificationStatus.MALFORMED

    def malformed_dummy(_engine: Argon2Engine, _candidate_hash: str | bytes, _candidate: str | bytes) -> bool:
        raise VerificationError

    monkeypatch.setattr(Argon2Engine, "verify", malformed_dummy)

    with pytest.raises(accounts_module.PasswordHashingUnavailableError):
        await password_hasher.verify(None, "constant-work candidate")


@pytest.mark.anyio
async def test_argon2_hasher_maps_unexpected_dummy_failure_to_unavailable(
    monkeypatch: pytest.MonkeyPatch, password_hasher: "accounts_module.Argon2PasswordHasher"
) -> None:
    def unavailable(_engine: Argon2Engine, _candidate_hash: str | bytes, _candidate: str | bytes) -> bool:
        raise RuntimeError

    monkeypatch.setattr(Argon2Engine, "verify", unavailable)

    with pytest.raises(accounts_module.PasswordHashingUnavailableError):
        await password_hasher.verify("not-an-argon2-hash", "constant-work candidate")


@pytest.mark.parametrize("encoded_hash", [object(), "a" * 1_025])
@pytest.mark.anyio
async def test_argon2_hasher_treats_invalid_hash_runtime_shapes_as_malformed(
    password_hasher: "accounts_module.Argon2PasswordHasher", encoded_hash: object
) -> None:
    result = await password_hasher.verify(encoded_hash, "constant-work candidate")  # type: ignore[arg-type]

    assert result.status is accounts_module.PasswordVerificationStatus.MALFORMED


@pytest.mark.anyio
async def test_argon2_hasher_rejects_oversized_or_invalid_text_before_workers(
    monkeypatch: pytest.MonkeyPatch, password_hasher: "accounts_module.Argon2PasswordHasher"
) -> None:
    worker_calls = 0
    original = Argon2Engine.verify

    def tracked(engine: Argon2Engine, candidate_hash: str | bytes, candidate: str | bytes) -> bool:
        nonlocal worker_calls
        worker_calls += 1
        return original(engine, candidate_hash, candidate)

    monkeypatch.setattr(Argon2Engine, "verify", tracked)

    oversized = await password_hasher.verify(None, "é" * 513)
    invalid_unicode = await password_hasher.verify(None, "\ud800")

    assert oversized.status is accounts_module.PasswordVerificationStatus.TOO_LONG
    assert invalid_unicode.status is accounts_module.PasswordVerificationStatus.INVALID
    assert worker_calls == 0
    with pytest.raises(ValueError, match="1,024 UTF-8 bytes"):
        await password_hasher.hash("a" * 1_025)
    with pytest.raises(ValueError, match="valid UTF-8"):
        await password_hasher.hash("\ud800")
    with pytest.raises(ValueError, match="must be text"):
        await password_hasher.hash(object())  # type: ignore[arg-type]


def test_argon2_hasher_maps_engine_configuration_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(**_kwargs: object) -> object:
        raise TypeError

    monkeypatch.setattr("litestar_security.accounts._passwords._Argon2Engine", unavailable)

    with pytest.raises(ImproperlyConfiguredException, match="Invalid Argon2"):
        accounts_module.Argon2PasswordHasher()


@pytest.mark.anyio
async def test_argon2_hasher_bounds_concurrency_and_maps_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    workers = WorkerLimits(crypto_tokens=2, timeout=1)
    hasher = accounts_module.Argon2PasswordHasher(worker_limits=workers)
    active = 0
    maximum_active = 0
    lock = ThreadLock()

    def slow_verify(_engine: Argon2Engine, _candidate_hash: str | bytes, _candidate: str | bytes) -> bool:
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
        sleep(0.03)
        with lock:
            active -= 1
        return True

    monkeypatch.setattr(Argon2Engine, "verify", slow_verify)
    results: list[accounts_module.PasswordVerificationResult] = []

    async def verify() -> None:
        results.append(await hasher.verify(None, "constant-work password"))

    async with create_task_group() as task_group:
        for _ in range(6):
            task_group.start_soon(verify)

    assert maximum_active == 2
    assert len(results) == 6
    assert all(result.status is accounts_module.PasswordVerificationStatus.INVALID for result in results)

    active = 0
    maximum_active = 0
    timeout_hasher = accounts_module.Argon2PasswordHasher(worker_limits=WorkerLimits(crypto_tokens=2, timeout=0.001))
    completed = Event()
    timed_out = 0
    ticker_iterations = 0

    async def timed_verify() -> None:
        nonlocal timed_out
        with pytest.raises(accounts_module.PasswordHashingUnavailableError):
            await timeout_hasher.verify(None, "constant-work password")
        timed_out += 1

    async def run_timeout_batch() -> None:
        async with create_task_group() as batch:
            for _ in range(100):
                batch.start_soon(timed_verify)
        completed.set()

    async def ticker() -> None:
        nonlocal ticker_iterations
        while not completed.is_set():
            ticker_iterations += 1
            await checkpoint()

    async with create_task_group() as task_group:
        task_group.start_soon(run_timeout_batch)
        task_group.start_soon(ticker)

    assert (timed_out, active, maximum_active) == (100, 0, 2)
    assert ticker_iterations > 0


class _PasswordStore:
    def __init__(  # noqa: PLR0913
        self,
        encoded_hash: str | None = "current-hash",
        *,
        fail_read: bool = False,
        fail_replace: bool = False,
        fail_bump: bool = False,
        replace_result: object = True,
        security_epoch: int = 1,
        active: bool = True,
        verified: bool = True,
        bump_result: accounts_module.PasswordChangeResult | None = None,
    ) -> None:
        self.encoded_hash = encoded_hash
        self.fail_read = fail_read
        self.fail_replace = fail_replace
        self.fail_bump = fail_bump
        self.replace_result = replace_result
        self.security_epoch = security_epoch
        self.active = active
        self.verified = verified
        self.bump_result = bump_result
        self.replacements: list[tuple[str, str, str, accounts_module.SecurityEvent]] = []
        self.bump_calls: list[tuple[str, str, int, accounts_module.SecurityEvent]] = []
        self._mutation_lock = asyncio.Lock()

    async def get_password_state(self, _account_id: str) -> accounts_module.PasswordCredentialState | None:
        if self.fail_read:
            raise OSError
        return (
            accounts_module.PasswordCredentialState(
                self.encoded_hash, self.security_epoch, active=self.active, verified=self.verified
            )
            if self.encoded_hash is not None
            else None
        )

    async def compare_and_replace_password(
        self, account_id: str, expected_hash: str, password_hash: str, *, event: accounts_module.SecurityEvent
    ) -> bool:
        if self.fail_replace:
            raise OSError
        self.replacements.append((account_id, expected_hash, password_hash, event))
        return cast("bool", self.replace_result)

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: accounts_module.SecurityEvent
    ) -> accounts_module.PasswordChangeResult:
        self.bump_calls.append((account_id, password_hash, expected_epoch, event))
        if self.fail_bump:
            raise OSError
        if self.bump_result is not None:
            return self.bump_result
        async with self._mutation_lock:
            if expected_epoch != self.security_epoch:
                return accounts_module.PasswordChangeResult(accounts_module.PasswordChangeStatus.CONFLICT)
            if expected_epoch == 9_223_372_036_854_775_807:
                return accounts_module.PasswordChangeResult(accounts_module.PasswordChangeStatus.EPOCH_EXHAUSTED)
            self.encoded_hash = password_hash
            self.security_epoch += 1
            return accounts_module.PasswordChangeResult(
                accounts_module.PasswordChangeStatus.CHANGED, security_epoch=self.security_epoch
            )

    async def current_epoch(self, _account_id: str) -> int | None:
        if self.fail_read:
            raise OSError
        return self.security_epoch


class _PasswordHasher:
    def __init__(
        self, result: accounts_module.PasswordVerificationResult | None = None, *, unavailable: bool = False
    ) -> None:
        self.result = result or accounts_module.PasswordVerificationResult(
            accounts_module.PasswordVerificationStatus.INVALID
        )
        self.unavailable = unavailable
        self.calls: list[tuple[str | None, str]] = []
        self.hash_calls: list[str] = []

    async def hash(self, password: str) -> str:
        self.hash_calls.append(password)
        if self.unavailable:
            raise accounts_module.PasswordHashingUnavailableError
        return f"hashed:{password}"

    async def verify(self, encoded_hash: str | None, password: str) -> accounts_module.PasswordVerificationResult:
        self.calls.append((encoded_hash, password))
        if self.unavailable:
            raise accounts_module.PasswordHashingUnavailableError
        return self.result


class _SecurityEvents:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.events: list[accounts_module.SecurityEvent] = []

    async def emit(self, event: accounts_module.SecurityEvent) -> None:
        if self.fail:
            raise OSError
        self.events.append(event)


@pytest.mark.parametrize("failure", ["invalid", "unavailable", "store"])
@pytest.mark.anyio
async def test_password_reauthentication_maps_every_failure_to_domain_outcome(failure: str) -> None:
    store = _PasswordStore(fail_read=failure == "store")
    hasher = _PasswordHasher(unavailable=failure == "unavailable")
    service = accounts_module.PasswordReauthenticationService(accounts=store, hasher=hasher)

    outcome = await service.verify("account-1", "presented secret", now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable if failure in {"unavailable", "store"} else InvalidCredentials)
    assert store.replacements == []
    assert "presented secret" not in repr(service)
    assert "presented secret" not in repr(outcome)


@pytest.mark.parametrize(
    ("status", "encoded_hash"),
    [
        (accounts_module.PasswordVerificationStatus.INVALID, "current-hash"),
        (accounts_module.PasswordVerificationStatus.MALFORMED, "malformed-hash"),
        (accounts_module.PasswordVerificationStatus.TOO_LONG, "current-hash"),
        (accounts_module.PasswordVerificationStatus.INVALID, None),
    ],
)
@pytest.mark.anyio
async def test_password_reauthentication_collapses_credential_failures_without_rehash(
    status: accounts_module.PasswordVerificationStatus, encoded_hash: str | None
) -> None:
    store = _PasswordStore(encoded_hash)
    hasher = _PasswordHasher(accounts_module.PasswordVerificationResult(status))
    service = accounts_module.PasswordReauthenticationService(accounts=store, hasher=hasher)

    outcome = await service.verify("account-1", "presented secret", now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert store.replacements == []


@pytest.mark.parametrize(
    ("active", "verified", "outcome_type"),
    [
        (False, True, InvalidCredentials),
        (True, False, InvalidCredentials),
        (True, True, accounts_module.PasswordReauthenticationProof),
    ],
)
@pytest.mark.anyio
async def test_password_reauthentication_rejects_inactive_or_unverified_accounts_after_hash_verification(
    active: bool,  # noqa: FBT001 - parametrized account-state matrix
    verified: bool,  # noqa: FBT001 - parametrized account-state matrix
    outcome_type: type[object],
) -> None:
    store = _PasswordStore(active=active, verified=verified)
    hasher = _PasswordHasher(
        accounts_module.PasswordVerificationResult(accounts_module.PasswordVerificationStatus.VERIFIED)
    )
    service = accounts_module.PasswordReauthenticationService(accounts=store, hasher=hasher)

    outcome = await service.verify("account-1", "presented secret", now=_JWT_NOW)

    assert isinstance(outcome, outcome_type)
    assert hasher.calls == [("current-hash", "presented secret")]
    assert store.replacements == []


@pytest.mark.parametrize("sink_mode", ["default", "available", "failure"])
@pytest.mark.anyio
async def test_password_reauthentication_emits_sanitized_malformed_hash_event(
    sink_mode: str, caplog: pytest.LogCaptureFixture
) -> None:
    store = _PasswordStore("malformed-secret-hash")
    hasher = _PasswordHasher(
        accounts_module.PasswordVerificationResult(accounts_module.PasswordVerificationStatus.MALFORMED)
    )
    events = _SecurityEvents(fail=sink_mode == "failure")
    event_options = {} if sink_mode == "default" else {"events": events}
    service = accounts_module.PasswordReauthenticationService(
        accounts=store, hasher=hasher, event_ids=lambda: "event-1", **event_options
    )

    outcome = await service.verify("account-1", "presented secret", now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    if sink_mode == "default":
        assert isinstance(service.events, accounts_module.NoOpSecurityEventSink)
    if sink_mode == "available":
        assert len(events.events) == 1
        event = events.events[0]
        assert (event.event_id, event.operation, event.outcome, event.account_id) == (
            "event-1",
            "local.password.verify",
            "malformed_hash",
            "account-1",
        )
        rendered = repr(event)
        assert "presented secret" not in rendered
        assert "malformed-secret-hash" not in rendered
    if sink_mode == "failure":
        assert "Security event sink failed" in caplog.text


@pytest.mark.parametrize(
    ("replace_result", "fail_replace", "outcome_type"),
    [
        (True, False, accounts_module.PasswordReauthenticationProof),
        (False, False, VerificationUnavailable),
        (object(), False, VerificationUnavailable),
        (True, True, VerificationUnavailable),
    ],
)
@pytest.mark.anyio
async def test_password_reauthentication_locks_atomic_rehash_outcomes(
    replace_result: object, *, fail_replace: bool, outcome_type: type[object]
) -> None:
    store = _PasswordStore(replace_result=replace_result, fail_replace=fail_replace)
    replacement = "$argon2id$replacement-secret"
    hasher = _PasswordHasher(
        accounts_module.PasswordVerificationResult(
            accounts_module.PasswordVerificationStatus.VERIFIED, replacement_hash=replacement
        )
    )
    service = accounts_module.PasswordReauthenticationService(accounts=store, hasher=hasher)

    outcome = await service.verify("account-1", "presented secret", now=_JWT_NOW)

    assert isinstance(outcome, outcome_type)
    if not fail_replace:
        assert len(store.replacements) == 1
        assert store.replacements[0][1:3] == ("current-hash", replacement)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"evidence_ttl": timedelta(0)},
        {"evidence_ttl": timedelta(minutes=6)},
        {"clock": None},
        {"events": object()},
        {"event_ids": None},
        {"accounts": object()},
        {"hasher": object()},
    ],
)
def test_password_reauthentication_rejects_invalid_configuration(kwargs: dict[str, object]) -> None:
    values = {"accounts": _PasswordStore(), "hasher": _PasswordHasher(), **kwargs}

    with pytest.raises(ImproperlyConfiguredException, match="Password reauthentication"):
        accounts_module.PasswordReauthenticationService(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("source", ["argument", "clock"])
@pytest.mark.anyio
async def test_password_reauthentication_rejects_naive_time_as_unavailable(source: str) -> None:
    naive = _JWT_NOW.replace(tzinfo=None)
    service = accounts_module.PasswordReauthenticationService(
        accounts=_PasswordStore(),
        hasher=_PasswordHasher(
            accounts_module.PasswordVerificationResult(accounts_module.PasswordVerificationStatus.VERIFIED)
        ),
        clock=lambda: naive,
    )

    outcome = await service.verify("account-1", "presented secret", now=naive if source == "argument" else None)

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.parametrize("account_id", [" ", object()])
@pytest.mark.anyio
async def test_password_reauthentication_rejects_invalid_account_ids_without_port_calls(account_id: object) -> None:
    hasher = _PasswordHasher()
    service = accounts_module.PasswordReauthenticationService(accounts=_PasswordStore(), hasher=hasher)

    outcome = await service.verify(account_id, "presented secret", now=_JWT_NOW)  # type: ignore[arg-type]

    assert isinstance(outcome, InvalidCredentials)
    assert hasher.calls == []


@pytest.mark.anyio
async def test_password_reauthentication_uses_an_aware_default_clock() -> None:
    service = accounts_module.PasswordReauthenticationService(
        accounts=_PasswordStore(),
        hasher=_PasswordHasher(
            accounts_module.PasswordVerificationResult(accounts_module.PasswordVerificationStatus.VERIFIED)
        ),
    )
    before = datetime.now(timezone.utc)

    outcome = await service.verify("account-1", "presented secret")

    after = datetime.now(timezone.utc)
    assert isinstance(outcome, accounts_module.PasswordReauthenticationProof)
    assert before <= outcome.authenticated_at <= after
    assert outcome.expires_at == outcome.authenticated_at + timedelta(minutes=5)


@pytest.mark.anyio
async def test_password_reauthentication_logs_blank_event_ids_without_changing_decision(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = accounts_module.PasswordReauthenticationService(
        accounts=_PasswordStore("malformed-hash"),
        hasher=_PasswordHasher(
            accounts_module.PasswordVerificationResult(accounts_module.PasswordVerificationStatus.MALFORMED)
        ),
        events=_SecurityEvents(),
        event_ids=lambda: " ",
    )

    outcome = await service.verify("account-1", "presented secret", now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert "Security event could not be built for local.password.verify" in caplog.text


@pytest.mark.anyio
async def test_password_reauthentication_returns_fresh_evidence_and_rehashes_atomically() -> None:
    replacement = "$argon2id$replacement-secret"
    store = _PasswordStore()
    hasher = _PasswordHasher(
        accounts_module.PasswordVerificationResult(
            accounts_module.PasswordVerificationStatus.VERIFIED, replacement_hash=replacement
        )
    )
    service = accounts_module.PasswordReauthenticationService(accounts=store, hasher=hasher)

    outcome = await service.verify(" account-1 ", "presented secret", now=_JWT_NOW)

    assert outcome == accounts_module.PasswordReauthenticationProof(
        account_id="account-1", security_epoch=1, authenticated_at=_JWT_NOW, expires_at=_JWT_NOW + timedelta(minutes=5)
    )
    assert hasher.calls == [("current-hash", "presented secret")]
    assert len(store.replacements) == 1
    account_id, expected_hash, new_hash, event = store.replacements[0]
    assert (account_id, expected_hash, new_hash) == ("account-1", "current-hash", replacement)
    assert (event.operation, event.outcome, event.account_id) == ("local.password.rehash", "updated", "account-1")
    assert "presented secret" not in repr(event)
    assert replacement not in repr(event)


class _CredentialCleanup:
    def __init__(self, *, failures: frozenset[str] = frozenset()) -> None:
        self.failures = failures
        self.session_revocations: list[tuple[str, accounts_module.SecurityEvent]] = []
        self.other_revocations: list[tuple[str, str, accounts_module.SecurityEvent]] = []
        self.rebinds: list[tuple[str, accounts_module.CreateSessionCommand, accounts_module.SecurityEvent]] = []
        self.refresh_revocations: list[tuple[str, accounts_module.SecurityEvent]] = []

    async def create(
        self, command: accounts_module.CreateSessionCommand, *, event: accounts_module.SecurityEvent
    ) -> accounts_module.SessionRecord:
        raise NotImplementedError

    async def create_family(
        self, command: accounts_module.CreateRefreshFamilyCommand, *, event: accounts_module.SecurityEvent
    ) -> bool:
        del command, event
        return False

    async def get(self, session_id: str) -> accounts_module.SessionRecord | None:
        del session_id
        return None

    async def list_for_account(self, account_id: str) -> list[accounts_module.SessionRecord]:
        del account_id
        return []

    async def touch(self, session_id: str, *, now: datetime) -> accounts_module.SessionRecord | None:
        del session_id, now
        return None

    async def revoke(self, session_id: str, *, event: accounts_module.SecurityEvent) -> bool:
        del session_id, event
        return False

    async def revoke_session_for_account(
        self, account_id: str, session_id: str, *, event: accounts_module.SecurityEvent
    ) -> bool:
        del account_id, session_id, event
        return False

    async def revoke_sessions_for_account(self, account_id: str, *, event: accounts_module.SecurityEvent) -> int:
        self.session_revocations.append((account_id, event))
        if "sessions" in self.failures:
            raise OSError
        return 1

    async def revoke_other_sessions(
        self, account_id: str, session_id: str, *, event: accounts_module.SecurityEvent
    ) -> int:
        self.other_revocations.append((account_id, session_id, event))
        if "others" in self.failures:
            raise OSError
        return 1

    async def rebind(
        self,
        prior_session_id: str,
        command: accounts_module.CreateSessionCommand,
        *,
        event: accounts_module.SecurityEvent,
    ) -> accounts_module.SessionRecord | None:
        self.rebinds.append((prior_session_id, command, event))
        if "rebind" in self.failures:
            raise OSError
        return None

    async def prepare_rotation(
        self,
        proof: accounts_module.RefreshTokenProof,
        idempotency_digest: bytes | None,
        *,
        now: datetime,
        event: accounts_module.SecurityEvent,
    ) -> (
        accounts_module.RefreshFamilyContext
        | accounts_module.RefreshReceiptReplay
        | accounts_module.PrepareRefreshResult
    ):
        del proof, idempotency_digest, now, event
        return accounts_module.PrepareRefreshResult(accounts_module.RefreshRotationStatus.INVALID)

    async def rotate(
        self, command: accounts_module.RotateRefreshCommand, *, now: datetime, event: accounts_module.SecurityEvent
    ) -> accounts_module.RotateRefreshResult:
        raise NotImplementedError

    async def revoke_family(self, family_id: str, *, event: accounts_module.SecurityEvent) -> bool:
        del family_id, event
        return False

    async def revoke_token(self, token_id: str, token_digest: bytes, *, event: accounts_module.SecurityEvent) -> bool:
        del token_id, token_digest, event
        return False

    async def revoke_token_for_account(
        self, account_id: str, token_id: str, token_digest: bytes, *, event: accounts_module.SecurityEvent
    ) -> bool:
        del account_id, token_id, token_digest, event
        return False

    async def revoke_for_account(self, account_id: str, *, event: accounts_module.SecurityEvent) -> int:
        self.refresh_revocations.append((account_id, event))
        if "refresh" in self.failures:
            raise OSError
        return 1


def _password_proof(
    *, account_id: str = "account-1", security_epoch: int = 1, authenticated_at: datetime = _JWT_NOW
) -> accounts_module.PasswordReauthenticationProof:
    return accounts_module.PasswordReauthenticationProof(
        account_id=account_id,
        security_epoch=security_epoch,
        authenticated_at=authenticated_at,
        expires_at=authenticated_at + timedelta(minutes=5),
    )


def _replacement_session(*, security_epoch: int = 1) -> accounts_module.CreateSessionCommand:
    return accounts_module.CreateSessionCommand(
        session_id="bm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm4",
        binding_id="sb_aWlpaWlpaWlpaWlpaWlpaQ",
        binding_digest=b"b" * 32,
        account_id="account-1",
        security_epoch=security_epoch,
        created_at=_JWT_NOW,
        authenticated_at=_JWT_NOW,
        expires_at=_JWT_NOW + timedelta(hours=1),
    )


@pytest.mark.parametrize(
    ("proof", "now", "accepted"),
    [
        (_password_proof(), _JWT_NOW + timedelta(minutes=5), True),
        (_password_proof(), _JWT_NOW + timedelta(minutes=5, microseconds=1), False),
        (_password_proof(authenticated_at=_JWT_NOW + timedelta(seconds=1)), _JWT_NOW, False),
        (_password_proof(account_id="account-2"), _JWT_NOW, False),
    ],
)
@pytest.mark.anyio
async def test_password_change_requires_account_epoch_bound_recent_proof(
    proof: accounts_module.PasswordReauthenticationProof, now: datetime, *, accepted: bool
) -> None:
    store = _PasswordStore()
    service = accounts_module.PasswordChangeService(accounts=store, hasher=_PasswordHasher())

    outcome = await service.change("account-1", "correct horse battery staple", proof=proof, now=now)

    if accepted:
        assert outcome == accounts_module.PasswordChangeResult(
            accounts_module.PasswordChangeStatus.CHANGED, security_epoch=2
        )
        assert len(store.bump_calls) == 1
    else:
        assert isinstance(outcome, InvalidCredentials)
        assert store.bump_calls == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"accounts": object()},
        {"hasher": object()},
        {"password_policy": object()},
        {"sessions": object()},
        {"refresh_tokens": object()},
        {"evidence_ttl": timedelta(0)},
        {"evidence_ttl": timedelta(minutes=6)},
        {"clock": None},
        {"event_ids": None},
    ],
)
def test_password_change_rejects_invalid_configuration(kwargs: dict[str, object]) -> None:
    values = {"accounts": _PasswordStore(), "hasher": _PasswordHasher(), **kwargs}

    with pytest.raises(ImproperlyConfiguredException, match="Password change"):
        accounts_module.PasswordChangeService(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("case", "outcome_type"),
    [
        ("change_time", accounts_module.InvalidLifecycleRequest),
        ("force_time", accounts_module.InvalidLifecycleRequest),
        ("invalid_proof", InvalidCredentials),
        ("blank_account", accounts_module.InvalidLifecycleRequest),
        ("compromise_rebind", accounts_module.InvalidLifecycleRequest),
        ("missing_replacement", accounts_module.InvalidLifecycleRequest),
        ("missing_current", accounts_module.InvalidLifecycleRequest),
        ("no_session_registry", accounts_module.InvalidLifecycleRequest),
        ("blank_current", accounts_module.InvalidLifecycleRequest),
        ("naive_expiry", accounts_module.InvalidLifecycleRequest),
        ("policy_failure", VerificationUnavailable),
        ("policy_rejection", accounts_module.PasswordPolicyResult),
        ("hash_failure", VerificationUnavailable),
        ("store_failure", VerificationUnavailable),
        ("event_failure", VerificationUnavailable),
        ("wrong_epoch", VerificationUnavailable),
    ],
)
@pytest.mark.anyio
async def test_password_change_fails_closed_before_or_after_the_atomic_boundary(
    case: str, outcome_type: type[object]
) -> None:
    store = _PasswordStore(
        fail_bump=case == "store_failure",
        bump_result=(
            accounts_module.PasswordChangeResult(accounts_module.PasswordChangeStatus.CHANGED, security_epoch=3)
            if case == "wrong_epoch"
            else None
        ),
    )
    hasher = _PasswordHasher(unavailable=case == "hash_failure")
    cleanup = _CredentialCleanup()
    service = accounts_module.PasswordChangeService(
        accounts=store,
        hasher=hasher,
        password_policy=accounts_module.PasswordPolicy(
            compromised=_unavailable_password_check if case == "policy_failure" else None
        ),
        sessions=None if case == "no_session_registry" else cleanup,
        event_ids=(lambda: " ") if case == "event_failure" else (lambda: "event-1"),
    )
    proof: object = object() if case == "invalid_proof" else _password_proof()
    replacement: accounts_module.CreateSessionCommand | None = _replacement_session()
    current_session_id: str | None = None
    compromise = False
    account_id = "account-1"
    password = "short" if case == "policy_rejection" else "correct horse battery staple"
    now = _JWT_NOW.replace(tzinfo=None) if case in {"change_time", "force_time"} else _JWT_NOW
    if case == "blank_account":
        account_id = " "
    elif case == "compromise_rebind":
        compromise = True
        current_session_id = "session-old"
    elif case == "missing_replacement":
        current_session_id = "session-old"
        replacement = None
    elif case == "missing_current":
        replacement = _replacement_session()
    elif case == "no_session_registry":
        current_session_id = "session-old"
    elif case == "blank_current":
        current_session_id = " "
    elif case == "naive_expiry":
        current_session_id = "session-old"
        replacement = _replacement_session()
        object.__setattr__(replacement, "expires_at", _JWT_NOW.replace(tzinfo=None))

    if case in {"blank_account", "force_time"}:
        outcome = await service.force_reset(account_id, password, expected_epoch=1, now=now)
    else:
        outcome = await service.change(
            account_id,
            password,
            proof=cast("accounts_module.PasswordReauthenticationProof", proof),
            current_session_id=current_session_id,
            replacement_session=replacement if current_session_id is not None or case == "missing_current" else None,
            compromise=compromise,
            now=now,
        )

    assert isinstance(outcome, outcome_type)


@pytest.mark.anyio
async def test_password_change_rebinds_only_current_session_at_new_epoch_and_revokes_all_refresh() -> None:
    store = _PasswordStore()
    cleanup = _CredentialCleanup()
    service = accounts_module.PasswordChangeService(
        accounts=store, hasher=_PasswordHasher(), sessions=cleanup, refresh_tokens=cleanup, event_ids=lambda: "event-1"
    )

    outcome = await service.change(
        "account-1",
        "correct horse battery staple",
        proof=_password_proof(),
        current_session_id="session-old",
        replacement_session=_replacement_session(),
        now=_JWT_NOW + timedelta(seconds=1),
    )

    assert outcome == accounts_module.PasswordChangeResult(
        accounts_module.PasswordChangeStatus.CHANGED, security_epoch=2
    )
    assert [(account_id, session_id) for account_id, session_id, _event in cleanup.other_revocations] == [
        ("account-1", "session-old")
    ]
    assert len(cleanup.rebinds) == 1
    prior_session_id, command, event = cleanup.rebinds[0]
    assert (prior_session_id, command.account_id, command.security_epoch, command.created_at) == (
        "session-old",
        "account-1",
        2,
        _JWT_NOW,
    )
    assert (event.operation, event.account_id) == ("local.password.session_rebind", "account-1")
    assert [account_id for account_id, _event in cleanup.refresh_revocations] == ["account-1"]
    assert cleanup.session_revocations == []


@pytest.mark.parametrize("operation", ["compromise", "force_reset", "bearer"])
@pytest.mark.anyio
async def test_password_change_compromise_admin_and_bearer_paths_revoke_every_local_transport(operation: str) -> None:
    store = _PasswordStore()
    cleanup = _CredentialCleanup()
    service = accounts_module.PasswordChangeService(
        accounts=store, hasher=_PasswordHasher(), sessions=cleanup, refresh_tokens=cleanup
    )

    if operation == "force_reset":
        outcome = await service.force_reset("account-1", "correct horse battery staple", expected_epoch=1, now=_JWT_NOW)
    else:
        outcome = await service.change(
            "account-1",
            "correct horse battery staple",
            proof=_password_proof(),
            compromise=operation == "compromise",
            now=_JWT_NOW,
        )

    assert outcome == accounts_module.PasswordChangeResult(
        accounts_module.PasswordChangeStatus.CHANGED, security_epoch=2
    )
    assert [account_id for account_id, _event in cleanup.session_revocations] == ["account-1"]
    assert [account_id for account_id, _event in cleanup.refresh_revocations] == ["account-1"]
    assert cleanup.rebinds == []
    assert cleanup.other_revocations == []


@pytest.mark.anyio
async def test_concurrent_password_changes_allow_exactly_one_epoch_compare_and_bump() -> None:
    store = _PasswordStore()
    cleanup = _CredentialCleanup()
    service = accounts_module.PasswordChangeService(
        accounts=store, hasher=_PasswordHasher(), sessions=cleanup, refresh_tokens=cleanup
    )
    outcomes: list[object] = []

    async def change() -> None:
        outcomes.append(
            await service.change("account-1", "correct horse battery staple", proof=_password_proof(), now=_JWT_NOW)
        )

    async with create_task_group() as task_group:
        task_group.start_soon(change)
        task_group.start_soon(change)

    statuses = [cast("accounts_module.PasswordChangeResult", outcome).status for outcome in outcomes]
    assert statuses.count(accounts_module.PasswordChangeStatus.CHANGED) == 1
    assert statuses.count(accounts_module.PasswordChangeStatus.CONFLICT) == 1
    assert len(cleanup.session_revocations) == 1
    assert len(cleanup.refresh_revocations) == 1


@pytest.mark.parametrize(
    ("epoch", "expected_status", "hash_calls"),
    [
        (9_223_372_036_854_775_806, accounts_module.PasswordChangeStatus.CHANGED, ["correct horse battery staple"]),
        (9_223_372_036_854_775_807, accounts_module.PasswordChangeStatus.EPOCH_EXHAUSTED, []),
    ],
)
@pytest.mark.anyio
async def test_password_change_never_wraps_security_epoch(
    epoch: int, expected_status: accounts_module.PasswordChangeStatus, hash_calls: list[str]
) -> None:
    store = _PasswordStore(security_epoch=epoch)
    hasher = _PasswordHasher()
    service = accounts_module.PasswordChangeService(accounts=store, hasher=hasher)

    outcome = await service.change(
        "account-1", "correct horse battery staple", proof=_password_proof(security_epoch=epoch), now=_JWT_NOW
    )

    assert isinstance(outcome, accounts_module.PasswordChangeResult)
    assert outcome.status is expected_status
    assert hasher.hash_calls == hash_calls


@pytest.mark.parametrize("failure", ["sessions", "refresh", "others", "rebind"])
@pytest.mark.anyio
async def test_committed_password_change_survives_best_effort_cleanup_failure(
    failure: str, caplog: pytest.LogCaptureFixture
) -> None:
    store = _PasswordStore()
    cleanup = _CredentialCleanup(failures=frozenset({failure}))
    service = accounts_module.PasswordChangeService(
        accounts=store, hasher=_PasswordHasher(), sessions=cleanup, refresh_tokens=cleanup
    )
    rebind = failure in {"others", "rebind"}

    outcome = await service.change(
        "account-1",
        "correct horse battery staple",
        proof=_password_proof(),
        current_session_id="session-old" if rebind else None,
        replacement_session=_replacement_session() if rebind else None,
        now=_JWT_NOW,
    )

    assert outcome == accounts_module.PasswordChangeResult(
        accounts_module.PasswordChangeStatus.CHANGED, security_epoch=2
    )
    assert "cleanup failed" in caplog.text or "rebind failed" in caplog.text


@pytest.mark.parametrize(
    ("current_epoch", "presented_epoch", "fail", "outcome_type"),
    [
        (3, 3, False, type(None)),
        (3, 2, False, InvalidCredentials),
        (None, 3, False, InvalidCredentials),
        (True, 1, False, InvalidCredentials),
        (3, 3, True, VerificationUnavailable),
    ],
)
@pytest.mark.anyio
async def test_security_epoch_validator_maps_exact_current_invalid_and_unavailable_states(
    current_epoch: object, presented_epoch: int, *, fail: bool, outcome_type: type[object]
) -> None:
    class Store:
        async def current_epoch(self, account_id: str) -> int | None:
            del account_id
            if fail:
                raise OSError
            return cast("int | None", current_epoch)

    validator = accounts_module.SecurityEpochValidator(cast("Any", Store()))

    outcome = await validator.validate("account-1", presented_epoch)

    assert isinstance(outcome, outcome_type)


@pytest.mark.anyio
async def test_security_epoch_validator_rejects_invalid_configuration_and_presented_state() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Security epoch validator"):
        accounts_module.SecurityEpochValidator(cast("Any", object()))
    validator = accounts_module.SecurityEpochValidator(_PasswordStore())
    invalid_value: object = True
    invalid_epoch = cast("int", invalid_value)

    assert isinstance(await validator.validate(" ", 1), InvalidCredentials)
    assert isinstance(await validator.validate("account-1", invalid_epoch), InvalidCredentials)


class _LifecycleStore:
    def __init__(
        self,
        *,
        account: "accounts_module.LocalAccount[object] | None" = None,
        registration_status: accounts_module.RegistrationStatus = accounts_module.RegistrationStatus.CREATED,
        consume_status: accounts_module.ConsumeStatus = accounts_module.ConsumeStatus.CONSUMED,
        reset_status: accounts_module.PasswordResetStatus = accounts_module.PasswordResetStatus.RESET,
        fail: bool = False,
    ) -> None:
        self.account = account
        self.registration_status = registration_status
        self.consume_status = consume_status
        self.reset_status = reset_status
        self.fail = fail
        self.registrations: list[tuple[object, ...]] = []
        self.absent_probes: list[None] = []
        self.issues: list[
            tuple[accounts_module.TokenIssue, accounts_module.NotificationCommand, accounts_module.SecurityEvent]
        ] = []
        self.consumptions: list[tuple[str, bytes, datetime, accounts_module.SecurityEvent]] = []
        self.resets: list[tuple[str, bytes, str, datetime, accounts_module.SecurityEvent]] = []

    async def find_for_login(self, _normalized_identifier: str) -> "accounts_module.LocalAccount[object] | None":
        return self.account

    async def get_by_id(self, _account_id: str) -> "accounts_module.LocalAccount[object] | None":
        return self.account

    async def register(  # noqa: PLR0913
        self,
        command: accounts_module.RegistrationCommand,
        password_hash: str,
        *,
        invitation_digest: bytes | None,
        verification: accounts_module.PurposeTokenDelivery | None,
        now: datetime,
        event: accounts_module.SecurityEvent,
    ) -> "accounts_module.RegistrationResult[object]":
        self.registrations.append((command, password_hash, invitation_digest, verification, now, event))
        if self.fail:
            raise OSError
        account = (
            accounts_module.LocalAccount(
                account_id="account-1",
                normalized_identifier="user@example.com",
                display_name=None,
                active=True,
                verified=verification is None,
                security_epoch=1,
            )
            if self.registration_status is accounts_module.RegistrationStatus.CREATED
            else None
        )
        return accounts_module.RegistrationResult(self.registration_status, account)

    async def issue(
        self,
        issue: accounts_module.TokenIssue,
        notification: accounts_module.NotificationCommand,
        *,
        event: accounts_module.SecurityEvent,
    ) -> None:
        self.issues.append((issue, notification, event))
        if self.fail:
            raise OSError

    async def issue_absent(self) -> None:
        self.absent_probes.append(None)
        if self.fail:
            raise OSError

    async def consume_and_verify(
        self, token_id: str, digest: bytes, *, now: datetime, event: accounts_module.SecurityEvent
    ) -> accounts_module.ConsumeResult:
        self.consumptions.append((token_id, digest, now, event))
        if self.fail:
            raise OSError
        if self.consume_status is accounts_module.ConsumeStatus.CONSUMED:
            return accounts_module.ConsumeResult(self.consume_status, "account-1", 1)
        return accounts_module.ConsumeResult(self.consume_status)

    async def consume_and_reset(
        self,
        token_id: str,
        digest: bytes,
        new_password_hash: str,
        *,
        now: datetime,
        event: accounts_module.SecurityEvent,
    ) -> accounts_module.PasswordResetResult:
        self.resets.append((token_id, digest, new_password_hash, now, event))
        if self.fail:
            raise OSError
        if self.reset_status is accounts_module.PasswordResetStatus.RESET:
            return accounts_module.PasswordResetResult(self.reset_status, "account-1", 2)
        return accounts_module.PasswordResetResult(self.reset_status)


def _lifecycle_account(*, active: bool = True, verified: bool = False) -> "accounts_module.LocalAccount[object]":
    return accounts_module.LocalAccount(
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
@pytest.mark.anyio
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
@pytest.mark.anyio
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
@pytest.mark.anyio
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
            accounts_module.InvalidLifecycleRequest
            if failure in {"identifier", "empty_identifier"}
            else VerificationUnavailable
        ),
    )
    assert "correct horse battery staple" not in repr(outcome)


@pytest.mark.anyio
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

    assert outcome == accounts_module.PasswordPolicyResult(
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
@pytest.mark.anyio
async def test_verification_resend_is_generic_across_account_and_store_states(
    account: "accounts_module.LocalAccount[object] | None",
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
        accounts_module.ConsumeStatus.CONSUMED,
        accounts_module.ConsumeStatus.INVALID,
        accounts_module.ConsumeStatus.EXPIRED,
        accounts_module.ConsumeStatus.USED,
    ],
)
@pytest.mark.anyio
async def test_verification_consume_delegates_replay_and_expiry_atomically(
    status: accounts_module.ConsumeStatus,
) -> None:
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
    issued = _lifecycle_token(codec, accounts_module.TokenPurpose.VERIFICATION, timedelta(hours=24))
    store = _LifecycleStore(consume_status=status)
    service = accounts_module.VerificationTokenService(accounts=store, store=store, tokens=codec)

    outcome = await service.consume(issued.notification.token, now=_JWT_NOW)

    assert isinstance(outcome, accounts_module.ConsumeResult)
    assert outcome.status is status
    assert len(store.consumptions) == 1
    token_id, digest, now, event = store.consumptions[0]
    assert (token_id, digest, now) == (issued.issue.token_id, issued.issue.digest, _JWT_NOW)
    assert event.operation == "local.verification.consume"


@pytest.mark.anyio
async def test_verification_consume_rejects_purpose_swap_without_store_access() -> None:
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
    recovery = _lifecycle_token(codec, accounts_module.TokenPurpose.RECOVERY, timedelta(minutes=30))
    store = _LifecycleStore()
    service = accounts_module.VerificationTokenService(accounts=store, store=store, tokens=codec)

    outcome = await service.consume(recovery.notification.token, now=_JWT_NOW)

    assert outcome == accounts_module.ConsumeResult(accounts_module.ConsumeStatus.INVALID)
    assert store.consumptions == []


@pytest.mark.anyio
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
@pytest.mark.anyio
async def test_recovery_request_is_generic_and_emits_only_atomic_outbox_commands(
    account: "accounts_module.LocalAccount[object] | None",
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
@pytest.mark.anyio
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

    assert isinstance(outcome, accounts_module.PasswordResetResult)
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
@pytest.mark.anyio
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

    assert outcome == accounts_module.PasswordResetResult(accounts_module.PasswordResetStatus.RESET, "account-1", 2)
    assert len(cleanup.session_revocations) == (1 if transport == "sessions" else 0)
    assert len(cleanup.refresh_revocations) == (0 if transport == "sessions" else 1)
    if transport == "refresh_failure":
        assert "Password refresh cleanup failed" in caplog.text


@pytest.mark.parametrize("case", ["purpose_swap", "policy", "policy_failure", "store_failure"])
@pytest.mark.anyio
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
        assert outcome == accounts_module.PasswordResetResult(accounts_module.PasswordResetStatus.INVALID)
        assert hasher.hash_calls == []
        assert store.resets == []
    elif case == "policy":
        assert outcome == accounts_module.PasswordPolicyResult(
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


class _NativeSessionStore:
    def __init__(self) -> None:
        self.account: accounts_module.LocalAccount[object] | None = accounts_module.LocalAccount(
            account_id="account-1",
            normalized_identifier="user@example.com",
            display_name="User",
            active=True,
            verified=True,
            security_epoch=1,
            user=object(),
        )
        self.epoch: int | None = 1
        self.records: dict[str, accounts_module.SessionRecord] = {}
        self.commands: list[accounts_module.CreateSessionCommand] = []
        self.rebinds: list[tuple[str, accounts_module.CreateSessionCommand]] = []
        self.revocations: list[tuple[str, str]] = []
        self.touches: list[tuple[str, datetime]] = []
        self.failures: set[str] = set()
        self.mismatch_create = False

    @staticmethod
    def record(command: accounts_module.CreateSessionCommand) -> accounts_module.SessionRecord:
        return accounts_module.SessionRecord(
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

    async def create(
        self, command: accounts_module.CreateSessionCommand, *, event: accounts_module.SecurityEvent
    ) -> accounts_module.SessionRecord:
        del event
        if "create" in self.failures:
            raise OSError
        self.commands.append(command)
        record = self.record(command)
        if self.mismatch_create:
            return accounts_module.SessionRecord(
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
        self.records[record.session_id] = record
        return record

    async def get(self, session_id: str) -> accounts_module.SessionRecord | None:
        if "get" in self.failures:
            raise OSError
        return self.records.get(session_id)

    async def get_by_id(self, account_id: str) -> accounts_module.LocalAccount[object] | None:
        if "account" in self.failures:
            raise OSError
        return self.account if self.account is not None and self.account.account_id == account_id else None

    async def current_epoch(self, account_id: str) -> int | None:
        if "epoch" in self.failures:
            raise OSError
        return self.epoch if account_id == "account-1" else None

    async def list_for_account(self, account_id: str) -> list[accounts_module.SessionRecord]:
        if "list" in self.failures:
            raise OSError
        return list(self.records.values()) if account_id == "account-1" else []

    async def touch(self, session_id: str, *, now: datetime) -> accounts_module.SessionRecord | None:
        if "touch" in self.failures:
            raise OSError
        self.touches.append((session_id, now))
        record = self.records.get(session_id)
        if record is None:
            return None
        touched = accounts_module.SessionRecord(
            session_id=record.session_id,
            binding_id=record.binding_id,
            binding_digest=record.binding_digest,
            account_id=record.account_id,
            security_epoch=record.security_epoch,
            created_at=record.created_at,
            authenticated_at=record.authenticated_at,
            last_seen_at=now,
            expires_at=record.expires_at,
            display_metadata=record.display_metadata,
        )
        self.records[session_id] = touched
        return touched

    async def revoke_session_for_account(
        self, account_id: str, session_id: str, *, event: accounts_module.SecurityEvent
    ) -> bool:
        del event
        if "revoke" in self.failures:
            raise OSError
        self.revocations.append((account_id, session_id))
        record = self.records.get(session_id)
        if record is None or record.account_id != account_id:
            return False
        del self.records[session_id]
        return True

    async def revoke_sessions_for_account(self, account_id: str, *, event: accounts_module.SecurityEvent) -> int:
        del event
        matches = tuple(key for key, record in self.records.items() if record.account_id == account_id)
        for key in matches:
            del self.records[key]
        return len(matches)

    async def revoke_other_sessions(
        self, account_id: str, session_id: str, *, event: accounts_module.SecurityEvent
    ) -> int:
        del event
        matches = tuple(
            key for key, record in self.records.items() if record.account_id == account_id and key != session_id
        )
        for key in matches:
            del self.records[key]
        return len(matches)

    async def rebind(
        self,
        prior_session_id: str,
        command: accounts_module.CreateSessionCommand,
        *,
        event: accounts_module.SecurityEvent,
    ) -> accounts_module.SessionRecord | None:
        del event
        if "rebind" in self.failures or prior_session_id not in self.records:
            return None
        self.rebinds.append((prior_session_id, command))
        del self.records[prior_session_id]
        record = self.record(command)
        self.records[record.session_id] = record
        return record


class _SessionEntropy:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, length: int) -> bytes:
        self.calls += 1
        return bytes([self.calls]) * length


def _native_session_connection(
    session: dict[str, object],
    *,
    binding_token: str | None = None,
    scope_type: str = "http",
    cookie_name: str = "__Host-litestar-security-binding",
) -> ASGIConnection[Any, Any, Any, Any]:
    headers = [] if binding_token is None else [(b"cookie", f"{cookie_name}={binding_token}".encode())]
    return ASGIConnection(
        cast(
            "Any",
            {
                "type": scope_type,
                "asgi": {"spec_version": "2.0", "version": "3.0"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "https" if scope_type == "http" else "wss",
                "path": "/",
                "raw_path": b"/",
                "query_string": b"",
                "root_path": "",
                "headers": headers,
                "client": ("test", 50000),
                "server": ("testserver", 443),
                "session": session,
            },
        )
    )


def _queued_binding_token(connection: ASGIConnection[Any, Any, Any, Any]) -> str:
    headers = cast("list[tuple[bytes, bytes]]", connection.scope["_litestar_security_response_headers"])
    name_value = headers[-1][1].decode().partition(";")[0]
    return name_value.partition("=")[2].strip('"')


def _copy_native_session(session: dict[str, object]) -> dict[str, object]:
    return {key: dict(value) if isinstance(value, dict) else value for key, value in session.items()}


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


@pytest.mark.anyio
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
        connection, cast("accounts_module.LocalAccount[object]", store.account), display_metadata={"device": "browser"}
    )

    assert isinstance(authentication, accounts_module.SessionAuthentication)
    assert session == {
        "cart": "anonymous",
        "_litestar_security": {
            "version": 2,
            "session_id": authentication.session_id,
            "binding_id": authentication.binding_id,
            "account_id": "account-1",
            "security_epoch": 1,
            "authenticated_at": _JWT_NOW.isoformat(),
            "expires_at": (_JWT_NOW + timedelta(days=14)).isoformat(),
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
    replacement = await auth.establish(connection, cast("accounts_module.LocalAccount[object]", store.account))
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


@pytest.mark.anyio
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
        cast("accounts_module.LocalAccount[object]", store.account),
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
@pytest.mark.anyio
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
        await auth.establish(establishing_connection, cast("accounts_module.LocalAccount[object]", store.account)),
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
@pytest.mark.anyio
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
        establishing_connection, cast("accounts_module.LocalAccount[object]", store.account)
    )
    assert isinstance(established, accounts_module.SessionAuthentication)
    if invalid_state == "missing":
        store.records.clear()
    elif invalid_state in {"disabled", "unverified"}:
        store.account = accounts_module.LocalAccount(
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


@pytest.mark.anyio
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
    current = await auth.establish(connection, cast("accounts_module.LocalAccount[object]", store.account))
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


@pytest.mark.anyio
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
    current = await auth.establish(connection, cast("accounts_module.LocalAccount[object]", store.account))
    assert isinstance(current, accounts_module.SessionAuthentication)
    assert auth.current_authentication(connection) == current

    plan = auth.prepare_password_rebind(connection, cast("accounts_module.LocalAccount[object]", store.account))
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
        auth.prepare_password_rebind(empty_connection, cast("accounts_module.LocalAccount[object]", store.account)),
        VerificationUnavailable,
    )
    assert isinstance(
        replace(auth, entropy=lambda _size: b"").prepare_password_rebind(
            connection, cast("accounts_module.LocalAccount[object]", store.account)
        ),
        VerificationUnavailable,
    )

    assert not await auth.activate_password_rebind(connection, cast("Any", object()), 2)
    assert auth.current_authentication(connection) is None

    current = await auth.establish(connection, cast("accounts_module.LocalAccount[object]", store.account))
    assert isinstance(current, accounts_module.SessionAuthentication)
    failed_plan = auth.prepare_password_rebind(connection, cast("accounts_module.LocalAccount[object]", store.account))
    assert isinstance(failed_plan, accounts_module.SessionRebindPlan)

    async def failing_get(_session_id: str) -> accounts_module.SessionRecord | None:
        raise OSError

    original_get = store.get
    store.get = failing_get  # type: ignore[method-assign]
    assert not await auth.activate_password_rebind(connection, failed_plan, 2)
    store.get = original_get  # type: ignore[method-assign]

    current = await auth.establish(connection, cast("accounts_module.LocalAccount[object]", store.account))
    assert isinstance(current, accounts_module.SessionAuthentication)
    missing_plan = auth.prepare_password_rebind(connection, cast("accounts_module.LocalAccount[object]", store.account))
    assert isinstance(missing_plan, accounts_module.SessionRebindPlan)
    assert not await auth.activate_password_rebind(connection, missing_plan, 2)

    current = await auth.establish(connection, cast("accounts_module.LocalAccount[object]", store.account))
    assert isinstance(current, accounts_module.SessionAuthentication)
    mismatch_plan = auth.prepare_password_rebind(
        connection, cast("accounts_module.LocalAccount[object]", store.account)
    )
    assert isinstance(mismatch_plan, accounts_module.SessionRebindPlan)
    store.records[mismatch_plan.command.session_id] = _NativeSessionStore.record(
        replace(mismatch_plan.command, security_epoch=3)
    )
    assert not await auth.activate_password_rebind(connection, mismatch_plan, 2)


@pytest.mark.anyio
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
    current = await auth.establish(connection, cast("accounts_module.LocalAccount[object]", store.account))
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
        await auth.establish(websocket, cast("accounts_module.LocalAccount[object]", store.account)),
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


@pytest.mark.anyio
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
        establishing_connection, cast("accounts_module.LocalAccount[object]", store.account)
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
@pytest.mark.anyio
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
        account = accounts_module.LocalAccount(
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

    outcome = await auth.establish(connection, cast("accounts_module.LocalAccount[object]", account))

    assert isinstance(outcome, VerificationUnavailable)
    assert session == {"anonymous": "value"}
    assert "_litestar_security_response_headers" not in connection.scope


@pytest.mark.parametrize("mutation", ["separator", "binding", "secret", "version", "boolean_version", "timestamp"])
@pytest.mark.anyio
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
        await auth.establish(establishing_connection, cast("accounts_module.LocalAccount[object]", store.account)),
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
            payload["version"] = True if mutation == "boolean_version" else 3
        else:
            payload["authenticated_at"] = "not-a-timestamp"
    connection = _native_session_connection(session, binding_token=token)

    outcome = auth.extract(connection)

    assert isinstance(outcome, InvalidCredentials)
    assert "_litestar_security" not in session


@pytest.mark.anyio
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
    current = await auth.establish(connection, cast("accounts_module.LocalAccount[object]", store.account))
    assert isinstance(current, accounts_module.SessionAuthentication)
    store.failures.add("revoke")

    assert isinstance(await auth.revoke_session(connection, "account-1", current.session_id), VerificationUnavailable)
    assert "_litestar_security" in session
    assert not await auth.revoke_session(connection, " ", current.session_id)
    assert not await auth.revoke_session(connection, "account-1", "invalid")
    assert isinstance(await auth.logout(connection), VerificationUnavailable)
    assert "_litestar_security" not in session


@pytest.mark.anyio
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
    current = await auth.establish(connection, cast("accounts_module.LocalAccount[object]", store.account))
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

    replacement = await auth.establish(connection, cast("accounts_module.LocalAccount[object]", store.account))
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


class _LocalAccessStore(_PasswordStore):
    def __init__(
        self,
        account: accounts_module.LocalAccount[object] | None,
        *,
        fail_lookup: bool = False,
        fail_password_read: bool = False,
        fail_epoch: bool = False,
    ) -> None:
        super().__init__(
            fail_read=fail_password_read, security_epoch=account.security_epoch if account is not None else 1
        )
        self.account = account
        self.fail_lookup = fail_lookup
        self.fail_epoch = fail_epoch
        self.login_lookups: list[str] = []
        self.id_lookups: list[str] = []

    async def find_for_login(self, normalized_identifier: str) -> accounts_module.LocalAccount[object] | None:
        self.login_lookups.append(normalized_identifier)
        if self.fail_lookup:
            raise OSError
        return self.account

    async def get_by_id(self, account_id: str) -> accounts_module.LocalAccount[object] | None:
        self.id_lookups.append(account_id)
        if self.fail_lookup:
            raise OSError
        return self.account if self.account is not None and self.account.account_id == account_id else None

    async def current_epoch(self, account_id: str) -> int | None:
        if self.fail_epoch:
            raise OSError
        return await super().current_epoch(account_id)


def _local_access_account(
    *, active: bool = True, verified: bool = True, security_epoch: int = 3
) -> accounts_module.LocalAccount[object]:
    return accounts_module.LocalAccount(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Local Person",
        active=active,
        verified=verified,
        security_epoch=security_epoch,
        user={"safe": "application object"},
    )


@pytest.mark.parametrize(
    ("account", "fail_lookup", "fail_password_read", "hasher_unavailable", "expected_type"),
    [
        (_local_access_account(), False, False, False, accounts_module.LocalAccount),
        (None, False, False, False, InvalidCredentials),
        (_local_access_account(active=False), False, False, False, InvalidCredentials),
        (_local_access_account(verified=False), False, False, False, InvalidCredentials),
        (_local_access_account(), True, False, False, VerificationUnavailable),
        (_local_access_account(), False, True, False, VerificationUnavailable),
        (_local_access_account(), False, False, True, VerificationUnavailable),
    ],
)
@pytest.mark.anyio
async def test_password_login_is_constant_work_and_returns_structured_outcomes(
    account: accounts_module.LocalAccount[object] | None,
    fail_lookup: bool,  # noqa: FBT001
    fail_password_read: bool,  # noqa: FBT001
    hasher_unavailable: bool,  # noqa: FBT001
    expected_type: type[object],
) -> None:
    store = _LocalAccessStore(account, fail_lookup=fail_lookup, fail_password_read=fail_password_read)
    hasher = _PasswordHasher(
        accounts_module.PasswordVerificationResult(accounts_module.PasswordVerificationStatus.VERIFIED),
        unavailable=hasher_unavailable,
    )
    service = accounts_module.PasswordLoginService(accounts=store, hasher=hasher)

    outcome = await service.authenticate(" Person@Example.com ", "presented secret", now=_JWT_NOW)

    assert isinstance(outcome, expected_type)
    assert len(hasher.calls) == 1
    assert hasher.calls[0][1] == "presented secret"
    if account is None or fail_lookup or fail_password_read:
        assert hasher.calls[0][0] is None


@pytest.mark.parametrize("scope", ["admin read", "admin\tread", '"quoted', "back\\slash", "é"])
def test_access_token_claims_reject_non_oauth_scope_tokens(scope: str) -> None:
    with pytest.raises(ValueError, match="scope"):
        build_access_token_claims(
            issuer=_JWT_ISSUER,
            audience=_JWT_AUDIENCE,
            subject="account-1",
            client_id="local",
            security_epoch=1,
            now=_JWT_NOW,
            lifetime=timedelta(minutes=10),
            scopes=frozenset({scope}),
        )


@pytest.mark.anyio
async def test_local_access_issue_cross_verifies_exact_minimal_claims_without_generic_scope_grants(
    local_key_ring: LocalKeyRing,
) -> None:
    account = _local_access_account()
    issuer = accounts_module.LocalAccessTokenIssuer(
        signer=local_key_ring.build_signer(),
        issuer=local_key_ring.issuer,
        audience=_JWT_AUDIENCE,
        client_id="local-web",
        clock=lambda: _JWT_NOW,
        token_ids=lambda: "access-token-1",
    )

    issued = await issuer.issue(account, scopes=frozenset({"write", "read"}))

    assert isinstance(issued, accounts_module.LocalAccessToken)
    assert (issued.token_type, issued.expires_in) == ("Bearer", 600)
    assert "access_token" not in repr(issued)
    verifier = local_key_ring.build_verifier(
        JWTValidationConfig(
            issuer=local_key_ring.issuer,
            audiences=frozenset({_JWT_AUDIENCE}),
            algorithms=frozenset(key.algorithm for key in local_key_ring.all_verification_keys),
            required_claims=frozenset({"se"}),
            maximum_lifetime=timedelta(minutes=10),
        ),
        mechanism_name="bearer",
        slot_name="local",
    )
    outcome = await verifier.verify(issued.access_token, now=_JWT_NOW)

    assert isinstance(outcome, Authenticated)
    assert outcome.grants == AuthorizationSnapshot()
    assert outcome.claims.raw == {
        "iss": local_key_ring.issuer,
        "sub": "account-1",
        "aud": _JWT_AUDIENCE,
        "exp": int((_JWT_NOW + timedelta(minutes=10)).timestamp()),
        "iat": int(_JWT_NOW.timestamp()),
        "client_id": "local-web",
        "jti": "access-token-1",
        "se": 3,
        "scope": "read write",
    }
    serialized_claims = json.dumps(dict(outcome.claims.raw))
    for forbidden in ("person@example.com", "Local Person", "application object", "password", "roles", "team"):
        assert forbidden not in serialized_claims


@pytest.mark.anyio
async def test_local_access_token_preserves_passkey_assurance(local_key_ring: LocalKeyRing) -> None:
    validation = JWTValidationConfig(
        issuer=local_key_ring.issuer,
        audiences=frozenset({_JWT_AUDIENCE}),
        algorithms=frozenset(key.algorithm for key in local_key_ring.all_verification_keys),
        required_claims=frozenset({"se"}),
        maximum_lifetime=timedelta(minutes=10),
    )
    issuer = accounts_module.LocalAccessTokenIssuer(
        signer=local_key_ring.build_signer(),
        issuer=local_key_ring.issuer,
        audience=_JWT_AUDIENCE,
        clock=lambda: _JWT_NOW,
        token_ids=lambda: "passkey-access-token",
    )
    evidence = AuthenticationEvidence(
        mechanism="passkey",
        slot="mfa",
        authenticated_at=_JWT_NOW,
        methods=frozenset({"passkey"}),
        traits=frozenset({"phishing-resistant", "user-verified"}),
        amr=("passkey",),
    )
    issued = await issuer.issue(_local_access_account(), evidence=evidence)
    assert isinstance(issued, accounts_module.LocalAccessToken)
    verifier = access_tokens_module.LocalAccessVerifier(
        config=validation,
        verifier=local_key_ring.build_verifier(validation, mechanism_name="bearer", slot_name="local"),
    )

    outcome = await verifier.verify(issued.access_token, now=_JWT_NOW)

    assert isinstance(outcome, Authenticated)
    assert outcome.evidence.methods == frozenset({"passkey"})
    assert outcome.evidence.traits == frozenset({"phishing-resistant", "user-verified"})
    assert outcome.evidence.amr == ("passkey",)

    class InvalidAssuranceVerifier:
        async def verify(self, _token: str, *, now: datetime) -> object:
            del now
            return replace(outcome, claims=replace(outcome.claims, raw={**outcome.claims.raw, "amr": ["bad value"]}))

    invalid = access_tokens_module.LocalAccessVerifier(
        config=validation, verifier=cast("Any", InvalidAssuranceVerifier())
    )
    assert isinstance(await invalid.verify("token", now=_JWT_NOW), InvalidCredentials)
    assert access_tokens_module._claim_set("passkey") is None  # noqa: SLF001 - defensive parser branch

    malformed = dict(outcome.claims.raw)
    malformed["amr"] = []
    with pytest.raises(ValueError, match="Invalid local access-token claims"):
        jwt_claims.validate_local_access_claims(malformed, issuer=local_key_ring.issuer, now=_JWT_NOW)
    malformed = dict(outcome.claims.raw)
    malformed["auth_time"] = int(_JWT_NOW.timestamp()) + 1
    with pytest.raises(ValueError, match="Invalid local access-token claims"):
        jwt_claims.validate_local_access_claims(malformed, issuer=local_key_ring.issuer, now=_JWT_NOW)
    with pytest.raises(ValueError, match="authentication time"):
        build_access_token_claims(
            issuer=local_key_ring.issuer,
            audience=_JWT_AUDIENCE,
            subject="account-1",
            client_id="local",
            security_epoch=1,
            now=_JWT_NOW,
            lifetime=timedelta(minutes=10),
            authenticated_at=_JWT_NOW + timedelta(seconds=1),
        )
    invalid_time: object = True
    assert access_tokens_module._claim_authentication_time(invalid_time, fallback=_JWT_NOW) is None  # noqa: SLF001
    assert (
        access_tokens_module._claim_authentication_time(10**30, fallback=_JWT_NOW)  # noqa: SLF001
        is None
    )


@pytest.mark.parametrize(
    ("account", "fail_lookup", "fail_epoch", "epoch", "expected_type"),
    [
        (_local_access_account(), False, False, 3, Principal),
        (None, False, False, 3, InvalidCredentials),
        (_local_access_account(active=False), False, False, 3, InvalidCredentials),
        (_local_access_account(verified=False), False, False, 3, InvalidCredentials),
        (_local_access_account(), True, False, 3, VerificationUnavailable),
        (_local_access_account(), False, True, 3, VerificationUnavailable),
        (_local_access_account(), False, False, 2, InvalidCredentials),
    ],
)
@pytest.mark.anyio
async def test_local_bearer_identity_resolution_checks_account_and_exact_epoch(
    account: accounts_module.LocalAccount[object] | None,
    fail_lookup: bool,  # noqa: FBT001
    fail_epoch: bool,  # noqa: FBT001
    epoch: int,
    expected_type: type[object],
) -> None:
    store = _LocalAccessStore(account, fail_lookup=fail_lookup, fail_epoch=fail_epoch)
    resolver = accounts_module.LocalBearerIdentityResolver(accounts=store)
    claims = JWTClaims(
        issuer=_JWT_ISSUER,
        subject="account-1",
        audiences=frozenset({_JWT_AUDIENCE}),
        expires_at=_JWT_NOW + timedelta(minutes=10),
        issued_at=_JWT_NOW,
        not_before=None,
        token_id="access-token-1",  # noqa: S106 - public JWT identifier
        client_id="local",
        scopes=frozenset(),
        raw={"se": epoch},
    )

    outcome = await resolver.resolve(claims)

    assert isinstance(outcome, expected_type)
    if isinstance(outcome, Principal):
        assert (outcome.id, outcome.display_name, outcome.user) == (
            "account-1",
            "Local Person",
            {"safe": "application object"},
        )


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"accounts": object()}, "AccountLookup"),
        ({"hasher": object()}, "PasswordHasher"),
        ({"normalizer": None}, "normalizer"),
    ],
)
def test_password_login_rejects_invalid_configuration(kwargs: dict[str, object], match: str) -> None:
    values = {"accounts": _LocalAccessStore(_local_access_account()), "hasher": _PasswordHasher(), **kwargs}

    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.PasswordLoginService(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("identifier", "unavailable", "expected_type"),
    [(" ", False, InvalidCredentials), ("person@example.com", True, VerificationUnavailable)],
)
@pytest.mark.anyio
async def test_password_login_dummy_work_handles_empty_identifiers_and_worker_failure(
    identifier: str,
    unavailable: bool,  # noqa: FBT001
    expected_type: type[object],
) -> None:
    hasher = _PasswordHasher(unavailable=unavailable)
    service = accounts_module.PasswordLoginService(accounts=_LocalAccessStore(None), hasher=hasher)

    outcome = await service.authenticate(identifier, "presented secret", now=_JWT_NOW)

    assert isinstance(outcome, expected_type)
    assert hasher.calls == [(None, "presented secret")]


@pytest.mark.parametrize(
    ("token", "expires_in"),
    [
        (cast("Any", object()), 600),
        ("not-compact", 600),
        ("a..c", 600),
        ("a.b.c", 600),
        ("e30.%.YQ", 600),
        ("é.b.c", 600),
        ("e30.e30.YQ", True),
        ("e30.e30.YQ", 29),
        ("e30.e30.YQ", 3_601),
    ],
)
def test_local_access_token_rejects_invalid_response_values(token: object, expires_in: int) -> None:
    with pytest.raises(ValueError, match="bounded expiry"):
        accounts_module.LocalAccessToken(access_token=token, expires_in=expires_in)  # type: ignore[arg-type]


class _AccessSigner:
    def __init__(self, token: str = "e30.e30.YQ", *, fail: bool = False) -> None:  # noqa: S107
        self.token = token
        self.fail = fail
        self.claims: list[Mapping[str, object]] = []

    async def sign(self, claims: Mapping[str, object], *, now: datetime) -> str:
        del now
        if self.fail:
            raise OSError
        self.claims.append(claims)
        return self.token


class _MFAProtector:
    active_key_version = "test-key"

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.plaintexts: dict[bytes, bytes] = {}
        self.associated_data: list[bytes] = []

    async def protect(self, secret: bytes, *, associated_data: bytes) -> accounts_module.ProtectedSecret:
        if self.fail:
            raise OSError
        ciphertext = b"ciphertext-" + len(self.plaintexts).to_bytes(2, "big")
        self.plaintexts[ciphertext] = secret
        self.associated_data.append(associated_data)
        return accounts_module.ProtectedSecret(ciphertext=ciphertext, key_version=self.active_key_version)

    async def unprotect(self, protected: accounts_module.ProtectedSecret, *, associated_data: bytes) -> bytes:
        if self.fail:
            raise OSError
        self.associated_data.append(associated_data)
        return self.plaintexts[protected.ciphertext]


class _MFAStore:
    def __init__(self) -> None:
        self.enrollments: dict[str, accounts_module.PendingTOTPEnrollment] = {}
        self.methods: dict[str, accounts_module.TOTPMethod] = {}
        self.recovery_codes: dict[bytes, accounts_module.RecoveryCodeDigest] = {}
        self.login_methods: dict[str, accounts_module.LoginMethod] = {}
        self.events: list[accounts_module.SecurityEvent] = []
        self.lock = asyncio.Lock()
        self.fail = False

    async def create_totp_enrollment(self, enrollment: accounts_module.PendingTOTPEnrollment) -> None:
        if self.fail:
            raise OSError
        self.enrollments[enrollment.enrollment_id] = enrollment

    async def get_totp_enrollment(self, enrollment_id: str) -> accounts_module.PendingTOTPEnrollment | None:
        if self.fail:
            raise OSError
        return self.enrollments.get(enrollment_id)

    async def activate_totp(  # noqa: PLR0913 - mirrors the atomic application port
        self,
        account_id: str,
        enrollment_id: str,
        *,
        accepted_counter: int,
        login_method: accounts_module.LoginMethod,
        event: accounts_module.SecurityEvent,
        now: datetime,
    ) -> accounts_module.TOTPMethod | None:
        if self.fail:
            raise OSError
        async with self.lock:
            enrollment = self.enrollments.pop(enrollment_id, None)
            if enrollment is None or enrollment.account_id != account_id or enrollment.expires_at <= now:
                return None
            method = accounts_module.TOTPMethod(
                method_id=enrollment.method_id,
                account_id=account_id,
                protected_secret=enrollment.protected_secret,
                policy=enrollment.policy,
                last_accepted_counter=accepted_counter,
                created_at=now,
            )
            self.methods[method.method_id] = method
            self.login_methods[login_method.method_id] = login_method
            self.events.append(event)
            return method

    async def activate_totp_with_recovery_codes(  # noqa: PLR0913 - mirrors the atomic application port
        self,
        account_id: str,
        enrollment_id: str,
        *,
        accepted_counter: int,
        codes: tuple[accounts_module.RecoveryCodeDigest, ...],
        login_method: accounts_module.LoginMethod,
        event: accounts_module.SecurityEvent,
        now: datetime,
    ) -> accounts_module.TOTPMethod | None:
        async with self.lock:
            enrollment = self.enrollments.get(enrollment_id)
            if self.fail:
                raise OSError
            if enrollment is None or enrollment.account_id != account_id or enrollment.expires_at <= now:
                return None
            method = accounts_module.TOTPMethod(
                method_id=enrollment.method_id,
                account_id=account_id,
                protected_secret=enrollment.protected_secret,
                policy=enrollment.policy,
                last_accepted_counter=accepted_counter,
                created_at=now,
            )
            del self.enrollments[enrollment_id]
            self.methods[method.method_id] = method
            self.recovery_codes = {code.digest: code for code in codes}
            self.login_methods[login_method.method_id] = login_method
            self.events.append(event)
            return method

    async def get_totp_method(self, account_id: str, method_id: str) -> accounts_module.TOTPMethod | None:
        if self.fail:
            raise OSError
        method = self.methods.get(method_id)
        return method if method is not None and method.account_id == account_id else None

    async def advance_totp_counter(self, method_id: str, *, accepted_counter: int, now: datetime) -> bool:
        if self.fail:
            raise OSError
        async with self.lock:
            method = self.methods.get(method_id)
            if method is None or accepted_counter <= method.last_accepted_counter:
                return False
            self.methods[method_id] = replace(method, last_accepted_counter=accepted_counter, last_used_at=now)
            return True

    async def replace_recovery_codes(
        self, account_id: str, codes: tuple[accounts_module.RecoveryCodeDigest, ...], *, now: datetime
    ) -> None:
        del now
        if self.fail:
            raise OSError
        async with self.lock:
            self.recovery_codes = {code.digest: code for code in codes if code.account_id == account_id}

    async def consume_recovery_code(self, account_id: str, digest: bytes, *, now: datetime) -> bool:
        del now
        if self.fail:
            raise OSError
        async with self.lock:
            match = next(
                (
                    stored_digest
                    for stored_digest in self.recovery_codes
                    if hmac.compare_digest(stored_digest, digest)
                    and self.recovery_codes[stored_digest].account_id == account_id
                ),
                None,
            )
            if match is None:
                return False
            del self.recovery_codes[match]
            return True


class _RecoveryLoginMethods:
    def __init__(
        self, status: accounts_module.RevokeLoginMethodStatus = accounts_module.RevokeLoginMethodStatus.REVOKED
    ) -> None:
        self.status = status
        self.events: list[accounts_module.SecurityEvent] = []

    async def register_login_method(
        self, account_id: str, method: accounts_module.LoginMethod, *, event: accounts_module.SecurityEvent
    ) -> None:
        del account_id, method
        self.events.append(event)

    async def revoke_login_method(
        self, account_id: str, method_id: str, *, require_remaining: bool = True, event: accounts_module.SecurityEvent
    ) -> accounts_module.RevokeLoginMethodResult:
        del account_id, method_id
        assert require_remaining
        self.events.append(event)
        return accounts_module.RevokeLoginMethodResult(self.status)


def _mfa_service(
    store: _MFAStore,
    protector: _MFAProtector,
    *,
    policy: accounts_module.TOTPPolicy = _MFA_POLICY,
    encoded_seed: str = _MFA_ENCODED_SEED,
    now: datetime = _MFA_VECTOR_NOW,
) -> accounts_module.MFAService:
    identifiers = iter(("enrollment-1", "method-1"))
    return accounts_module.MFAService(
        store=store,
        secret_protector=protector,
        policy=policy,
        issuer="Litestar Security",
        clock=lambda: now,
        secret_generator=lambda: encoded_seed,
        identifiers=lambda: next(identifiers),
    )


@pytest.mark.parametrize(
    ("algorithm", "secret", "code"),
    [
        ("SHA1", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "94287082"),
        ("SHA256", base64.b32encode(b"12345678901234567890123456789012").decode(), "46119246"),
        (
            "SHA512",
            base64.b32encode(b"1234567890123456789012345678901234567890123456789012345678901234").decode(),
            "90693936",
        ),
    ],
)
@pytest.mark.anyio
async def test_totp_enrollment_uses_rfc_vectors_and_persists_only_protected_secret(
    algorithm: str, secret: str, code: str
) -> None:
    store = _MFAStore()
    protector = _MFAProtector()
    service = _mfa_service(
        store,
        protector,
        policy=accounts_module.TOTPPolicy(digits=8, algorithm=cast("Any", algorithm), allowed_drift_steps=0),
        encoded_seed=secret,
    )

    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")

    assert isinstance(enrollment, accounts_module.TOTPEnrollment)
    assert "secret=" in enrollment.provisioning_uri
    assert secret not in repr(enrollment)
    assert secret.encode() not in repr(store.enrollments).encode()
    activated = await service.activate_totp("account-1", enrollment.enrollment_id, code)
    assert isinstance(activated, accounts_module.TOTPMethod)
    assert activated.last_accepted_counter == 1
    assert b"account-1" in protector.associated_data[0]
    assert b"method-1" in protector.associated_data[0]
    assert b"totp" in protector.associated_data[0]
    assert b"test-key" in protector.associated_data[0]


@pytest.mark.anyio
async def test_totp_counter_advance_allows_one_concurrent_use_and_rejects_replay() -> None:
    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    store = _MFAStore()
    protector = _MFAProtector()
    service = _mfa_service(store, protector, now=now)
    events = _SecurityEvents()
    service.events = events
    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(enrollment, accounts_module.TOTPEnrollment)
    code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", interval=30).at(now)
    assert isinstance(
        await service.activate_totp("account-1", enrollment.enrollment_id, code), accounts_module.TOTPMethod
    )
    next_time = now + timedelta(seconds=30)
    next_code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", interval=30).at(next_time)
    service.clock = lambda: next_time
    outcomes: list[object] = []

    async def verify() -> None:
        outcomes.append(await service.verify_totp("account-1", "method-1", next_code))

    async with create_task_group() as task_group:
        task_group.start_soon(verify)
        task_group.start_soon(verify)

    assert sum(isinstance(outcome, AuthenticationEvidence) for outcome in outcomes) == 1
    assert sum(isinstance(outcome, InvalidCredentials) for outcome in outcomes) == 1
    assert [(event.operation, event.outcome) for event in events.events] == [
        ("local.mfa.totp.enroll", "created"),
        ("local.mfa.totp.verify", "verified"),
    ]
    assert isinstance(await service.verify_totp("account-1", "method-1", next_code), InvalidCredentials)


@pytest.mark.parametrize(
    ("policy_kwargs", "match"),
    [
        ({"digits": 7}, "digits"),
        ({"period_seconds": 0}, "period"),
        ({"algorithm": "MD5"}, "algorithm"),
        ({"allowed_drift_steps": -1}, "drift"),
        ({"enrollment_ttl": timedelta()}, "lifetime"),
    ],
)
def test_totp_policy_rejects_unsupported_or_unbounded_profiles(policy_kwargs: dict[str, object], match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.TOTPPolicy(**policy_kwargs)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_totp_drift_account_and_expiry_failures_are_generic() -> None:
    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    store = _MFAStore()
    protector = _MFAProtector()
    service = _mfa_service(store, protector, now=now)
    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(enrollment, accounts_module.TOTPEnrollment)
    code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", interval=30).at(now)

    assert isinstance(await service.activate_totp("account-2", enrollment.enrollment_id, code), InvalidCredentials)
    service.clock = lambda: enrollment.expires_at
    assert isinstance(await service.activate_totp("account-1", enrollment.enrollment_id, code), InvalidCredentials)

    service = _mfa_service(store := _MFAStore(), protector := _MFAProtector(), now=now)
    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(enrollment, accounts_module.TOTPEnrollment)
    future_code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", interval=30).at(now + timedelta(seconds=30))
    activated = await service.activate_totp("account-1", enrollment.enrollment_id, future_code)
    assert isinstance(activated, accounts_module.TOTPMethod)
    service.clock = lambda: now + timedelta(seconds=60)
    too_far_code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", interval=30).at(now + timedelta(seconds=120))
    assert isinstance(await service.verify_totp("account-1", activated.method_id, too_far_code), InvalidCredentials)
    assert isinstance(await service.verify_totp("account-2", activated.method_id, future_code), InvalidCredentials)


@pytest.mark.parametrize("failure", ["protect", "store", "unprotect"])
@pytest.mark.anyio
async def test_totp_protector_and_store_failures_are_sanitized(failure: str) -> None:
    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    store = _MFAStore()
    protector = _MFAProtector(fail=failure == "protect")
    service = _mfa_service(store, protector, now=now)
    if failure == "store":
        store.fail = True

    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")

    if failure in {"protect", "store"}:
        assert isinstance(enrollment, VerificationUnavailable)
        assert "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" not in repr(enrollment)
        return
    assert isinstance(enrollment, accounts_module.TOTPEnrollment)
    protector.fail = True
    code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", interval=30).at(now)
    outcome = await service.activate_totp("account-1", enrollment.enrollment_id, code)
    assert isinstance(outcome, VerificationUnavailable)
    assert "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" not in repr(outcome)


@pytest.mark.anyio
async def test_recovery_codes_are_reveal_once_digest_only_and_atomically_consumed() -> None:
    store = _MFAStore()
    service = _mfa_service(store, _MFAProtector())
    service.recovery_peppers = (accounts_module.RecoveryCodePepper(key_version="v1", key=b"p" * 32),)
    entropy_counter = iter(range(1, 11))
    service.recovery_entropy = lambda length: next(entropy_counter).to_bytes(length, "big")

    issued = await service.generate_recovery_codes("account-1")

    assert isinstance(issued, accounts_module.RecoveryCodes)
    assert len(issued.codes) == 10
    assert len(set(issued.codes)) == 10
    assert all(code.startswith("rc_v1_") and len(code) == 38 for code in issued.codes)
    assert issued.codes[0] not in repr(issued)
    assert issued.codes[0].encode() not in repr(store.recovery_codes).encode()
    outcomes: list[object] = []

    async def consume() -> None:
        outcomes.append(await service.consume_recovery_code("account-1", issued.codes[0]))

    async with create_task_group() as task_group:
        task_group.start_soon(consume)
        task_group.start_soon(consume)

    assert sum(isinstance(outcome, AuthenticationEvidence) for outcome in outcomes) == 1
    assert sum(isinstance(outcome, InvalidCredentials) for outcome in outcomes) == 1


@pytest.mark.anyio
async def test_recovery_regeneration_invalidates_old_codes_and_pepper_versions_are_explicit() -> None:
    entropy_values = iter((b"\x01" * 16, b"\x02" * 16, b"\x03" * 16))
    store = _MFAStore()
    service = _mfa_service(store, _MFAProtector())
    v1 = accounts_module.RecoveryCodePepper(key_version="v1", key=b"p" * 32)
    v2 = accounts_module.RecoveryCodePepper(key_version="v2", key=b"q" * 32)
    service.recovery_peppers = (v1,)
    service.recovery_code_count = 1
    service.recovery_entropy = lambda _length: next(entropy_values)
    first = await service.generate_recovery_codes("account-1")
    assert isinstance(first, accounts_module.RecoveryCodes)
    service.recovery_peppers = (v2, v1)
    assert isinstance(await service.consume_recovery_code("account-1", first.codes[0]), AuthenticationEvidence)
    service.recovery_peppers = (v1,)
    stale = await service.generate_recovery_codes("account-1")
    assert isinstance(stale, accounts_module.RecoveryCodes)
    service.recovery_peppers = (v2, v1)
    second = await service.generate_recovery_codes("account-1")
    assert isinstance(second, accounts_module.RecoveryCodes)
    assert second.codes[0].startswith("rc_v2_")
    assert isinstance(await service.consume_recovery_code("account-1", stale.codes[0]), InvalidCredentials)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (accounts_module.RevokeLoginMethodStatus.REVOKED, accounts_module.RevokeLoginMethodStatus.REVOKED),
        (accounts_module.RevokeLoginMethodStatus.FINAL_METHOD, accounts_module.RevokeLoginMethodStatus.FINAL_METHOD),
    ],
)
@pytest.mark.anyio
async def test_totp_removal_delegates_atomic_final_method_safety_and_redacts_events(
    status: accounts_module.RevokeLoginMethodStatus, expected: accounts_module.RevokeLoginMethodStatus
) -> None:
    login_methods = _RecoveryLoginMethods(status)
    service = _mfa_service(_MFAStore(), _MFAProtector())
    service.login_methods = login_methods

    outcome = await service.remove_totp_method("account-1", "method-1")

    assert isinstance(outcome, accounts_module.RevokeLoginMethodResult)
    assert outcome.status is expected
    assert len(login_methods.events) == 1
    assert login_methods.events[0].operation == "local.mfa.totp.remove"
    assert "secret" not in repr(login_methods.events[0]).lower()


@pytest.mark.parametrize(
    ("case", "expected_type"),
    [
        ("unconfigured", VerificationUnavailable),
        ("duplicate_entropy", VerificationUnavailable),
        ("store_replace", VerificationUnavailable),
        ("malformed", InvalidCredentials),
        ("unknown_version", InvalidCredentials),
        ("store_consume", VerificationUnavailable),
    ],
)
@pytest.mark.anyio
async def test_recovery_failures_are_generic_and_never_leak_codes(case: str, expected_type: type[object]) -> None:
    store = _MFAStore()
    service = _mfa_service(store, _MFAProtector())
    pepper = accounts_module.RecoveryCodePepper(key_version="v1", key=b"p" * 32)
    if case != "unconfigured":
        service.recovery_peppers = (pepper,)
    service.recovery_code_count = 1
    service.recovery_entropy = lambda length: b"\x01" * length
    if case == "duplicate_entropy":
        service.recovery_code_count = 2
    if case == "store_replace":
        store.fail = True
    if case in {"unconfigured", "duplicate_entropy", "store_replace"}:
        outcome = await service.generate_recovery_codes("account-1")
    else:
        issued = await service.generate_recovery_codes("account-1")
        assert isinstance(issued, accounts_module.RecoveryCodes)
        code = (
            "malformed"
            if case == "malformed"
            else issued.codes[0].replace("rc_v1_", "rc_old_")
            if case == "unknown_version"
            else issued.codes[0]
        )
        if case == "store_consume":
            store.fail = True
        outcome = await service.consume_recovery_code("account-1", code)

    assert isinstance(outcome, expected_type)
    assert "01010101" not in repr(outcome)


@pytest.mark.anyio
async def test_recovery_audit_failure_cannot_reverse_settled_generation_or_consumption() -> None:
    store = _MFAStore()
    service = _mfa_service(store, _MFAProtector())
    service.events = _SecurityEvents(fail=True)
    service.recovery_peppers = (accounts_module.RecoveryCodePepper(key_version="v1", key=b"p" * 32),)
    service.recovery_code_count = 1
    service.recovery_entropy = lambda length: b"\x01" * length

    issued = await service.generate_recovery_codes("account-1")

    assert isinstance(issued, accounts_module.RecoveryCodes)
    assert isinstance(await service.consume_recovery_code("account-1", issued.codes[0]), AuthenticationEvidence)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"key_version": " ", "key": b"p" * 32},
        {"key_version": "bad_version", "key": b"p" * 32},
        {"key_version": "v1", "key": b"short"},
    ],
)
def test_recovery_pepper_rejects_ambiguous_or_short_keys(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Recovery-code pepper"):
        accounts_module.RecoveryCodePepper(**kwargs)  # type: ignore[arg-type]


class _ChallengeStore:
    def __init__(self) -> None:
        self.records: dict[bytes, accounts_module.WebAuthnChallenge] = {}
        self.lock = asyncio.Lock()
        self.fail = False

    async def put(self, challenge: accounts_module.WebAuthnChallenge) -> None:
        if self.fail:
            raise OSError
        self.records[challenge.challenge_digest] = challenge

    async def consume(
        self, challenge_digest: bytes, *, binding_digest: bytes, purpose: str, now: datetime
    ) -> accounts_module.WebAuthnChallenge | None:
        if self.fail:
            raise OSError
        async with self.lock:
            challenge = self.records.pop(challenge_digest, None)
            if (
                challenge is None
                or challenge.binding_digest != binding_digest
                or challenge.purpose != purpose
                or challenge.expires_at <= now
            ):
                return None
            return challenge


class _PasskeyStore:
    def __init__(self) -> None:
        self.credentials: dict[bytes, accounts_module.PasskeyCredential] = {}
        self.login_methods: dict[str, accounts_module.LoginMethod] = {}
        self.events: list[accounts_module.SecurityEvent] = []
        self.fail = False

    async def add_credential(
        self,
        credential: accounts_module.PasskeyCredential,
        *,
        login_method: accounts_module.LoginMethod,
        event: accounts_module.SecurityEvent,
    ) -> bool:
        if self.fail:
            raise OSError
        if credential.credential_id in self.credentials:
            return False
        self.credentials[credential.credential_id] = credential
        self.login_methods[login_method.method_id] = login_method
        self.events.append(event)
        return True

    async def get_credential(self, credential_id: bytes) -> accounts_module.PasskeyCredential | None:
        if self.fail:
            raise OSError
        return self.credentials.get(credential_id)

    async def record_assertion(  # noqa: PLR0913 - mirrors the explicit atomic application port
        self,
        credential_id: bytes,
        *,
        expected_version: int,
        sign_count: int,
        backup_eligible: bool,
        backup_state: bool,
        clone_risk: bool,
        now: datetime,
    ) -> accounts_module.AssertionRecordResult:
        del now
        credential = self.credentials.get(credential_id)
        if self.fail:
            raise OSError
        if (
            credential is None
            or credential.version != expected_version
            or credential.backup_eligible != backup_eligible
        ):
            return accounts_module.AssertionRecordResult.CONFLICT
        self.credentials[credential_id] = replace(
            credential,
            sign_count=sign_count,
            backup_state=backup_state,
            suspect=clone_risk,
            version=credential.version + 1,
            last_used_at=_JWT_NOW,
        )
        if clone_risk:
            return accounts_module.AssertionRecordResult.CLONE_RISK
        return accounts_module.AssertionRecordResult.RECORDED

    async def list_credentials(self, account_id: str) -> tuple[accounts_module.PasskeyCredential, ...]:
        if self.fail:
            raise OSError
        return tuple(credential for credential in self.credentials.values() if credential.account_id == account_id)

    async def rename_credential(
        self, account_id: str, credential_id: bytes, display_name: str
    ) -> accounts_module.PasskeyCredential | None:
        if self.fail:
            raise OSError
        credential = self.credentials.get(credential_id)
        if credential is None or credential.account_id != account_id:
            return None
        renamed = replace(credential, display_name=display_name, version=credential.version + 1)
        self.credentials[credential_id] = renamed
        return renamed


class _WebAuthnVerifier:
    challenge = b"c" * 32
    expected_credential_id = b"credential-1"

    def __init__(
        self,
        *,
        failure: str | None = None,
        user_verified: bool = True,
        sign_count: int = 1,
        backup_eligible: bool = False,
        backup_state: bool = False,
    ) -> None:
        self.failure = failure
        self.user_verified = user_verified
        self.sign_count = sign_count
        self.backup_eligible = backup_eligible
        self.backup_state = backup_state

    def registration_options(self, **kwargs: object) -> str:
        assert kwargs["challenge"] == self.challenge
        return '{"challenge":"Y2Nj"}'

    def authentication_options(self, **kwargs: object) -> str:
        assert kwargs["challenge"] == self.challenge
        return '{"challenge":"Y2Nj"}'

    def registration_challenge(self, response: str) -> bytes:
        del response
        return self.challenge

    def authentication_challenge(self, response: str) -> bytes:
        del response
        return self.challenge

    def credential_id(self, response: str) -> bytes:
        del response
        return self.expected_credential_id

    def verify_registration(self, **kwargs: object) -> accounts_module.RegistrationVerification:
        del kwargs
        if self.failure is not None:
            raise accounts_module.InvalidWebAuthnResponseError
        return accounts_module.RegistrationVerification(
            credential_id=self.expected_credential_id,
            public_key=b"public-key",
            sign_count=self.sign_count,
            backup_eligible=self.backup_eligible,
            backup_state=self.backup_state,
            user_verified=self.user_verified,
            aaguid="00000000-0000-0000-0000-000000000000",
            attestation_format="none",
            attestation_chain_verified=False,
        )

    def verify_authentication(self, **kwargs: object) -> accounts_module.AuthenticationVerification:
        del kwargs
        if self.failure is not None:
            raise accounts_module.InvalidWebAuthnResponseError
        return accounts_module.AuthenticationVerification(
            credential_id=self.expected_credential_id,
            sign_count=self.sign_count,
            backup_eligible=self.backup_eligible,
            backup_state=self.backup_state,
            user_verified=self.user_verified,
        )


def _passkey_service(  # noqa: PLR0913 - explicit service seam builder for ceremony matrices
    *,
    challenge_store: _ChallengeStore | None = None,
    store: _PasskeyStore | None = None,
    verifier: _WebAuthnVerifier | None = None,
    now: datetime = _JWT_NOW,
    attestation_trust: object | None = None,
    login_methods: object | None = None,
    worker_timeout: float = 10.0,
) -> accounts_module.PasskeyService:
    return accounts_module.PasskeyService(
        store=store or _PasskeyStore(),
        challenge_store=challenge_store or _ChallengeStore(),
        verifier=verifier or _WebAuthnVerifier(),
        rp_id="example.com",
        rp_name="Example",
        origins=("https://example.com",),
        user_verification=accounts_module.UserVerification.REQUIRED,
        clock=lambda: now,
        challenge_entropy=lambda length: b"c" * length,
        attestation_trust=cast("Any", attestation_trust),
        login_methods=cast("Any", login_methods),
        worker_timeout=worker_timeout,
    )


@pytest.mark.anyio
async def test_passkey_registration_is_bound_one_time_and_stores_only_verified_project_types() -> None:
    challenge_store = _ChallengeStore()
    store = _PasskeyStore()
    service = _passkey_service(challenge_store=challenge_store, store=store)
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
@pytest.mark.anyio
async def test_passkey_registration_rejects_unbound_invalid_or_unavailable_ceremonies(case: str) -> None:
    challenge_store = _ChallengeStore()
    store = _PasskeyStore()
    verifier = _WebAuthnVerifier(failure=case if case not in {"binding", "account", "expired", "store"} else None)
    service = _passkey_service(challenge_store=challenge_store, store=store, verifier=verifier)
    binding = b"session-binding"
    assert isinstance(
        await service.begin_registration("account-1", user_name="person@example.com", binding=binding),
        accounts_module.WebAuthnOptions,
    )
    if case == "expired":
        service.clock = lambda: _JWT_NOW + timedelta(minutes=5)
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
        with pytest.raises(accounts_module.InvalidWebAuthnResponseError):
            operation("{}")


@pytest.mark.anyio
async def test_passkey_authentication_verifies_owner_and_emits_normalized_assurance() -> None:
    challenge_store = _ChallengeStore()
    store = _PasskeyStore()
    verifier = _WebAuthnVerifier()
    store.credentials[verifier.expected_credential_id] = accounts_module.PasskeyCredential(
        credential_id=verifier.expected_credential_id,
        account_id="account-1",
        public_key=b"public-key",
        sign_count=0,
        backup_eligible=False,
        backup_state=False,
        user_verified=True,
        aaguid="00000000-0000-0000-0000-000000000000",
        attestation_format="none",
        created_at=_JWT_NOW,
    )
    service = _passkey_service(challenge_store=challenge_store, store=store, verifier=verifier)
    binding = b"session-binding"
    assert isinstance(await service.begin_authentication("account-1", binding=binding), accounts_module.WebAuthnOptions)

    evidence = await service.verify_authentication("account-1", binding=binding, response='{"id":"credential"}')

    assert isinstance(evidence, AuthenticationEvidence)
    assert evidence.methods == frozenset({"passkey"})
    assert evidence.traits == frozenset({"phishing-resistant", "user-verified"})


def _stored_passkey(
    *, sign_count: int = 0, backup_eligible: bool = False, backup_state: bool = False
) -> accounts_module.PasskeyCredential:
    return accounts_module.PasskeyCredential(
        credential_id=b"credential-1",
        account_id="account-1",
        public_key=b"public-key",
        sign_count=sign_count,
        backup_eligible=backup_eligible,
        backup_state=backup_state,
        user_verified=True,
        aaguid="00000000-0000-0000-0000-000000000000",
        attestation_format="none",
        created_at=_JWT_NOW,
    )


@pytest.mark.parametrize(
    ("stored_count", "new_count", "policy", "expected_type", "suspect"),
    [
        (0, 0, accounts_module.CloneRiskPolicy.REJECT, AuthenticationEvidence, False),
        (0, 1, accounts_module.CloneRiskPolicy.REJECT, AuthenticationEvidence, False),
        (1, 2, accounts_module.CloneRiskPolicy.REJECT, AuthenticationEvidence, False),
        (1, 1, accounts_module.CloneRiskPolicy.REJECT, InvalidCredentials, True),
        (2, 1, accounts_module.CloneRiskPolicy.REJECT, InvalidCredentials, True),
        (2, 1, accounts_module.CloneRiskPolicy.AUDIT_ONLY, AuthenticationEvidence, True),
    ],
)
@pytest.mark.anyio
async def test_passkey_counter_policy_persists_clone_risk_before_assurance(
    stored_count: int,
    new_count: int,
    policy: accounts_module.CloneRiskPolicy,
    expected_type: type[object],
    suspect: bool,  # noqa: FBT001
) -> None:
    store = _PasskeyStore()
    store.credentials[b"credential-1"] = _stored_passkey(sign_count=stored_count)
    service = _passkey_service(store=store, verifier=_WebAuthnVerifier(sign_count=new_count))
    service.clone_risk_policy = policy
    binding = b"session-binding"
    assert isinstance(await service.begin_authentication("account-1", binding=binding), accounts_module.WebAuthnOptions)

    outcome = await service.verify_authentication("account-1", binding=binding, response='{"id":"credential"}')

    assert isinstance(outcome, expected_type)
    assert store.credentials[b"credential-1"].suspect is suspect


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
@pytest.mark.anyio
async def test_passkey_backup_eligibility_is_immutable_and_state_may_transition(
    stored_be: bool,  # noqa: FBT001
    stored_bs: bool,  # noqa: FBT001
    new_be: bool,  # noqa: FBT001
    new_bs: bool,  # noqa: FBT001
    expected_type: type[object],
) -> None:
    store = _PasskeyStore()
    store.credentials[b"credential-1"] = _stored_passkey(backup_eligible=stored_be, backup_state=stored_bs)
    verifier = _WebAuthnVerifier(backup_eligible=new_be, backup_state=new_bs)
    service = _passkey_service(store=store, verifier=verifier)
    binding = b"session-binding"
    assert isinstance(await service.begin_authentication("account-1", binding=binding), accounts_module.WebAuthnOptions)

    outcome = await service.verify_authentication("account-1", binding=binding, response='{"id":"credential"}')

    assert isinstance(outcome, expected_type)


@pytest.mark.anyio
async def test_passkey_listing_rename_and_removal_are_safe_and_final_method_guarded() -> None:
    store = _PasskeyStore()
    store.credentials[b"credential-1"] = _stored_passkey()
    login_methods = _RecoveryLoginMethods(accounts_module.RevokeLoginMethodStatus.FINAL_METHOD)
    service = _passkey_service(store=store)
    service.login_methods = login_methods

    summaries = await service.list_credentials("account-1")
    renamed = await service.rename_credential("account-1", b"credential-1", "Work key")
    removal = await service.remove_credential("account-1", b"credential-1")

    assert len(summaries) == 1
    assert not hasattr(summaries[0], "public_key")
    assert renamed is not None
    assert renamed.display_name == "Work key"
    assert isinstance(removal, accounts_module.RevokeLoginMethodResult)
    assert removal.status is accounts_module.RevokeLoginMethodStatus.FINAL_METHOD


class _StepUpStore:
    def __init__(self) -> None:
        self.records: dict[bytes, accounts_module.StepUpRecord] = {}

    async def put(self, record: accounts_module.StepUpRecord) -> None:
        self.records[record.grant_digest] = record

    async def consume(  # noqa: PLR0913 - mirrors the exact atomic StepUpStore contract
        self,
        grant_digest: bytes,
        *,
        principal_id: str,
        security_epoch: int,
        purpose: str,
        transport_digest: bytes,
        now: datetime,
    ) -> accounts_module.StepUpRecord | None:
        record = self.records.pop(grant_digest, None)
        if (
            record is None
            or record.principal_id != principal_id
            or record.security_epoch != security_epoch
            or record.purpose != purpose
            or record.transport_digest != transport_digest
            or record.expires_at <= now
        ):
            return None
        return record


@pytest.mark.anyio
async def test_step_up_grant_is_exactly_bound_expiring_and_single_use() -> None:
    store = _StepUpStore()
    now = datetime(2026, 7, 27, tzinfo=timezone.utc)
    service = accounts_module.StepUpService(store=store, clock=lambda: now, entropy=lambda _size: b"g" * 32)
    source = AuthenticationEvidence(mechanism="totp", slot="mfa", authenticated_at=now, methods=frozenset({"totp"}))

    grant = await service.issue(
        principal_id="account-1",
        security_epoch=2,
        purpose="password-change",
        transport_binding=b"session-1",
        evidence=source,
    )

    assert isinstance(grant, accounts_module.StepUpGrant)
    assert "gggg" not in repr(grant)
    assert isinstance(
        await service.consume(
            grant.token,
            principal_id="account-1",
            security_epoch=2,
            purpose="different-action",
            transport_binding=b"session-1",
        ),
        InvalidCredentials,
    )
    replay = await service.consume(
        grant.token,
        principal_id="account-1",
        security_epoch=2,
        purpose="password-change",
        transport_binding=b"session-1",
    )
    assert isinstance(replay, InvalidCredentials)


@pytest.mark.anyio
@pytest.mark.parametrize(("changed"), ["principal", "epoch", "transport", "expiry"])
async def test_step_up_grant_rejects_changed_binding(changed: str) -> None:
    store = _StepUpStore()
    now = datetime(2026, 7, 27, tzinfo=timezone.utc)
    service = accounts_module.StepUpService(store=store, clock=lambda: now)
    source = AuthenticationEvidence(
        mechanism="passkey",
        slot="mfa",
        authenticated_at=now,
        methods=frozenset({"passkey"}),
        traits=frozenset({"phishing-resistant"}),
    )
    grant = await service.issue(
        principal_id="account-1",
        security_epoch=2,
        purpose="credential-remove",
        transport_binding=b"token-1",
        evidence=source,
    )
    assert isinstance(grant, accounts_module.StepUpGrant)
    if changed == "expiry":
        service.clock = lambda: now + timedelta(minutes=6)
    result = await service.consume(
        grant.token,
        principal_id="account-2" if changed == "principal" else "account-1",
        security_epoch=3 if changed == "epoch" else 2,
        purpose="credential-remove",
        transport_binding=b"token-2" if changed == "transport" else b"token-1",
    )
    assert isinstance(result, InvalidCredentials)


def test_public_testing_helpers_are_isolated_structural_conformance_ports() -> None:
    now = datetime(2026, 7, 27, tzinfo=timezone.utc)
    clock = testing_module.FakeClock(now)

    assert isinstance(testing_module.InMemoryMFAStore(), accounts_module.MFAStore)
    assert isinstance(testing_module.InMemoryMFALoginChallengeStore(), accounts_module.MFALoginChallengeStore)
    assert isinstance(testing_module.InMemorySecurityBackend().mfa_login, accounts_module.MFALoginChallengeStore)
    assert isinstance(testing_module.InMemoryWebAuthnChallengeStore(), accounts_module.WebAuthnChallengeStore)
    assert isinstance(testing_module.InMemoryPasskeyStore(), accounts_module.PasskeyStore)
    assert isinstance(testing_module.InMemoryStepUpStore(), accounts_module.StepUpStore)
    assert clock() == now
    assert clock.advance(timedelta(seconds=1)) == now + timedelta(seconds=1)
    with pytest.raises(ValueError, match="positive"):
        clock.advance(timedelta())


@pytest.mark.anyio
async def test_public_step_up_conformance_store_has_one_atomic_winner() -> None:
    now = datetime(2026, 7, 27, tzinfo=timezone.utc)
    store = testing_module.InMemoryStepUpStore()
    service = accounts_module.StepUpService(store=store, clock=lambda: now, entropy=lambda _size: b"s" * 32)
    grant = await service.issue(
        principal_id="account-1",
        security_epoch=1,
        purpose="settings",
        transport_binding=b"session",
        evidence=AuthenticationEvidence(
            mechanism="totp", slot="mfa", authenticated_at=now, methods=frozenset({"totp"})
        ),
    )
    assert isinstance(grant, accounts_module.StepUpGrant)
    outcomes: list[object] = []

    async def consume() -> None:
        outcomes.append(
            await service.consume(
                grant.token,
                principal_id="account-1",
                security_epoch=1,
                purpose="settings",
                transport_binding=b"session",
            )
        )

    async with create_task_group() as task_group:
        task_group.start_soon(consume)
        task_group.start_soon(consume)

    assert sum(isinstance(outcome, AuthenticationEvidence) for outcome in outcomes) == 1
    assert sum(isinstance(outcome, InvalidCredentials) for outcome in outcomes) == 1


@pytest.mark.anyio
async def test_public_conformance_helpers_execute_factor_atomicity_matrix() -> None:
    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    clock = testing_module.FakeClock(now)
    mfa_store = testing_module.InMemoryMFAStore()
    protector = _MFAProtector()
    recovery_values = iter(range(10))
    mfa = accounts_module.MFAService(
        store=mfa_store,
        secret_protector=protector,
        clock=clock,
        secret_generator=lambda: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        identifiers=iter(("enrollment-1", "method-1")).__next__,
        recovery_peppers=(accounts_module.RecoveryCodePepper("v1", b"p" * 32),),
        recovery_entropy=lambda _size: next(recovery_values).to_bytes(16, "big"),
    )
    enrollment = await mfa.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(enrollment, accounts_module.TOTPEnrollment)
    code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").at(now)
    method = await mfa.activate_totp("account-1", enrollment.enrollment_id, code)
    assert isinstance(method, accounts_module.TOTPMethod)
    assert await mfa_store.get_totp_method("other", method.method_id) is None
    assert not await mfa_store.advance_totp_counter(method.method_id, accepted_counter=1, now=now)
    recovery = await mfa.generate_recovery_codes("account-1")
    assert isinstance(recovery, accounts_module.RecoveryCodes)
    assert isinstance(await mfa.consume_recovery_code("account-1", recovery.codes[0]), AuthenticationEvidence)
    assert isinstance(await mfa.consume_recovery_code("account-1", recovery.codes[0]), InvalidCredentials)

    challenge_store = testing_module.InMemoryWebAuthnChallengeStore()
    passkey_store = testing_module.InMemoryPasskeyStore()
    verifier = _WebAuthnVerifier()
    passkeys = accounts_module.PasskeyService(
        store=passkey_store,
        challenge_store=challenge_store,
        verifier=verifier,
        rp_id="example.com",
        rp_name="Example",
        origins=("https://example.com",),
        clock=clock,
        challenge_entropy=lambda size: b"c" * size,
    )
    options = await passkeys.begin_registration("account-1", user_name="person@example.com", binding=b"session")
    assert isinstance(options, accounts_module.WebAuthnOptions)
    credential = await passkeys.verify_registration("account-1", binding=b"session", response="{}")
    assert isinstance(credential, accounts_module.PasskeyCredential)
    assert not await passkey_store.add_credential(
        credential,
        login_method=accounts_module.LoginMethod("pk_duplicate", "passkey", now),
        event=accounts_module.SecurityEvent(
            event_id="event-duplicate",
            occurred_at=now,
            operation="passkey.register.verify",
            outcome="created",
            account_id="account-1",
        ),
    )
    assert await passkey_store.get_credential(b"absent") is None
    assert (
        await passkey_store.record_assertion(
            credential.credential_id,
            expected_version=99,
            sign_count=1,
            backup_eligible=False,
            backup_state=False,
            clone_risk=False,
            now=now,
        )
        is accounts_module.AssertionRecordResult.CONFLICT
    )
    assert len(await passkey_store.list_credentials("account-1")) == 1
    assert await passkey_store.rename_credential("other", credential.credential_id, "No") is None
    renamed = await passkey_store.rename_credential("account-1", credential.credential_id, "Laptop")
    assert renamed is not None
    assert renamed.display_name == "Laptop"
    assert await challenge_store.consume(b"x" * 32, binding_digest=b"y" * 32, purpose="registration", now=now) is None


@pytest.mark.parametrize(
    "value",
    [
        accounts_module.TOTPEnrollmentRequest(label="User", step_up_grant="grant-secret"),
        accounts_module.TOTPEnrollmentResponse(
            enrollment_id="e1",
            method_id="m1",
            provisioning_uri="otpauth://secret",
            expires_at=datetime(2026, 7, 27, tzinfo=timezone.utc),
        ),
        accounts_module.TOTPVerificationRequest(enrollment_id="e1", code="123456"),
        accounts_module.StepUpAuthorizedRequest(step_up_grant="grant-secret"),
        accounts_module.StepUpRequest(method="totp", credential="123456", method_id="m1"),
        accounts_module.StepUpResponse(
            grant="grant-secret", purpose="settings", expires_at=datetime(2026, 7, 27, tzinfo=timezone.utc)
        ),
        accounts_module.RecoveryCodesResponse(codes=("rc_v1_SECRET",)),
        accounts_module.PasskeyVerifyRequest(account_id="account-1", response="browser-secret"),
        accounts_module.PasskeyRegistrationOptionsRequest(user_name="person@example.com", step_up_grant="grant-secret"),
        accounts_module.PasskeyOptionsResponse(
            options="challenge-secret", expires_at=datetime(2026, 7, 27, tzinfo=timezone.utc)
        ),
    ],
)
def test_mfa_route_dto_representations_redact_secret_material(value: object) -> None:
    rendered = repr(value)

    assert "<redacted>" in rendered
    assert all(
        secret not in rendered
        for secret in (
            "123456",
            "grant-secret",
            "rc_v1_SECRET",
            "browser-secret",
            "otpauth://secret",
            "challenge-secret",
        )
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
        "store": _PasskeyStore(),
        "challenge_store": _ChallengeStore(),
        "rp_id": "example.com",
        "rp_name": "Example",
        "origins": ("https://example.com",),
    }
    config.update(kwargs)
    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.PasskeyService(**config)  # type: ignore[arg-type]


def test_mfa_value_and_service_configuration_rejects_invalid_contracts() -> None:
    now = datetime(2026, 7, 27, tzinfo=timezone.utc)
    protected = accounts_module.ProtectedSecret(b"cipher", "v1")
    with pytest.raises(ValueError, match="Protected secret"):
        accounts_module.ProtectedSecret(b"", "v1")
    with pytest.raises(ValueError, match="Pending TOTP"):
        accounts_module.PendingTOTPEnrollment(
            enrollment_id=" ",
            method_id="m1",
            account_id="a1",
            protected_secret=protected,
            policy=accounts_module.TOTPPolicy(),
            created_at=now,
            expires_at=now + timedelta(minutes=1),
        )
    with pytest.raises(ValueError, match="TOTP method"):
        accounts_module.TOTPMethod(
            method_id="m1",
            account_id="a1",
            protected_secret=protected,
            policy=accounts_module.TOTPPolicy(),
            last_accepted_counter=-1,
            created_at=now,
        )
    with pytest.raises(ValueError, match="Recovery-code digest"):
        accounts_module.RecoveryCodeDigest("a1", "v1", b"short")
    with pytest.raises(ValueError, match="Step-up record"):
        accounts_module.StepUpRecord(
            grant_digest=b"short",
            transport_digest=b"t" * 32,
            principal_id="a1",
            security_epoch=1,
            purpose="settings",
            methods=frozenset(),
            traits=frozenset(),
            authenticated_at=now,
            expires_at=now + timedelta(minutes=1),
        )
    with pytest.raises(ValueError, match="MFA login challenge"):
        accounts_module.MFALoginChallenge(
            challenge_digest=bytearray(b"d" * 32),
            account_id="a1",
            security_epoch=1,
            client_key=None,
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )
    with pytest.raises(ValueError, match="MFA login challenge"):
        accounts_module.MFALoginChallenge(
            challenge_digest=b"d" * 32,
            account_id="a1",
            security_epoch=1,
            client_key=None,
            issued_at=now,
            expires_at=now + timedelta(minutes=11),
        )
    with pytest.raises(ImproperlyConfiguredException, match="store"):
        accounts_module.MFAService(cast("Any", object()), _MFAProtector())
    with pytest.raises(ImproperlyConfiguredException, match="protector"):
        accounts_module.MFAService(_MFAStore(), cast("Any", object()))
    with pytest.raises(ImproperlyConfiguredException, match="issuer"):
        accounts_module.MFAService(_MFAStore(), _MFAProtector(), issuer=" ")
    with pytest.raises(ImproperlyConfiguredException, match="LoginMethodStore"):
        accounts_module.MFAService(_MFAStore(), _MFAProtector(), login_methods=cast("Any", object()))
    with pytest.raises(ImproperlyConfiguredException, match="store"):
        accounts_module.StepUpService(cast("Any", object()))
    with pytest.raises(ImproperlyConfiguredException, match="lifetime"):
        accounts_module.StepUpService(_StepUpStore(), ttl=timedelta())


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
        require_user_verification=True,
    )
    assert registration.credential_id == b"credential"
    assert registration.attestation_chain_verified
    assert registration_kwargs["pem_root_certs_bytes_by_fmt"] == {
        passkeys_module.AttestationFormat.PACKED: [b"trusted-root"]
    }
    assert authentication.sign_count == 2

    monkeypatch.setattr(passkeys_module, "options_to_json", lambda _options: 1 / 0)
    with pytest.raises(accounts_module.InvalidWebAuthnResponseError):
        adapter.registration_options(**options_kwargs)
    with pytest.raises(accounts_module.InvalidWebAuthnResponseError):
        adapter.authentication_options(**options_kwargs)
    monkeypatch.setattr(passkeys_module, "verify_registration_response", lambda **_kwargs: 1 / 0)
    monkeypatch.setattr(passkeys_module, "verify_authentication_response", lambda **_kwargs: 1 / 0)
    with pytest.raises(accounts_module.InvalidWebAuthnResponseError):
        adapter.verify_registration(
            response="{}",
            challenge=b"challenge",
            rp_id="example.com",
            origins=("https://example.com",),
            require_user_verification=True,
            algorithms=(-7,),
        )
    with pytest.raises(accounts_module.InvalidWebAuthnResponseError):
        adapter.verify_authentication(
            response="{}",
            challenge=b"challenge",
            rp_id="example.com",
            origins=("https://example.com",),
            public_key=b"public-key",
            require_user_verification=True,
        )


def test_passkey_values_and_dependency_configuration_reject_invalid_shapes() -> None:
    now = datetime(2026, 7, 27, tzinfo=timezone.utc)
    with pytest.raises(ImproperlyConfiguredException, match="LoginMethodStore"):
        _passkey_service(login_methods=cast("Any", object()))
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
        replace(_stored_passkey(), backup_state=True)
    base: dict[str, object] = {
        "store": _PasskeyStore(),
        "challenge_store": _ChallengeStore(),
        "verifier": _WebAuthnVerifier(),
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


@pytest.mark.anyio
async def test_passkey_worker_timeout_cancels_the_request_boundary() -> None:
    class SlowVerifier(_WebAuthnVerifier):
        def authentication_options(self, **kwargs: object) -> str:
            sleep(0.05)
            return super().authentication_options(**kwargs)

    service = _passkey_service(verifier=SlowVerifier(), worker_timeout=0.001)
    assert isinstance(await service.begin_authentication("account-1", binding=b"binding"), VerificationUnavailable)


@pytest.mark.anyio
async def test_passkey_service_defensive_store_and_ceremony_outcomes_are_sanitized() -> None:
    store = _PasskeyStore()
    service = _passkey_service(store=store)
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

    class ConflictingStore(_PasskeyStore):
        async def record_assertion(self, *args: object, **kwargs: object) -> accounts_module.AssertionRecordResult:
            del args, kwargs
            return accounts_module.AssertionRecordResult.CONFLICT

    conflict_store = ConflictingStore()
    conflict_store.credentials[b"credential-1"] = _stored_passkey()
    conflict_service = _passkey_service(store=conflict_store)
    options = await conflict_service.begin_authentication("account-1", binding=b"session")
    assert isinstance(options, accounts_module.WebAuthnOptions)
    assert isinstance(
        await conflict_service.verify_authentication("account-1", binding=b"session", response="{}"), InvalidCredentials
    )


@pytest.mark.anyio
async def test_local_auth_passkey_login_selects_only_configured_transport() -> None:
    account = accounts_module.LocalAccount(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Person",
        active=True,
        verified=True,
        security_epoch=1,
    )

    class Accounts:
        value: object = account

        async def get_by_id(self, account_id: str) -> object:
            del account_id
            if isinstance(self.value, BaseException):
                raise self.value
            return self.value

    class Session:
        result: object = accounts_module.SessionAuthentication(
            session_id="c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M",
            binding_id="sb_aWlpaWlpaWlpaWlpaWlpaQ",
            account_id="account-1",
            security_epoch=1,
            authenticated_at=_JWT_NOW,
            expires_at=_JWT_NOW + timedelta(hours=1),
        )

        async def establish(self, request: object, projected: object, *, evidence: object) -> object:
            del request, projected, evidence
            return self.result

    class Tokens:
        result = object()
        evidence: object | None = None

        async def issue(self, projected: object, *, evidence: object) -> object:
            del projected
            self.evidence = evidence
            return self.result

    accounts = Accounts()
    session = Session()
    tokens = Tokens()
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
    assert isinstance(result, accounts_module.LocalAccountResponse)
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


def test_step_up_purpose_allowlist_covers_every_consumed_purpose_with_strong_factors() -> None:
    purpose_methods = mfa_controllers_module._PURPOSE_METHODS  # noqa: SLF001 - assert the deny-by-default contract

    assert set(purpose_methods) == {
        "totp-enroll",
        "totp-remove",
        "recovery-codes",
        "passkey-register",
        "passkey-remove",
    }
    assert all(methods == frozenset({"password", "passkey"}) for methods in purpose_methods.values())


@pytest.mark.anyio
async def test_mfa_controller_helpers_cover_safe_failure_matrix() -> None:
    request = cast("Any", SimpleNamespace(headers={"authorization": "Bearer transport"}))
    with pytest.raises(ValueError, match="At least one"):
        mfa_controllers_module.build_mfa_routes(step_up=cast("Any", object()), epochs=cast("Any", object()))
    mfa_controllers_module.build_mfa_routes(
        step_up=cast("Any", object()), epochs=cast("Any", object()), mfa=cast("Any", object())
    )
    mfa_controllers_module.build_mfa_routes(
        step_up=cast("Any", object()), epochs=cast("Any", object()), passkeys=cast("Any", object())
    )
    mfa_controllers_module.build_mfa_routes(
        step_up=cast("Any", object()),
        epochs=cast("Any", object()),
        passkeys=cast("Any", object()),
        session_capable=True,
        token_capable=True,
    )
    error_cases = (
        (accounts_module.RateLimited(retry_after=3), TooManyRequestsException, 429, "Too many requests.", "3"),
        (accounts_module.RateLimited(), TooManyRequestsException, 429, "Too many requests.", None),
        (VerificationUnavailable(), ServiceUnavailableException, 503, "Authentication service is unavailable.", None),
        (InvalidCredentials(), NotAuthorizedException, 401, "Authentication required.", None),
    )
    for outcome, exception_type, status_code, detail, retry_after in error_cases:
        with pytest.raises(exception_type) as exc_info:
            mfa_controllers_module._error(outcome)  # noqa: SLF001
        assert exc_info.value.status_code == status_code
        assert exc_info.value.detail == detail
        if retry_after is None:
            assert not exc_info.value.headers or "Retry-After" not in exc_info.value.headers
        else:
            assert exc_info.value.headers["Retry-After"] == retry_after
    assert mfa_controllers_module._principal_id(Principal.anonymous()) is None  # noqa: SLF001
    assert (
        mfa_controllers_module._transport_binding(  # noqa: SLF001
            cast("Any", SimpleNamespace(headers={"cookie": "session=value"}))
        )
        == b"session=value"
    )
    assert (
        mfa_controllers_module._transport_binding(  # noqa: SLF001
            cast("Any", SimpleNamespace(headers={}))
        )
        == b""
    )

    class Epochs:
        value: object = 1

        async def current_epoch(self, account_id: str) -> object:
            del account_id
            if isinstance(self.value, BaseException):
                raise self.value
            return self.value

    epochs = Epochs()
    services = mfa_controllers_module._MFAFeatureService(  # noqa: SLF001
        mfa=None,
        passkeys=None,
        step_up=cast("Any", object()),
        epochs=cast("Any", epochs),
        rate_limits=None,
        client_key=None,
        local_auth=None,
    )
    assert await mfa_controllers_module._current_epoch(services, "account-1") == 1  # noqa: SLF001
    epochs.value = False
    assert isinstance(
        await mfa_controllers_module._current_epoch(services, "account-1"),  # noqa: SLF001
        VerificationUnavailable,
    )
    epochs.value = OSError()
    assert isinstance(
        await mfa_controllers_module._consume_step_up(  # noqa: SLF001
            mfa_service=services, request=request, account_id="account-1", purpose="settings", grant="grant"
        ),
        VerificationUnavailable,
    )

    class Guard:
        async def check(self, *args: object, **kwargs: object) -> accounts_module.RateLimited:
            del args, kwargs
            return accounts_module.RateLimited()

    services = replace(services, rate_limits=cast("Any", Guard()), client_key=cast("Any", lambda _request: "client"))
    assert isinstance(
        await mfa_controllers_module._check_rate_limit(  # noqa: SLF001
            services, request, "operation", "account-1"
        ),
        accounts_module.RateLimited,
    )
    services = replace(services, client_key=cast("Any", lambda _request: 1 / 0))
    assert isinstance(
        await mfa_controllers_module._check_rate_limit(  # noqa: SLF001
            services, request, "operation", "account-1"
        ),
        accounts_module.RateLimited,
    )
    assert isinstance(
        await mfa_controllers_module._StepUpController._verify_factor(  # noqa: SLF001
            "account-1", cast("Any", SimpleNamespace(method="unsupported", credential={})), request, services
        ),
        InvalidCredentials,
    )
    for response_factory in (mfa_controllers_module._options_response, mfa_controllers_module._removal_response):  # noqa: SLF001
        with pytest.raises(ServiceUnavailableException) as exc_info:
            response_factory(VerificationUnavailable())
        assert exc_info.value.status_code == 503
        assert exc_info.value.detail == "Authentication service is unavailable."
    assert (
        mfa_controllers_module._removal_response(  # noqa: SLF001 - exercises the private HTTP projection matrix
            accounts_module.RevokeLoginMethodResult(accounts_module.RevokeLoginMethodStatus.FINAL_METHOD)
        ).status_code
        == 409
    )
    assert (
        mfa_controllers_module._removal_response(  # noqa: SLF001 - exercises the private HTTP projection matrix
            accounts_module.RevokeLoginMethodResult(accounts_module.RevokeLoginMethodStatus.NOT_FOUND)
        ).status_code
        == 400
    )


@pytest.mark.anyio
async def test_mfa_and_step_up_defensive_failures_are_sanitized() -> None:
    now = datetime(2026, 7, 27, tzinfo=timezone.utc)

    class WrongVersionProtector(_MFAProtector):
        async def protect(self, secret: bytes, *, associated_data: bytes) -> accounts_module.ProtectedSecret:
            protected = await super().protect(secret, associated_data=associated_data)
            return replace(protected, key_version="other")

    service = _mfa_service(_MFAStore(), WrongVersionProtector(), now=now)
    assert isinstance(
        await service.begin_totp_enrollment("account-1", label="person@example.com"), VerificationUnavailable
    )
    service = _mfa_service(_MFAStore(), _MFAProtector(), now=now)
    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(enrollment, accounts_module.TOTPEnrollment)
    assert isinstance(await service.activate_totp("account-1", enrollment.enrollment_id, "000000"), InvalidCredentials)
    assert isinstance(await service.remove_totp_method("account-1", "method-1"), VerificationUnavailable)
    assert isinstance(await service.consume_recovery_code("account-1", 1), InvalidCredentials)  # type: ignore[arg-type]
    assert isinstance(
        await service.begin_totp_enrollment("bad\x00account", label="person@example.com"), VerificationUnavailable
    )
    service.secret_generator = cast("Any", lambda: b"bytes")
    assert isinstance(
        await service.begin_totp_enrollment("account-1", label="person@example.com"), VerificationUnavailable
    )
    service.secret_generator = lambda: "SHORT"
    assert isinstance(
        await service.begin_totp_enrollment("account-1", label="person@example.com"), VerificationUnavailable
    )

    step_up = accounts_module.StepUpService(
        _StepUpStore(), clock=lambda: now, entropy=cast("Any", lambda _size: b"short")
    )
    evidence = AuthenticationEvidence(mechanism="totp", slot="mfa", authenticated_at=now, methods=frozenset({"totp"}))
    assert isinstance(
        await step_up.issue(
            principal_id="account-1",
            security_epoch=1,
            purpose="settings",
            transport_binding=b"session",
            evidence=evidence,
        ),
        VerificationUnavailable,
    )
    assert isinstance(
        await step_up.issue(
            principal_id=" ", security_epoch=1, purpose="settings", transport_binding=b"session", evidence=evidence
        ),
        InvalidCredentials,
    )
    assert isinstance(
        await step_up.consume(
            " ", principal_id="account-1", security_epoch=1, purpose="settings", transport_binding=b"session"
        ),
        InvalidCredentials,
    )


@pytest.mark.anyio
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

    credential = _stored_passkey()
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
        is accounts_module.AssertionRecordResult.CLONE_RISK
    )


def test_mfa_and_passkey_feature_configs_build_services_and_validate_route_controls() -> None:
    class CombinedMFAStore(_MFAStore, _StepUpStore):
        def __init__(self) -> None:
            _MFAStore.__init__(self)
            _StepUpStore.__init__(self)

    combined = CombinedMFAStore()
    login_methods = _RecoveryLoginMethods()
    events = _SecurityEvents()
    policy = accounts_module.TOTPPolicy(algorithm="SHA256")
    pepper = accounts_module.RecoveryCodePepper("v1", b"p" * 32)
    mfa = MFAConfig(
        store=combined,
        secret_protector=_MFAProtector(),
        policy=policy,
        recovery_peppers=(pepper,),
        login_methods=login_methods,
        events=events,
        route_prefix="/security/",
        register_routes=False,
    )
    assert isinstance(mfa.mfa_service, accounts_module.MFAService)
    assert isinstance(mfa.step_up_service, accounts_module.StepUpService)
    assert mfa.mfa_service.policy is policy
    assert mfa.mfa_service.recovery_peppers == (pepper,)
    assert mfa.mfa_service.login_methods is login_methods
    assert mfa.mfa_service.events is events
    assert mfa.route_prefix == "/security"

    passkeys = PasskeyConfig(
        store=_PasskeyStore(),
        challenge_store=_ChallengeStore(),
        rp_id="example.com",
        origins=("https://example.com",),
        login_methods=login_methods,
        events=events,
        step_up_store=_StepUpStore(),
        register_routes=False,
    )
    assert isinstance(passkeys.passkey_service, accounts_module.PasskeyService)
    assert isinstance(passkeys.step_up_service, accounts_module.StepUpService)
    assert passkeys.passkey_service.login_methods is login_methods
    assert passkeys.passkey_service.events is events

    with pytest.raises(ImproperlyConfiguredException, match="recovery-code pepper"):
        MFAConfig(store=combined, secret_protector=_MFAProtector())
    with pytest.raises(ImproperlyConfiguredException, match="login-method"):
        PasskeyConfig(
            store=_PasskeyStore(),
            challenge_store=_ChallengeStore(),
            rp_id="example.com",
            origins=("https://example.com",),
        )

    for config in (
        lambda: MFAConfig(_MFAStore(), _MFAProtector(), route_prefix="relative"),
        lambda: MFAConfig(_MFAStore(), _MFAProtector(), route_prefix=cast("Any", 1)),
        lambda: MFAConfig(_MFAStore(), _MFAProtector(), register_routes=cast("Any", 1)),
        lambda: PasskeyConfig(
            _PasskeyStore(), _ChallengeStore(), "example.com", ("https://example.com",), register_routes=cast("Any", 1)
        ),
    ):
        with pytest.raises(ImproperlyConfiguredException):
            config()


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"signer": object()}, "TokenSigner"),
        ({"issuer": " "}, "issuer"),
        ({"audience": "bad audience"}, "audience"),
        ({"client_id": "e\u0301"}, "client id"),
        ({"lifetime": object()}, "timedelta"),
        ({"clock": None}, "clock"),
        ({"token_ids": None}, "token id"),
    ],
)
def test_local_access_token_issuer_rejects_invalid_configuration(kwargs: dict[str, object], match: str) -> None:
    values = {
        "signer": _AccessSigner(),
        "issuer": _JWT_ISSUER,
        "audience": _JWT_AUDIENCE,
        "client_id": "local",
        **kwargs,
    }

    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.LocalAccessTokenIssuer(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("account", "signer", "clock", "token_ids", "scopes", "expected_type"),
    [
        (
            _local_access_account(active=False),
            _AccessSigner(),
            lambda: _JWT_NOW,
            lambda: "token",
            frozenset(),
            InvalidCredentials,
        ),
        (
            _local_access_account(),
            _AccessSigner(),
            lambda: 1 / 0,
            lambda: "token",
            frozenset(),
            VerificationUnavailable,
        ),
        (
            _local_access_account(),
            _AccessSigner(),
            lambda: _JWT_NOW,
            lambda: 1 / 0,
            frozenset(),
            VerificationUnavailable,
        ),
        (
            _local_access_account(),
            _AccessSigner(),
            lambda: _JWT_NOW,
            lambda: "token",
            frozenset({"bad scope"}),
            InvalidCredentials,
        ),
        (
            _local_access_account(),
            _AccessSigner(fail=True),
            lambda: _JWT_NOW,
            lambda: "token",
            frozenset(),
            VerificationUnavailable,
        ),
        (
            _local_access_account(),
            _AccessSigner("malformed"),
            lambda: _JWT_NOW,
            lambda: "token",
            frozenset(),
            VerificationUnavailable,
        ),
    ],
)
@pytest.mark.anyio
async def test_local_access_token_issuer_maps_invalid_and_unavailable_composition(  # noqa: PLR0913 - one composition matrix per parametrized case
    *,
    account: accounts_module.LocalAccount[object],
    signer: _AccessSigner,
    clock: Callable[[], datetime],
    token_ids: Callable[[], str],
    scopes: frozenset[str],
    expected_type: type[object],
) -> None:
    service = accounts_module.LocalAccessTokenIssuer(
        signer=signer, issuer=_JWT_ISSUER, audience=_JWT_AUDIENCE, clock=clock, token_ids=token_ids
    )

    outcome = await service.issue(account, scopes=scopes)

    assert isinstance(outcome, expected_type)


def test_local_bearer_resolver_rejects_missing_capabilities() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="AccountLookup and SecurityEpochStore"):
        accounts_module.LocalBearerIdentityResolver(accounts=object())  # type: ignore[arg-type]


@pytest.mark.parametrize("epoch", [None, True, -1, 1.0, "1"])
@pytest.mark.anyio
async def test_local_bearer_resolver_rejects_malformed_epoch_without_lookup(epoch: object) -> None:
    store = _LocalAccessStore(_local_access_account())
    resolver = accounts_module.LocalBearerIdentityResolver(accounts=store)
    claims = JWTClaims(
        issuer=_JWT_ISSUER,
        subject="account-1",
        audiences=frozenset({_JWT_AUDIENCE}),
        expires_at=_JWT_NOW + timedelta(minutes=10),
        issued_at=_JWT_NOW,
        not_before=None,
        token_id="public-token-id",  # noqa: S106
        client_id="local",
        scopes=frozenset(),
        raw={"se": cast("Any", epoch)},
    )

    outcome = await resolver.resolve(claims)

    assert isinstance(outcome, InvalidCredentials)
    assert store.id_lookups == []


class _RefreshEntropy:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self, length: int) -> bytes:
        self.value += 1
        return self.value.to_bytes(length, "big")


def _refresh_identifier(prefix: str, value: int) -> str:
    return f"{prefix}{base64.urlsafe_b64encode(value.to_bytes(16, 'big')).rstrip(b'=').decode()}"


def _refresh_idempotency_key(value: int = 1) -> str:
    return base64.urlsafe_b64encode(value.to_bytes(16, "big")).rstrip(b"=").decode()


class _AtomicRefreshStore:
    """Deterministic test-only implementation of the strict atomic store contract."""

    def __init__(
        self,
        accounts: _LocalAccessStore,
        *,
        expected_preparations: int = 0,
        expected_atomic_rotations: int = 0,
        before_atomic_rotate: Callable[[], None] | None = None,
    ) -> None:
        self.accounts = accounts
        self.tokens: dict[str, SimpleNamespace] = {}
        self.revoked_families: set[str] = set()
        self.rotations: list[accounts_module.RefreshRotationStatus] = []
        self.preparations: list[
            accounts_module.PrepareRefreshResult
            | accounts_module.RefreshFamilyContext
            | accounts_module.RefreshReceiptReplay
        ] = []
        self.preparation_events: list[accounts_module.SecurityEvent] = []
        self.override_receipt: bytes | None = None
        self._lock = asyncio.Lock()
        self._expected_preparations = expected_preparations
        self._prepared_count = 0
        self._preparation_gate = asyncio.Event()
        self._expected_atomic_rotations = expected_atomic_rotations
        self._atomic_rotation_count = 0
        self._atomic_rotation_gate = asyncio.Event()
        self._atomic_rotation_lock = asyncio.Lock()
        self._before_atomic_rotate = before_atomic_rotate

    async def create_family(
        self, command: accounts_module.CreateRefreshFamilyCommand, *, event: accounts_module.SecurityEvent
    ) -> bool:
        self.preparation_events.append(event)
        async with self._lock:
            if command.token_id in self.tokens or command.security_epoch != self.accounts.security_epoch:
                return False
            self.tokens[command.token_id] = SimpleNamespace(
                account_id=command.account_id,
                consumed=False,
                family_expires_at=command.family_expires_at,
                family_id=command.family_id,
                idempotency_digest=None,
                evidence=command.evidence,
                receipt_expires_at=None,
                scopes=command.scopes,
                sealed_receipt=None,
                security_epoch=command.security_epoch,
                token_digest=command.token_digest,
                token_expires_at=command.token_expires_at,
            )
            return True

    async def prepare_rotation(
        self,
        proof: accounts_module.RefreshTokenProof,
        idempotency_digest: bytes | None,
        *,
        now: datetime,
        event: accounts_module.SecurityEvent,
    ) -> (
        accounts_module.RefreshFamilyContext
        | accounts_module.RefreshReceiptReplay
        | accounts_module.PrepareRefreshResult
    ):
        self.preparation_events.append(event)
        async with self._lock:
            record = self.tokens.get(proof.token_id)
            if record is None or not hmac.compare_digest(record.token_digest, proof.digest):
                result: (
                    accounts_module.RefreshFamilyContext
                    | accounts_module.RefreshReceiptReplay
                    | accounts_module.PrepareRefreshResult
                ) = accounts_module.PrepareRefreshResult(accounts_module.RefreshRotationStatus.INVALID)
            elif record.family_id in self.revoked_families:
                result = accounts_module.PrepareRefreshResult(
                    accounts_module.RefreshRotationStatus.REVOKED, family_revoked=True
                )
            elif record.security_epoch != self.accounts.security_epoch:
                result = accounts_module.PrepareRefreshResult(accounts_module.RefreshRotationStatus.EPOCH_MISMATCH)
            elif now >= record.token_expires_at or now >= record.family_expires_at:
                result = accounts_module.PrepareRefreshResult(accounts_module.RefreshRotationStatus.EXPIRED)
            elif record.consumed:
                same_key = (
                    record.idempotency_digest is not None
                    and idempotency_digest is not None
                    and hmac.compare_digest(record.idempotency_digest, idempotency_digest)
                )
                if same_key and now < record.receipt_expires_at:
                    result = accounts_module.RefreshReceiptReplay(
                        context=accounts_module.RefreshFamilyContext(
                            account_id=record.account_id,
                            family_id=record.family_id,
                            security_epoch=record.security_epoch,
                            token_expires_at=record.token_expires_at,
                            family_expires_at=record.family_expires_at,
                            scopes=record.scopes,
                            evidence=record.evidence,
                        ),
                        sealed_receipt=record.sealed_receipt,
                    )
                else:
                    self.revoked_families.add(record.family_id)
                    result = accounts_module.PrepareRefreshResult(
                        accounts_module.RefreshRotationStatus.REPLAY_DETECTED, family_revoked=True
                    )
            else:
                result = accounts_module.RefreshFamilyContext(
                    account_id=record.account_id,
                    family_id=record.family_id,
                    security_epoch=record.security_epoch,
                    token_expires_at=record.token_expires_at,
                    family_expires_at=record.family_expires_at,
                    scopes=record.scopes,
                    evidence=record.evidence,
                )
            self.preparations.append(result)
            if self._expected_preparations:
                self._prepared_count += 1
                if self._prepared_count == self._expected_preparations:
                    self._preparation_gate.set()
        if self._expected_preparations:
            await self._preparation_gate.wait()
        return result

    async def rotate(  # noqa: C901, PLR0911 - explicit atomic state-machine outcomes
        self, command: accounts_module.RotateRefreshCommand, *, now: datetime, event: accounts_module.SecurityEvent
    ) -> accounts_module.RotateRefreshResult:
        del event
        if self._expected_atomic_rotations:
            async with self._atomic_rotation_lock:
                self._atomic_rotation_count += 1
                if self._atomic_rotation_count == self._expected_atomic_rotations:
                    if self._before_atomic_rotate is not None:
                        self._before_atomic_rotate()
                    self._atomic_rotation_gate.set()
            await self._atomic_rotation_gate.wait()
        async with self._lock:
            record = self.tokens.get(command.token_id)
            if record is None or not hmac.compare_digest(record.token_digest, command.token_digest):
                return self._result(accounts_module.RefreshRotationStatus.INVALID)
            if record.family_id in self.revoked_families:
                return self._result(accounts_module.RefreshRotationStatus.REVOKED, family_revoked=True)
            if (
                command.account_id != record.account_id
                or command.family_id != record.family_id
                or command.security_epoch != record.security_epoch
                or command.family_expires_at != record.family_expires_at
                or command.scopes != record.scopes
                or command.evidence != record.evidence
            ):
                return self._result(accounts_module.RefreshRotationStatus.INVALID)
            if command.security_epoch != self.accounts.security_epoch:
                return self._result(accounts_module.RefreshRotationStatus.EPOCH_MISMATCH)
            if now >= record.token_expires_at or now >= record.family_expires_at:
                return self._result(accounts_module.RefreshRotationStatus.EXPIRED)
            if record.consumed:
                same_key = (
                    record.idempotency_digest is not None
                    and command.idempotency_digest is not None
                    and hmac.compare_digest(record.idempotency_digest, command.idempotency_digest)
                )
                if same_key and now < record.receipt_expires_at:
                    return self._result(
                        accounts_module.RefreshRotationStatus.IDEMPOTENT_REPLAY, sealed_receipt=record.sealed_receipt
                    )
                self.revoked_families.add(record.family_id)
                return self._result(accounts_module.RefreshRotationStatus.REPLAY_DETECTED, family_revoked=True)
            record.consumed = True
            record.idempotency_digest = command.idempotency_digest
            record.receipt_expires_at = command.receipt_expires_at
            record.sealed_receipt = command.sealed_receipt
            self.tokens[command.successor_id] = SimpleNamespace(
                account_id=record.account_id,
                consumed=False,
                family_expires_at=record.family_expires_at,
                family_id=record.family_id,
                idempotency_digest=None,
                evidence=record.evidence,
                receipt_expires_at=None,
                scopes=record.scopes,
                sealed_receipt=None,
                security_epoch=record.security_epoch,
                token_digest=command.successor_digest,
                token_expires_at=command.successor_expires_at,
            )
            return self._result(
                accounts_module.RefreshRotationStatus.ROTATED,
                sealed_receipt=self.override_receipt or command.sealed_receipt,
            )

    async def revoke_family(self, family_id: str, *, event: accounts_module.SecurityEvent) -> bool:
        del event
        async with self._lock:
            exists = any(record.family_id == family_id for record in self.tokens.values())
            if not exists or family_id in self.revoked_families:
                return False
            self.revoked_families.add(family_id)
            return True

    async def revoke_token(self, token_id: str, token_digest: bytes, *, event: accounts_module.SecurityEvent) -> bool:
        del event
        async with self._lock:
            record = self.tokens.get(token_id)
            if (
                record is None
                or record.family_id in self.revoked_families
                or not hmac.compare_digest(record.token_digest, token_digest)
            ):
                return False
            self.revoked_families.add(record.family_id)
            return True

    async def revoke_token_for_account(
        self, account_id: str, token_id: str, token_digest: bytes, *, event: accounts_module.SecurityEvent
    ) -> bool:
        del event
        async with self._lock:
            record = self.tokens.get(token_id)
            if (
                record is None
                or record.account_id != account_id
                or record.family_id in self.revoked_families
                or not hmac.compare_digest(record.token_digest, token_digest)
            ):
                return False
            self.revoked_families.add(record.family_id)
            return True

    async def revoke_for_account(self, account_id: str, *, event: accounts_module.SecurityEvent) -> int:
        del event
        async with self._lock:
            families = {
                record.family_id
                for record in self.tokens.values()
                if record.account_id == account_id and record.family_id not in self.revoked_families
            }
            self.revoked_families.update(families)
            return len(families)

    def _result(
        self,
        status: accounts_module.RefreshRotationStatus,
        *,
        sealed_receipt: bytes | None = None,
        family_revoked: bool = False,
    ) -> accounts_module.RotateRefreshResult:
        self.rotations.append(status)
        return accounts_module.RotateRefreshResult(
            status=status, sealed_receipt=sealed_receipt, family_revoked=family_revoked
        )


def _refresh_service(
    *,
    expected_preparations: int = 0,
    expected_atomic_rotations: int = 0,
    before_atomic_rotate: Callable[[], None] | None = None,
    idle_lifetime: timedelta = timedelta(days=7),
    absolute_lifetime: timedelta = timedelta(days=30),
) -> tuple[
    accounts_module.RefreshTokenService[object],
    _AtomicRefreshStore,
    _LocalAccessStore,
    accounts_module.LocalAccount[object],
]:
    account = _local_access_account()
    accounts = _LocalAccessStore(account)
    store = _AtomicRefreshStore(
        accounts,
        expected_preparations=expected_preparations,
        expected_atomic_rotations=expected_atomic_rotations,
        before_atomic_rotate=before_atomic_rotate,
    )
    codec = accounts_module.RefreshTokenCodec(pepper=b"p" * 32, entropy=_RefreshEntropy())
    receipts = accounts_module.RefreshReceiptSealer(
        active_key=accounts_module.RefreshReceiptKey("active", b"k" * 32), entropy=_RefreshEntropy()
    )
    access_tokens = accounts_module.LocalAccessTokenIssuer(
        signer=_AccessSigner(),
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        clock=lambda: _JWT_NOW,
        token_ids=lambda: "access-token",
    )
    return (
        accounts_module.RefreshTokenService(
            accounts=accounts,
            store=store,
            codec=codec,
            receipts=receipts,
            access_tokens=access_tokens,
            idle_lifetime=idle_lifetime,
            absolute_lifetime=absolute_lifetime,
            clock=lambda: _JWT_NOW,
            family_ids=lambda: _refresh_identifier("rf_", 1),
            event_ids=lambda: "refresh-event",
        ),
        store,
        accounts,
        account,
    )


@pytest.mark.anyio
async def test_mfa_operational_and_format_failure_branches_are_sanitized() -> None:
    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    store = _MFAStore()
    protector = _MFAProtector()
    service = _mfa_service(store, protector, now=now)
    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(enrollment, accounts_module.TOTPEnrollment)
    code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").at(now)
    method = await service.activate_totp("account-1", enrollment.enrollment_id, code)
    assert isinstance(method, accounts_module.TOTPMethod)
    next_time = now + timedelta(seconds=30)
    next_code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").at(next_time)
    service.clock = lambda: next_time
    store.fail = True
    assert isinstance(await service.verify_totp("account-1", method.method_id, next_code), VerificationUnavailable)

    class FailingLoginMethods(_RecoveryLoginMethods):
        async def revoke_login_method(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            raise OSError

    service.login_methods = cast("Any", FailingLoginMethods(accounts_module.RevokeLoginMethodStatus.REVOKED))
    assert isinstance(await service.remove_totp_method("account-1", method.method_id), VerificationUnavailable)

    failing_step_store = _StepUpStore()
    step_up = accounts_module.StepUpService(failing_step_store, clock=lambda: now)
    failing_step_store.consume = cast("Any", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()))
    assert isinstance(
        await step_up.consume(
            "token", principal_id="account-1", security_epoch=1, purpose="settings", transport_binding=b"session"
        ),
        VerificationUnavailable,
    )

    for invalid_secret in (1, "!!!!", "GEZA", base64.b32encode(b"x").decode()):
        invalid = _mfa_service(_MFAStore(), _MFAProtector(), now=now)
        invalid.secret_generator = cast("Any", lambda value=invalid_secret: value)
        assert isinstance(
            await invalid.begin_totp_enrollment("account-1", label="person@example.com"), VerificationUnavailable
        )
    invalid = _mfa_service(_MFAStore(), _MFAProtector(), now=now)
    invalid.recovery_peppers = (accounts_module.RecoveryCodePepper("v1", b"p" * 32),)
    invalid.recovery_entropy = cast("Any", lambda _size: b"short")
    assert isinstance(await invalid.generate_recovery_codes("account-1"), VerificationUnavailable)


@pytest.mark.anyio
async def test_mfa_atomic_rejection_and_step_up_storage_failure_are_sanitized() -> None:
    class RejectingAdvanceStore(_MFAStore):
        async def advance_totp_counter(self, method_id: str, *, accepted_counter: int, now: datetime) -> bool:
            del method_id, accepted_counter, now
            return False

    class FailingStepUpStore(_StepUpStore):
        async def put(self, record: accounts_module.StepUpRecord) -> None:
            del record
            raise OSError

    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    store = RejectingAdvanceStore()
    service = _mfa_service(store, _MFAProtector(), now=now)
    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(enrollment, accounts_module.TOTPEnrollment)
    activation_code = pyotp.TOTP(_MFA_ENCODED_SEED).at(now)
    method = await service.activate_totp("account-1", enrollment.enrollment_id, activation_code)
    assert isinstance(method, accounts_module.TOTPMethod)
    next_time = now + timedelta(seconds=30)
    service.clock = lambda: next_time
    assert isinstance(
        await service.verify_totp("account-1", method.method_id, pyotp.TOTP(_MFA_ENCODED_SEED).at(next_time)),
        InvalidCredentials,
    )
    assert isinstance(
        await service.verify_totp("account-1", method.method_id, "１２３４５６"),  # noqa: RUF001 - non-ASCII digits
        InvalidCredentials,
    )
    assert isinstance(await service.verify_totp("account-1", method.method_id, "ABCDEF"), InvalidCredentials)

    invalid_context = _mfa_service(_MFAStore(), _MFAProtector(), now=now)
    invalid_context.identifiers = iter(("enrollment", "bad\x00method")).__next__
    assert isinstance(
        await invalid_context.begin_totp_enrollment("account-1", label="person@example.com"), VerificationUnavailable
    )

    step_up = accounts_module.StepUpService(FailingStepUpStore(), clock=lambda: now)
    evidence = AuthenticationEvidence(mechanism="totp", slot="mfa", authenticated_at=now, methods=frozenset({"totp"}))
    assert isinstance(
        await step_up.issue(
            principal_id="account-1",
            security_epoch=1,
            purpose="settings",
            transport_binding=b"session",
            evidence=evidence,
        ),
        VerificationUnavailable,
    )

    atomic_store = _MFAStore()
    atomic = _mfa_service(atomic_store, _MFAProtector(), now=now)
    atomic.recovery_peppers = (accounts_module.RecoveryCodePepper("v1", b"p" * 32),)
    atomic.recovery_code_count = 1
    atomic.recovery_entropy = lambda length: b"r" * length
    pending = await atomic.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(pending, accounts_module.TOTPEnrollment)
    assert isinstance(
        await atomic.activate_totp_with_recovery_codes("account-1", pending.enrollment_id, "000000"), InvalidCredentials
    )
    atomic_store.fail = True
    assert isinstance(
        await atomic.activate_totp_with_recovery_codes(
            "account-1", pending.enrollment_id, pyotp.TOTP(_MFA_ENCODED_SEED).at(now)
        ),
        VerificationUnavailable,
    )
    atomic_store.fail = False
    activated = await atomic.activate_totp_with_recovery_codes(
        "account-1", pending.enrollment_id, pyotp.TOTP(_MFA_ENCODED_SEED).at(now)
    )
    assert isinstance(activated, accounts_module.RecoveryCodes)
    assert atomic_store.methods
    assert atomic_store.recovery_codes
    assert isinstance(
        await atomic.activate_totp_with_recovery_codes(
            "account-1", pending.enrollment_id, pyotp.TOTP(_MFA_ENCODED_SEED).at(now)
        ),
        InvalidCredentials,
    )

    class RejectActivationStore(_MFAStore):
        async def activate_totp_with_recovery_codes(
            self, *args: object, **kwargs: object
        ) -> accounts_module.TOTPMethod | None:
            del args, kwargs
            return None

    rejecting = _mfa_service(RejectActivationStore(), _MFAProtector(), now=now)
    rejecting.recovery_peppers = atomic.recovery_peppers
    rejecting.recovery_code_count = 1
    rejected_pending = await rejecting.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(rejected_pending, accounts_module.TOTPEnrollment)
    assert isinstance(
        await rejecting.activate_totp_with_recovery_codes(
            "account-1", rejected_pending.enrollment_id, pyotp.TOTP(_MFA_ENCODED_SEED).at(now)
        ),
        InvalidCredentials,
    )

    class RejectSingleActivationStore(_MFAStore):
        async def activate_totp(self, *args: object, **kwargs: object) -> accounts_module.TOTPMethod | None:
            del args, kwargs
            return None

    single = _mfa_service(RejectSingleActivationStore(), _MFAProtector(), now=now)
    single_pending = await single.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(single_pending, accounts_module.TOTPEnrollment)
    assert isinstance(
        await single.activate_totp("account-1", single_pending.enrollment_id, pyotp.TOTP(_MFA_ENCODED_SEED).at(now)),
        InvalidCredentials,
    )


@pytest.mark.anyio
async def test_passkey_defensive_registration_authentication_and_audit_outcomes() -> None:  # noqa: PLR0915
    class InvalidAttestationVerifier(_WebAuthnVerifier):
        def verify_registration(self, **kwargs: object) -> accounts_module.RegistrationVerification:
            return replace(super().verify_registration(**kwargs), attestation_format="packed")

    class ChainAttestationVerifier(InvalidAttestationVerifier):
        def verify_registration(self, **kwargs: object) -> accounts_module.RegistrationVerification:
            return replace(super().verify_registration(**kwargs), attestation_chain_verified=True)

    class TrustedAttestation:
        def root_certificates(self) -> Mapping[str, tuple[bytes, ...]]:
            return {"packed": (b"trusted-root",)}

        def trusted(self, verification: accounts_module.RegistrationVerification) -> bool:
            return verification.attestation_format == "packed"

    class UnanchoredAttestation(TrustedAttestation):
        def root_certificates(self) -> Mapping[str, tuple[bytes, ...]]:
            return {}

    class MismatchedAttestation(TrustedAttestation):
        def root_certificates(self) -> Mapping[str, tuple[bytes, ...]]:
            return {"tpm": (b"trusted-root",)}

    binding = b"session-binding"
    assert not passkeys_module._valid_attestation_roots({"none": (b"root",)})  # noqa: SLF001
    service = _passkey_service(verifier=InvalidAttestationVerifier())
    await service.begin_registration("account-1", user_name="person@example.com", binding=binding)
    assert isinstance(
        await service.verify_registration("account-1", binding=binding, response="{}"), InvalidCredentials
    )
    service = _passkey_service(verifier=_WebAuthnVerifier(backup_state=True))
    await service.begin_registration("account-1", user_name="person@example.com", binding=binding)
    assert isinstance(
        await service.verify_registration("account-1", binding=binding, response="{}"), InvalidCredentials
    )
    service = _passkey_service(verifier=InvalidAttestationVerifier(), attestation_trust=UnanchoredAttestation())
    await service.begin_registration("account-1", user_name="person@example.com", binding=binding)
    assert isinstance(
        await service.verify_registration("account-1", binding=binding, response="{}"), InvalidCredentials
    )
    service = _passkey_service(verifier=InvalidAttestationVerifier(), attestation_trust=TrustedAttestation())
    await service.begin_registration("account-1", user_name="person@example.com", binding=binding)
    assert isinstance(
        await service.verify_registration("account-1", binding=binding, response="{}"), InvalidCredentials
    )
    service = _passkey_service(verifier=ChainAttestationVerifier(), attestation_trust=MismatchedAttestation())
    await service.begin_registration("account-1", user_name="person@example.com", binding=binding)
    assert isinstance(
        await service.verify_registration("account-1", binding=binding, response="{}"), InvalidCredentials
    )

    trusted_store = _PasskeyStore()
    trusted_events = _SecurityEvents()
    service = _passkey_service(
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

    store = _PasskeyStore()
    store.credentials[b"credential-1"] = _stored_passkey()
    service = _passkey_service(store=store)
    await service.begin_registration("account-1", user_name="person@example.com", binding=binding)
    assert isinstance(
        await service.verify_registration("account-1", binding=binding, response="{}"), InvalidCredentials
    )

    service = _passkey_service(store=store)
    await service.begin_authentication("account-1", binding=binding)
    assert isinstance(await service.verify_authentication("other", binding=binding, response="{}"), InvalidCredentials)

    service = _passkey_service(store=store, verifier=_WebAuthnVerifier(failure="authentication"))
    await service.begin_authentication("account-1", binding=binding)
    assert isinstance(
        await service.verify_authentication("account-1", binding=binding, response="{}"), InvalidCredentials
    )

    challenge_store = _ChallengeStore()
    service = _passkey_service(challenge_store=challenge_store, store=store)
    await service.begin_authentication("account-1", binding=binding)
    challenge_store.fail = True
    assert isinstance(
        await service.verify_authentication("account-1", binding=binding, response="{}"), VerificationUnavailable
    )

    service = _passkey_service(store=store, verifier=_WebAuthnVerifier(user_verified=False, sign_count=2))
    await service.begin_authentication("account-1", binding=binding)
    evidence = await service.verify_authentication("account-1", binding=binding, response="{}")
    assert isinstance(evidence, AuthenticationEvidence)
    assert "user-verified" not in evidence.traits

    class FailingLoginMethods(_RecoveryLoginMethods):
        async def revoke_login_method(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            raise OSError

    service.login_methods = cast("Any", FailingLoginMethods())
    assert isinstance(await service.remove_credential("account-1", b"credential-1"), VerificationUnavailable)
    service.events = _SecurityEvents(fail=True)
    await service._emit_event(  # noqa: SLF001 - verifies best-effort audit isolation directly
        operation="passkey.assert", outcome="clone_risk", account_id="account-1", occurred_at=_JWT_NOW
    )


@pytest.mark.parametrize(
    "token",
    [
        "",
        "rt_missing-secret",
        "rt_AAAAAAAAAAAAAAAAAAAAAA.%",
        "rt_AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.extra",
        "xx_AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ],
)
def test_refresh_codec_is_canonical_hmac_only_and_rejects_malformed_tokens(token: str) -> None:
    first = accounts_module.RefreshTokenCodec(pepper=b"p" * 32, entropy=_RefreshEntropy())
    second = accounts_module.RefreshTokenCodec(pepper=b"q" * 32, entropy=_RefreshEntropy())
    issued = first.issue()

    proof = first.verify(issued.refresh_token)
    other_pepper = second.verify(issued.refresh_token)

    assert issued.refresh_token.startswith("rt_")
    assert len(issued.refresh_token) == 69
    assert isinstance(proof, accounts_module.RefreshTokenProof)
    assert proof.digest == issued.digest
    assert isinstance(other_pepper, accounts_module.RefreshTokenProof)
    assert other_pepper.digest != issued.digest
    assert isinstance(first.verify(token), InvalidCredentials)
    assert isinstance(first.digest_idempotency_key(issued.token_id, "%" * 22), InvalidCredentials)
    assert issued.refresh_token not in repr(issued)
    assert issued.digest.hex() not in repr(issued)


@pytest.mark.anyio
async def test_refresh_known_lookup_with_wrong_digest_is_invalid_without_family_revocation() -> None:
    service, store, _accounts, account = _refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)
    token_id = initial.refresh_token.split(".")[0]
    wrong_secret = base64.urlsafe_b64encode(b"wrong" * 6 + b"!!").rstrip(b"=").decode()

    outcome = await service.rotate(
        f"{token_id}.{wrong_secret}", idempotency_key=_refresh_idempotency_key(), now=_JWT_NOW
    )

    assert isinstance(outcome, InvalidCredentials)
    assert not store.revoked_families
    assert store.rotations == []


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("token_id", _refresh_identifier("rt_", 2)),
        ("family_id", _refresh_identifier("rf_", 2)),
        ("account_id", "account-2"),
        ("security_epoch", 4),
        ("idempotency_digest", b"z" * 32),
    ],
)
def test_refresh_receipts_bind_all_context_and_support_key_rotation(field: str, replacement: object) -> None:
    codec = accounts_module.RefreshTokenCodec(pepper=b"p" * 32, entropy=_RefreshEntropy())
    response = accounts_module.RefreshTokenResponse(
        access_token="e30.e30.YQ",  # noqa: S106 - compact public test JWT
        refresh_token=codec.issue().refresh_token,
        expires_in=600,
    )
    context = accounts_module.RefreshReceiptContext(
        token_id=_refresh_identifier("rt_", 1),
        family_id=_refresh_identifier("rf_", 1),
        account_id="account-1",
        security_epoch=3,
        idempotency_digest=b"i" * 32,
    )
    old_key = accounts_module.RefreshReceiptKey("old", b"o" * 32)
    receipt = accounts_module.RefreshReceiptSealer(active_key=old_key, entropy=_RefreshEntropy()).seal(
        response, context, expires_at=_JWT_NOW + timedelta(seconds=30)
    )
    rotated = accounts_module.RefreshReceiptSealer(
        active_key=accounts_module.RefreshReceiptKey("new", b"n" * 32),
        retained_keys=(old_key, accounts_module.RefreshReceiptKey("alias", old_key.key)),
    )

    assert rotated.unseal(receipt, context, now=_JWT_NOW) == response
    assert isinstance(
        rotated.unseal(receipt, replace(context, **{field: replacement}), now=_JWT_NOW), InvalidCredentials
    )
    assert isinstance(
        accounts_module.RefreshReceiptSealer(active_key=rotated.active_key).unseal(receipt, context, now=_JWT_NOW),
        InvalidCredentials,
    )
    assert isinstance(
        rotated.unseal(receipt[:-1] + bytes([receipt[-1] ^ 1]), context, now=_JWT_NOW), InvalidCredentials
    )
    assert isinstance(
        rotated.unseal(receipt.replace(b".old.", b".alias.", 1), context, now=_JWT_NOW), InvalidCredentials
    )
    assert isinstance(rotated.unseal(receipt, context, now=_JWT_NOW + timedelta(seconds=30)), InvalidCredentials)
    assert response.access_token.encode() not in receipt
    assert response.refresh_token.encode() not in receipt
    assert response.access_token not in repr(response)
    assert response.refresh_token not in repr(response)


@pytest.mark.anyio
async def test_refresh_first_rotation_and_same_key_duplicate_return_exact_sealed_result() -> None:
    service, store, _accounts, account = _refresh_service()
    initial = await service.issue(account, scopes=frozenset({"reports:read"}), now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)
    key = _refresh_idempotency_key()

    first = await service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW)
    duplicate = await service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW)

    assert isinstance(first, accounts_module.RefreshTokenResponse)
    assert duplicate == first
    assert store.rotations == [accounts_module.RefreshRotationStatus.ROTATED]
    assert isinstance(store.preparations[-1], accounts_module.RefreshReceiptReplay)
    original = next(iter(store.tokens.values()))
    successor_id = next(token_id for token_id in store.tokens if token_id != initial.refresh_token.split(".")[0])
    successor = store.tokens[successor_id]
    assert original.consumed
    assert successor.scopes == frozenset({"reports:read"})
    assert successor.token_expires_at <= successor.family_expires_at
    stored = repr(store.tokens)
    for plaintext in (initial.refresh_token, first.access_token, first.refresh_token):
        assert plaintext not in stored


@pytest.mark.anyio
async def test_refresh_rotation_preserves_original_passkey_assurance_and_time() -> None:
    service, store, _accounts, account = _refresh_service()
    authenticated_at = _JWT_NOW - timedelta(minutes=2)
    evidence = AuthenticationEvidence(
        mechanism="passkey",
        slot="mfa",
        authenticated_at=authenticated_at,
        methods=frozenset({"passkey"}),
        traits=frozenset({"phishing-resistant"}),
        amr=("passkey",),
    )
    initial = await service.issue(account, evidence=evidence, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)

    rotated = await service.rotate(
        initial.refresh_token, idempotency_key=_refresh_idempotency_key(), now=_JWT_NOW + timedelta(minutes=1)
    )

    assert isinstance(rotated, accounts_module.RefreshTokenResponse)
    records = tuple(store.tokens.values())
    assert all(record.evidence == evidence for record in records)
    signer = cast("_AccessSigner", service.access_tokens.signer)
    assert [claims["auth_time"] for claims in signer.claims] == [
        int(authenticated_at.timestamp()),
        int(authenticated_at.timestamp()),
    ]
    assert all(claims["amr"] == ["passkey"] for claims in signer.claims)


@pytest.mark.parametrize("outage", ["signer", "token_entropy", "receipt_entropy"])
@pytest.mark.anyio
async def test_refresh_same_key_retry_recovers_without_fresh_crypto(outage: str) -> None:
    service, _store, _accounts, account = _refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)
    key = _refresh_idempotency_key()
    first = await service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW)
    assert isinstance(first, accounts_module.RefreshTokenResponse)
    if outage == "signer":
        service = replace(service, access_tokens=_RefreshAccessOutcome(VerificationUnavailable(), fail=True))
    elif outage == "token_entropy":
        service = replace(
            service,
            codec=accounts_module.RefreshTokenCodec(pepper=service.codec.pepper, entropy=lambda _length: b"short"),
        )
    else:
        service = replace(service, receipts=replace(service.receipts, entropy=lambda _length: b"short"))

    duplicate = await service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW)

    assert duplicate == first


@pytest.mark.anyio
async def test_refresh_receipt_window_preserves_subsecond_precision() -> None:
    service, _store, _accounts, account = _refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)
    key = _refresh_idempotency_key()
    rotated_at = _JWT_NOW + timedelta(microseconds=500_000)
    first = await service.rotate(initial.refresh_token, idempotency_key=key, now=rotated_at)
    assert isinstance(first, accounts_module.RefreshTokenResponse)

    duplicate = await service.rotate(
        initial.refresh_token, idempotency_key=key, now=rotated_at + timedelta(seconds=29, microseconds=750_000)
    )

    assert duplicate == first


@pytest.mark.anyio
async def test_refresh_malformed_key_revokes_consumed_token_but_not_active_token() -> None:
    service, store, _accounts, account = _refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)
    assert isinstance(
        await service.rotate(initial.refresh_token, idempotency_key="weak", now=_JWT_NOW), InvalidCredentials
    )
    first = await service.rotate(initial.refresh_token, idempotency_key=_refresh_idempotency_key(), now=_JWT_NOW)
    assert isinstance(first, accounts_module.RefreshTokenResponse)
    assert isinstance(
        await service.rotate(initial.refresh_token, idempotency_key="weak", now=_JWT_NOW), InvalidCredentials
    )
    assert next(iter(store.tokens.values())).family_id in store.revoked_families
    assert store.preparation_events[-1].operation == "local.refresh.prepare"
    assert store.preparation_events[-1].outcome == "attempted"
    assert "weak" not in repr(store.preparation_events[-1])


@pytest.mark.anyio
async def test_refresh_preflight_replay_receipt_failure_revokes_family() -> None:
    service, store, _accounts, account = _refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)
    key = _refresh_idempotency_key()
    first = await service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW)
    assert isinstance(first, accounts_module.RefreshTokenResponse)
    record = store.tokens[initial.refresh_token.partition(".")[0]]
    record.sealed_receipt = b"malformed"

    outcome = await service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert record.family_id in store.revoked_families


@pytest.mark.parametrize(
    ("second_key", "advance"),
    [
        (None, timedelta(0)),
        (_refresh_idempotency_key(2), timedelta(0)),
        (_refresh_idempotency_key(1), timedelta(seconds=30)),
    ],
)
@pytest.mark.anyio
async def test_refresh_replay_without_exact_live_key_revokes_family(second_key: str | None, advance: timedelta) -> None:
    service, store, _accounts, account = _refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)
    first = await service.rotate(initial.refresh_token, idempotency_key=_refresh_idempotency_key(1), now=_JWT_NOW)
    assert isinstance(first, accounts_module.RefreshTokenResponse)

    replay = await service.rotate(initial.refresh_token, idempotency_key=second_key, now=_JWT_NOW + advance)

    assert isinstance(replay, InvalidCredentials)
    assert any(
        isinstance(prepared, accounts_module.PrepareRefreshResult)
        and prepared.status is accounts_module.RefreshRotationStatus.REPLAY_DETECTED
        and prepared.family_revoked
        for prepared in store.preparations
    )
    family_id = next(iter(store.tokens.values())).family_id
    assert family_id in store.revoked_families
    assert isinstance(
        await service.rotate(first.refresh_token, idempotency_key=second_key, now=_JWT_NOW + advance),
        InvalidCredentials,
    )


@pytest.mark.parametrize("receipt_kind", ["malformed", "expired", "swapped_context"])
@pytest.mark.anyio
async def test_refresh_invalid_store_receipt_fails_closed_and_revokes_family(receipt_kind: str) -> None:
    service, store, _accounts, account = _refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)
    key = _refresh_idempotency_key()
    proof = service.codec.verify(initial.refresh_token)
    assert isinstance(proof, accounts_module.RefreshTokenProof)
    digest = service.codec.digest_idempotency_key(proof.token_id, key)
    assert isinstance(digest, bytes)
    record = store.tokens[proof.token_id]
    if receipt_kind == "malformed":
        store.override_receipt = b"rr1.malformed"
    else:
        context = accounts_module.RefreshReceiptContext(
            token_id=proof.token_id,
            family_id=(_refresh_identifier("rf_", 2) if receipt_kind == "swapped_context" else record.family_id),
            account_id=record.account_id,
            security_epoch=record.security_epoch,
            idempotency_digest=digest,
        )
        store.override_receipt = service.receipts.seal(
            accounts_module.RefreshTokenResponse(
                access_token="e30.e30.YQ",  # noqa: S106 - compact public test JWT
                refresh_token=service.codec.issue().refresh_token,
                expires_in=600,
            ),
            context,
            expires_at=_JWT_NOW if receipt_kind == "expired" else _JWT_NOW + timedelta(seconds=30),
        )

    outcome = await service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert record.family_id in store.revoked_families


@pytest.mark.parametrize("condition", ["idle", "absolute", "epoch", "disabled", "account_revoke", "family_revoke"])
@pytest.mark.anyio
async def test_refresh_rotation_rejects_expiry_epoch_and_revocation_boundaries(condition: str) -> None:
    idle = timedelta(days=1)
    absolute = timedelta(days=2)
    service, store, accounts, account = _refresh_service(idle_lifetime=idle, absolute_lifetime=absolute)
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)
    rotate_at = _JWT_NOW
    if condition == "idle":
        rotate_at += idle
    elif condition == "absolute":
        rotate_at += absolute
    elif condition == "epoch":
        accounts.security_epoch += 1
    elif condition == "disabled":
        accounts.account = replace(account, active=False)
    elif condition == "account_revoke":
        await store.revoke_for_account(
            account.account_id,
            event=accounts_module.SecurityEvent(
                "event-revoke", _JWT_NOW, "local.refresh.revoke", "revoked", account_id=account.account_id
            ),
        )
    else:
        family_id = next(iter(store.tokens.values())).family_id
        await store.revoke_family(
            family_id,
            event=accounts_module.SecurityEvent(
                "event-revoke", _JWT_NOW, "local.refresh.revoke", "revoked", family_id=family_id
            ),
        )

    outcome = await service.rotate(initial.refresh_token, idempotency_key=_refresh_idempotency_key(), now=rotate_at)

    assert isinstance(outcome, InvalidCredentials)
    assert len(store.tokens) == 1


@pytest.mark.anyio
async def test_refresh_epoch_bump_after_preflight_is_rejected_by_atomic_rotate() -> None:
    accounts_holder: list[_LocalAccessStore] = []

    def bump_epoch() -> None:
        accounts_holder[0].security_epoch += 1

    service, store, accounts, account = _refresh_service(
        expected_preparations=100, expected_atomic_rotations=100, before_atomic_rotate=bump_epoch
    )
    accounts_holder.append(accounts)
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)

    outcomes = await asyncio.gather(
        *(
            service.rotate(initial.refresh_token, idempotency_key=_refresh_idempotency_key(), now=_JWT_NOW)
            for _ in range(100)
        )
    )

    assert all(isinstance(outcome, InvalidCredentials) for outcome in outcomes)
    assert store.rotations == [accounts_module.RefreshRotationStatus.EPOCH_MISMATCH] * 100
    assert len(store.tokens) == 1
    assert not store.revoked_families


@pytest.mark.anyio
async def test_refresh_atomic_rotate_revalidates_preserved_scopes() -> None:
    service, store, _accounts, account = _refresh_service()
    initial = await service.issue(account, scopes=frozenset({"read"}), now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)
    prepare_rotation = store.prepare_rotation

    async def broadened_preflight(
        proof: accounts_module.RefreshTokenProof,
        idempotency_digest: bytes | None,
        *,
        now: datetime,
        event: accounts_module.SecurityEvent,
    ) -> (
        accounts_module.RefreshFamilyContext
        | accounts_module.RefreshReceiptReplay
        | accounts_module.PrepareRefreshResult
    ):
        prepared = await prepare_rotation(proof, idempotency_digest, now=now, event=event)
        return (
            replace(prepared, scopes=frozenset({"admin"}))
            if isinstance(prepared, accounts_module.RefreshFamilyContext)
            else prepared
        )

    store.prepare_rotation = broadened_preflight  # type: ignore[method-assign]

    outcome = await service.rotate(initial.refresh_token, idempotency_key=_refresh_idempotency_key(), now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert store.rotations == [accounts_module.RefreshRotationStatus.INVALID]
    assert len(store.tokens) == 1


@pytest.mark.anyio
async def test_refresh_presented_token_revoke_is_exact_and_idempotent() -> None:
    service, store, _accounts, account = _refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)

    assert not await service.revoke_for_account("account-2", initial.refresh_token, now=_JWT_NOW)
    assert await service.revoke_for_account(account.account_id, initial.refresh_token, now=_JWT_NOW)
    assert not await service.revoke(initial.refresh_token, now=_JWT_NOW)
    assert isinstance(await service.revoke("malformed", now=_JWT_NOW), InvalidCredentials)
    assert len(store.revoked_families) == 1


@pytest.mark.parametrize("mode", ["shared_key", "no_key"])
@pytest.mark.anyio
async def test_refresh_one_hundred_way_races_enforce_one_logical_result(mode: str) -> None:
    service, store, _accounts, account = _refresh_service(expected_preparations=100)
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)
    key = _refresh_idempotency_key() if mode == "shared_key" else None

    outcomes = await asyncio.gather(
        *(service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW) for _ in range(100))
    )

    successes = [outcome for outcome in outcomes if isinstance(outcome, accounts_module.RefreshTokenResponse)]
    if mode == "shared_key":
        assert len(successes) == 100
        assert all(outcome == successes[0] for outcome in successes)
        assert store.rotations.count(accounts_module.RefreshRotationStatus.ROTATED) == 1
        assert store.rotations.count(accounts_module.RefreshRotationStatus.IDEMPOTENT_REPLAY) == 99
        assert not store.revoked_families
    else:
        assert len(successes) == 1
        assert sum(isinstance(outcome, InvalidCredentials) for outcome in outcomes) == 99
        assert store.rotations.count(accounts_module.RefreshRotationStatus.ROTATED) == 1
        assert accounts_module.RefreshRotationStatus.REPLAY_DETECTED in store.rotations
        assert len(store.revoked_families) == 1
        assert isinstance(await service.rotate(successes[0].refresh_token, now=_JWT_NOW), InvalidCredentials)


def test_refresh_response_headers_are_immutable_no_store_contract() -> None:
    assert accounts_module.REFRESH_RESPONSE_HEADERS == {"Cache-Control": "no-store", "Pragma": "no-cache"}
    with pytest.raises(TypeError):
        accounts_module.REFRESH_RESPONSE_HEADERS["Cache-Control"] = "public"  # type: ignore[index]


def test_refresh_service_rejects_invalid_composition_and_lifetimes() -> None:
    service, _store, _accounts, _account = _refresh_service()
    invalid_values = (
        ("accounts", object(), "accounts"),
        ("store", object(), "store"),
        ("codec", object(), "codec"),
        ("receipts", object(), "receipts"),
        ("access_tokens", object(), "issuer"),
        ("idle_lifetime", object(), "lifetimes"),
        ("absolute_lifetime", object(), "lifetimes"),
        ("receipt_window", object(), "lifetimes"),
        ("idle_lifetime", timedelta(0), "lifetimes"),
        ("absolute_lifetime", timedelta(days=1), "lifetimes"),
        ("receipt_window", timedelta(0), "lifetimes"),
        ("receipt_window", timedelta(seconds=31), "lifetimes"),
        ("clock", None, "factories"),
        ("family_ids", None, "factories"),
        ("event_ids", None, "factories"),
    )

    for field_name, value, match in invalid_values:
        with pytest.raises(ImproperlyConfiguredException, match=match):
            replace(service, **{field_name: value})


@pytest.mark.anyio
async def test_refresh_service_default_clock_and_id_factories_issue_valid_family() -> None:
    service, store, accounts, account = _refresh_service()
    defaulted = accounts_module.RefreshTokenService(
        accounts=accounts,
        store=store,
        codec=service.codec,
        receipts=service.receipts,
        access_tokens=service.access_tokens,
    )

    outcome = await defaulted.issue(account)

    assert isinstance(outcome, accounts_module.RefreshTokenResponse)
    assert next(iter(store.tokens.values())).family_id.startswith("rf_")


class _BrokenRefreshScopes(AbstractSet[str]):
    def __contains__(self, _value: object) -> bool:
        return False

    def __len__(self) -> int:
        return 1

    def __iter__(self) -> Iterator[str]:
        raise TypeError


class _RefreshAccessOutcome:
    def __init__(self, outcome: object, *, fail: bool = False) -> None:
        self.outcome = outcome
        self.fail = fail

    async def issue(self, _account: object, *, scopes: object, evidence: object | None = None, now: datetime) -> object:
        del scopes, evidence, now
        if self.fail:
            raise OSError
        return self.outcome


@pytest.mark.parametrize(
    "mode",
    [
        "not_account",
        "inactive",
        "unverified",
        "clock_failure",
        "epoch_failure",
        "epoch_bool",
        "epoch_mismatch",
        "scopes_type",
        "scopes_broken",
        "scopes_invalid",
        "access_outcome",
        "access_failure",
        "access_shape",
        "bad_family_id",
        "codec_failure",
        "event_failure",
        "create_failure",
        "create_false",
    ],
)
@pytest.mark.anyio
async def test_refresh_issue_sanitizes_invalid_and_unavailable_composition(  # noqa: C901, PLR0912, PLR0915
    mode: str,
) -> None:
    service, store, accounts, account = _refresh_service()
    candidate: object = account
    scopes: object = frozenset()
    now: datetime | None = _JWT_NOW
    if mode == "not_account":
        candidate = object()
    elif mode == "inactive":
        candidate = replace(account, active=False)
    elif mode == "unverified":
        candidate = replace(account, verified=False)
    elif mode == "clock_failure":
        service = replace(service, clock=lambda: 1 / 0)
        now = None
    elif mode == "epoch_failure":

        async def current_epoch(_account_id: str) -> int:
            raise OSError

        accounts.current_epoch = current_epoch  # type: ignore[method-assign]
    elif mode == "epoch_bool":

        async def current_epoch(_account_id: str) -> bool:
            return True

        accounts.current_epoch = current_epoch  # type: ignore[method-assign]
    elif mode == "epoch_mismatch":
        accounts.security_epoch += 1
    elif mode == "scopes_type":
        scopes = ["read"]
    elif mode == "scopes_broken":
        scopes = _BrokenRefreshScopes()
    elif mode == "scopes_invalid":
        scopes = frozenset({"bad scope"})
    elif mode == "access_outcome":
        service = replace(service, access_tokens=_RefreshAccessOutcome(InvalidCredentials()))
    elif mode == "access_failure":
        service = replace(service, access_tokens=_RefreshAccessOutcome(VerificationUnavailable(), fail=True))
    elif mode == "access_shape":
        service = replace(service, access_tokens=_RefreshAccessOutcome(object()))
    elif mode == "bad_family_id":
        service = replace(service, family_ids=lambda: "invalid")
    elif mode == "codec_failure":
        service = replace(
            service, codec=accounts_module.RefreshTokenCodec(pepper=b"p" * 32, entropy=lambda _length: b"short")
        )
    elif mode == "event_failure":
        service = replace(service, event_ids=lambda: " ")
    elif mode == "create_failure":

        async def create_family(
            _command: accounts_module.CreateRefreshFamilyCommand, *, event: accounts_module.SecurityEvent
        ) -> bool:
            del event
            raise OSError

        store.create_family = create_family  # type: ignore[method-assign]
    else:

        async def create_family(
            _command: accounts_module.CreateRefreshFamilyCommand, *, event: accounts_module.SecurityEvent
        ) -> bool:
            del event
            return False

        store.create_family = create_family  # type: ignore[method-assign]

    outcome = await service.issue(candidate, scopes=scopes, now=now)  # type: ignore[arg-type]

    expected = (
        VerificationUnavailable
        if mode
        in {
            "clock_failure",
            "epoch_failure",
            "access_failure",
            "access_shape",
            "bad_family_id",
            "codec_failure",
            "event_failure",
            "create_failure",
            "create_false",
        }
        else InvalidCredentials
    )
    assert isinstance(outcome, expected)


@pytest.mark.parametrize(
    "mode",
    [
        "malformed",
        "prepare_failure",
        "prepare_shape",
        "expired_context",
        "invalid_idempotency",
        "replay_account_failure",
        "account_failure",
        "access_outcome",
        "access_failure",
        "access_shape",
        "codec_failure",
        "seal_failure",
        "event_failure",
        "rotate_failure",
        "rotate_shape",
        "receipt_revoke_failure",
        "receipt_revoke_false",
    ],
)
@pytest.mark.anyio
async def test_refresh_rotate_sanitizes_invalid_and_unavailable_composition(  # noqa: C901,PLR0912,PLR0915
    mode: str,
) -> None:
    service, store, accounts, account = _refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)
    presented = initial.refresh_token
    idempotency_key: str | None = _refresh_idempotency_key()
    if mode == "malformed":
        presented = "malformed"
    elif mode == "prepare_failure":

        async def prepare_rotation(
            _proof: accounts_module.RefreshTokenProof,
            _idempotency_digest: bytes | None,
            *,
            now: datetime,
            event: accounts_module.SecurityEvent,
        ) -> accounts_module.PrepareRefreshResult:
            del now, event
            raise OSError

        store.prepare_rotation = prepare_rotation  # type: ignore[method-assign]
    elif mode == "prepare_shape":

        async def prepare_rotation(
            _proof: accounts_module.RefreshTokenProof,
            _idempotency_digest: bytes | None,
            *,
            now: datetime,
            event: accounts_module.SecurityEvent,
        ) -> object:
            del now, event
            return object()

        store.prepare_rotation = prepare_rotation  # type: ignore[method-assign]
    elif mode == "expired_context":
        record = next(iter(store.tokens.values()))

        async def prepare_rotation(
            _proof: accounts_module.RefreshTokenProof,
            _idempotency_digest: bytes | None,
            *,
            now: datetime,
            event: accounts_module.SecurityEvent,
        ) -> accounts_module.RefreshFamilyContext:
            del now, event
            return accounts_module.RefreshFamilyContext(
                account_id=record.account_id,
                family_id=record.family_id,
                security_epoch=record.security_epoch,
                token_expires_at=_JWT_NOW,
                family_expires_at=record.family_expires_at,
                scopes=record.scopes,
            )

        store.prepare_rotation = prepare_rotation  # type: ignore[method-assign]
    elif mode == "invalid_idempotency":
        idempotency_key = "weak"
    elif mode == "replay_account_failure":
        first = await service.rotate(presented, idempotency_key=idempotency_key, now=_JWT_NOW)
        assert isinstance(first, accounts_module.RefreshTokenResponse)

        async def get_by_id(_account_id: str) -> None:
            return None

        accounts.get_by_id = get_by_id  # type: ignore[method-assign]
    elif mode == "account_failure":

        async def get_by_id(_account_id: str) -> accounts_module.LocalAccount[object] | None:
            raise OSError

        accounts.get_by_id = get_by_id  # type: ignore[method-assign]
    elif mode == "access_outcome":
        service = replace(service, access_tokens=_RefreshAccessOutcome(VerificationUnavailable()))
    elif mode == "access_failure":
        service = replace(service, access_tokens=_RefreshAccessOutcome(VerificationUnavailable(), fail=True))
    elif mode == "access_shape":
        service = replace(service, access_tokens=_RefreshAccessOutcome(object()))
    elif mode == "codec_failure":
        service = replace(
            service,
            codec=accounts_module.RefreshTokenCodec(pepper=service.codec.pepper, entropy=lambda _length: b"short"),
        )
    elif mode == "seal_failure":
        service = replace(
            service,
            receipts=accounts_module.RefreshReceiptSealer(
                active_key=accounts_module.RefreshReceiptKey("key", b"k" * 32), entropy=lambda _length: b"short"
            ),
        )
    elif mode == "event_failure":
        service = replace(service, event_ids=lambda: " ")
    elif mode == "rotate_failure":

        async def rotate(
            _command: accounts_module.RotateRefreshCommand, *, now: datetime, event: accounts_module.SecurityEvent
        ) -> accounts_module.RotateRefreshResult:
            del now, event
            raise OSError

        store.rotate = rotate  # type: ignore[method-assign]
    elif mode == "rotate_shape":

        async def rotate(
            _command: accounts_module.RotateRefreshCommand, *, now: datetime, event: accounts_module.SecurityEvent
        ) -> object:
            del now, event
            return object()

        store.rotate = rotate  # type: ignore[method-assign]
    else:
        store.override_receipt = b"malformed"
        if mode == "receipt_revoke_failure":

            async def revoke_family(_family_id: str, *, event: accounts_module.SecurityEvent) -> bool:
                del event
                raise OSError

        else:

            async def revoke_family(_family_id: str, *, event: accounts_module.SecurityEvent) -> bool:
                del event
                return False

        store.revoke_family = revoke_family  # type: ignore[method-assign,possibly-undefined]

    outcome = await service.rotate(presented, idempotency_key=idempotency_key, now=_JWT_NOW)

    unavailable_modes = {
        "prepare_failure",
        "prepare_shape",
        "account_failure",
        "access_outcome",
        "access_failure",
        "access_shape",
        "codec_failure",
        "seal_failure",
        "event_failure",
        "rotate_failure",
        "rotate_shape",
        "receipt_revoke_failure",
        "receipt_revoke_false",
    }
    assert isinstance(outcome, VerificationUnavailable if mode in unavailable_modes else InvalidCredentials)


@pytest.mark.anyio
async def test_refresh_revoke_maps_store_and_clock_failures_to_unavailable() -> None:
    service, store, _accounts, account = _refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.RefreshTokenResponse)

    async def revoke_token(_token_id: str, _token_digest: bytes, *, event: accounts_module.SecurityEvent) -> bool:
        del event
        raise OSError

    store.revoke_token = revoke_token  # type: ignore[method-assign]
    assert isinstance(await service.revoke(initial.refresh_token, now=_JWT_NOW), VerificationUnavailable)

    async def malformed_revoke_token(
        _token_id: str, _token_digest: bytes, *, event: accounts_module.SecurityEvent
    ) -> object:
        del event
        return object()

    store.revoke_token = malformed_revoke_token  # type: ignore[method-assign]
    assert isinstance(await service.revoke(initial.refresh_token, now=_JWT_NOW), VerificationUnavailable)
    assert isinstance(
        await replace(service, clock=lambda: 1 / 0).revoke(initial.refresh_token), VerificationUnavailable
    )
    assert isinstance(await service.revoke_for_account("", initial.refresh_token, now=_JWT_NOW), InvalidCredentials)
    assert isinstance(
        await service.revoke_for_account(account.account_id, "malformed", now=_JWT_NOW), InvalidCredentials
    )

    async def failing_account_revoke(
        _account_id: str, _token_id: str, _token_digest: bytes, *, event: accounts_module.SecurityEvent
    ) -> bool:
        del event
        raise OSError

    store.revoke_token_for_account = failing_account_revoke  # type: ignore[method-assign]
    assert isinstance(
        await service.revoke_for_account(account.account_id, initial.refresh_token, now=_JWT_NOW),
        VerificationUnavailable,
    )

    async def malformed_account_revoke(
        _account_id: str, _token_id: str, _token_digest: bytes, *, event: accounts_module.SecurityEvent
    ) -> object:
        del event
        return object()

    store.revoke_token_for_account = malformed_account_revoke  # type: ignore[method-assign]
    assert isinstance(
        await service.revoke_for_account(account.account_id, initial.refresh_token, now=_JWT_NOW),
        VerificationUnavailable,
    )
    assert isinstance(
        await replace(service, clock=lambda: 1 / 0).revoke_for_account(account.account_id, initial.refresh_token),
        VerificationUnavailable,
    )


@pytest.mark.anyio
async def test_generated_local_handlers_map_services_to_typed_http_contracts() -> None:  # noqa: PLR0915
    class AsyncOutcome:
        def __init__(self, *outcomes: object) -> None:
            self.outcomes = list(outcomes)

        async def __call__(self, *_args: object, **_kwargs: object) -> object:
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

    class SessionRoutes:
        def __init__(self) -> None:
            success = True
            self.logout = AsyncOutcome(success, VerificationUnavailable())
            self.revoke_session = AsyncOutcome(success, VerificationUnavailable())
            self.list_sessions = AsyncOutcome((), OSError())

        def current_authentication(self, _request: object) -> accounts_module.SessionAuthentication | None:
            return None

    token = accounts_module.RefreshTokenCodec(pepper=b"p" * 32, entropy=_RefreshEntropy()).issue().refresh_token
    refresh_response = accounts_module.RefreshTokenResponse(
        access_token="e30.e30.YQ",  # noqa: S106 - compact public test JWT
        refresh_token=token,
        expires_in=600,
    )
    principal = Principal(id="account-1")
    anonymous = Principal.anonymous()
    credentials = accounts_module.LocalCredentials(
        identifier="user@example.com",
        password="secret",  # noqa: S106 - request DTO fixture
    )
    token_request = accounts_module.LocalTokenRequest(token=token)
    password_request = accounts_module.LocalPasswordChangeRequest(
        current_password="old",  # noqa: S106 - request DTO fixture
        password="new-password",  # noqa: S106 - request DTO fixture
    )
    session_routes = SessionRoutes()
    services = SimpleNamespace(
        session_login=AsyncOutcome(accounts_module.LocalAccountResponse("account-1"), InvalidCredentials()),
        token_login=AsyncOutcome(refresh_response, InvalidCredentials()),
        session_auth=session_routes,
        refresh_tokens=SimpleNamespace(
            rotate=AsyncOutcome(refresh_response, InvalidCredentials()),
            revoke_for_account=AsyncOutcome(bool(1), VerificationUnavailable()),
        ),
        recovery=SimpleNamespace(
            request=AsyncOutcome(accounts_module.LifecycleAccepted()),
            reset=AsyncOutcome(
                accounts_module.PasswordResetResult(
                    accounts_module.PasswordResetStatus.RESET, account_id="account-1", security_epoch=2
                ),
                accounts_module.PasswordResetResult(accounts_module.PasswordResetStatus.INVALID),
            ),
        ),
        verification=SimpleNamespace(
            resend=AsyncOutcome(accounts_module.LifecycleAccepted()),
            consume=AsyncOutcome(
                accounts_module.ConsumeResult(accounts_module.ConsumeStatus.CONSUMED, "account-1", 1),
                accounts_module.ConsumeResult(accounts_module.ConsumeStatus.INVALID),
            ),
        ),
        registration=SimpleNamespace(
            register=AsyncOutcome(accounts_module.LifecycleAccepted(), accounts_module.InvalidInvitation())
        ),
        change_session_password=AsyncOutcome(
            accounts_module.PasswordChangeResult(accounts_module.PasswordChangeStatus.CHANGED, security_epoch=2),
            InvalidCredentials(),
        ),
        change_token_password=AsyncOutcome(
            accounts_module.PasswordChangeResult(accounts_module.PasswordChangeStatus.CHANGED, security_epoch=2),
            accounts_module.InvalidLifecycleRequest(),
        ),
        client_key_for=lambda _connection: "1.2.3.4",
    )
    request = cast("Any", SimpleNamespace())

    session_login = cast("Any", controllers_module._LocalSessionController.login.fn)  # noqa: SLF001
    assert (await session_login(None, credentials, request, services)).status_code == 200
    await _assert_http_exception(
        session_login(None, credentials, request, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )
    session_logout = cast("Any", controllers_module._LocalSessionController.logout.fn)  # noqa: SLF001
    assert (await session_logout(None, request, services)).status_code == 200
    await _assert_http_exception(
        session_logout(None, request, services),
        ServiceUnavailableException,
        status_code=503,
        detail="Authentication service is unavailable.",
    )
    services.session_auth = None
    await _assert_http_exception(
        session_logout(None, request, services),
        ServiceUnavailableException,
        status_code=503,
        detail="Authentication service is unavailable.",
    )
    services.session_auth = session_routes
    list_sessions = cast("Any", controllers_module._LocalSessionController.list_sessions.fn)  # noqa: SLF001
    assert (await list_sessions(None, request, principal, services)).status_code == 200
    await _assert_http_exception(
        list_sessions(None, request, principal, services),
        ServiceUnavailableException,
        status_code=503,
        detail="Authentication service is unavailable.",
    )
    await _assert_http_exception(
        list_sessions(None, request, anonymous, services),
        NotAuthorizedException,
        status_code=401,
        detail="Authentication required.",
    )
    revoke_session = cast("Any", controllers_module._LocalSessionController.revoke_session.fn)  # noqa: SLF001
    assert (await revoke_session(None, "session", request, principal, services)).status_code == 200
    await _assert_http_exception(
        revoke_session(None, "session", request, principal, services),
        ServiceUnavailableException,
        status_code=503,
        detail="Authentication service is unavailable.",
    )
    services.session_auth = None
    await _assert_http_exception(
        revoke_session(None, "session", request, principal, services),
        NotAuthorizedException,
        status_code=401,
        detail="Authentication required.",
    )
    services.session_auth = session_routes

    token_login = cast("Any", controllers_module._LocalTokenController.login.fn)  # noqa: SLF001
    assert (await token_login(None, credentials, request, services)).status_code == 200
    await _assert_http_exception(
        token_login(None, credentials, request, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )
    refresh = cast("Any", controllers_module._LocalTokenController.refresh.fn)  # noqa: SLF001
    assert (await refresh(None, token_request, request, services, "AAAAAAAAAAAAAAAAAAAAAA")).status_code == 200
    await _assert_http_exception(
        refresh(None, token_request, request, services, None),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )
    refresh_tokens = services.refresh_tokens
    services.refresh_tokens = None
    await _assert_http_exception(
        refresh(None, token_request, request, services, None),
        ServiceUnavailableException,
        status_code=503,
        detail="Authentication service is unavailable.",
    )
    services.refresh_tokens = refresh_tokens
    revoke = cast("Any", controllers_module._LocalTokenController.revoke.fn)  # noqa: SLF001
    assert (await revoke(None, token_request, principal, services)).status_code == 200
    await _assert_http_exception(
        revoke(None, token_request, principal, services),
        ServiceUnavailableException,
        status_code=503,
        detail="Authentication service is unavailable.",
    )
    await _assert_http_exception(
        revoke(None, token_request, anonymous, services),
        NotAuthorizedException,
        status_code=401,
        detail="Authentication required.",
    )

    lifecycle = controllers_module._LocalLifecycleController  # noqa: SLF001
    identifier = accounts_module.LocalIdentifierRequest(identifier="user@example.com")
    assert (await cast("Any", lifecycle.recovery.fn)(None, identifier, request, services)).status_code == 202
    reset = cast("Any", lifecycle.reset.fn)
    reset_request = accounts_module.LocalPasswordResetRequest(
        token=token,
        password="new-password",  # noqa: S106 - request DTO fixture
    )
    assert (await reset(None, reset_request, request, services)).status_code == 200
    await _assert_http_exception(
        reset(None, reset_request, request, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )
    assert (await cast("Any", lifecycle.verification.fn)(None, identifier, request, services)).status_code == 202
    confirm = cast("Any", lifecycle.confirm_verification.fn)
    assert (await confirm(None, token_request, request, services)).status_code == 200
    await _assert_http_exception(
        confirm(None, token_request, request, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )

    register = cast("Any", controllers_module._LocalRegistrationController.register.fn)  # noqa: SLF001
    registration = accounts_module.LocalRegistrationRequest(
        identifier="user@example.com",
        password="password",  # noqa: S106 - request DTO fixture
    )
    assert (await register(None, registration, request, services)).status_code == 202
    await _assert_http_exception(
        register(None, registration, request, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )
    services.registration = None
    await _assert_http_exception(
        register(None, registration, request, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )
    services.registration = SimpleNamespace(
        register=AsyncOutcome(accounts_module.LifecycleAccepted(), accounts_module.InvalidInvitation())
    )
    invite_register = cast(
        "Any",
        controllers_module._LocalInvitationRegistrationController.register.fn,  # noqa: SLF001
    )
    invitation = accounts_module.LocalInvitationRegistrationRequest(
        identifier="user@example.com",
        password="password",  # noqa: S106 - request DTO fixture
        invitation_token="invite-secret",  # noqa: S106 - request DTO fixture
    )
    assert (await invite_register(None, invitation, request, services)).status_code == 202
    await _assert_http_exception(
        invite_register(None, invitation, request, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )
    services.registration = None
    await _assert_http_exception(
        invite_register(None, invitation, request, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )

    session_change = cast("Any", controllers_module._LocalSessionPasswordController.change.fn)  # noqa: SLF001
    assert (await session_change(None, password_request, request, principal, services)).status_code == 200
    await _assert_http_exception(
        session_change(None, password_request, request, principal, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )
    await _assert_http_exception(
        session_change(None, password_request, request, anonymous, services),
        NotAuthorizedException,
        status_code=401,
        detail="Authentication required.",
    )
    token_change = cast("Any", controllers_module._LocalTokenPasswordController.change.fn)  # noqa: SLF001
    assert (await token_change(None, password_request, principal, services)).status_code == 200
    await _assert_http_exception(
        token_change(None, password_request, anonymous, services),
        NotAuthorizedException,
        status_code=401,
        detail="Authentication required.",
    )
    token_only_change = cast("Any", controllers_module._LocalTokenOnlyPasswordController.change.fn)  # noqa: SLF001
    await _assert_http_exception(
        token_only_change(None, password_request, principal, services),
        ClientException,
        status_code=400,
        detail="The request is invalid.",
    )
    await _assert_http_exception(
        token_only_change(None, password_request, anonymous, services),
        NotAuthorizedException,
        status_code=401,
        detail="Authentication required.",
    )

    bearer_context = SecurityContext(
        session=NullSessionHandle(), evidence=(AuthenticationEvidence("bearer", "local", _JWT_NOW),)
    )
    controllers_module.requires_local_bearer(cast("Any", SimpleNamespace(auth=bearer_context)), cast("Any", None))
    with pytest.raises(NotAuthorizedException, match="Authentication required"):
        controllers_module.requires_local_bearer(
            cast("Any", SimpleNamespace(auth=SecurityContext(session=NullSessionHandle()))), cast("Any", None)
        )


@pytest.mark.anyio
async def test_local_auth_service_graph_composes_existing_services_without_handler_logic() -> None:
    class AsyncOutcome:
        def __init__(self, *outcomes: object) -> None:
            self.outcomes = list(outcomes)

        async def __call__(self, *_args: object, **_kwargs: object) -> object:
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

    account = accounts_module.LocalAccount(
        account_id="account-1",
        normalized_identifier="user@example.com",
        display_name="User",
        active=True,
        verified=True,
        security_epoch=1,
    )
    proof = accounts_module.PasswordReauthenticationProof(
        account_id="account-1", security_epoch=1, authenticated_at=_JWT_NOW, expires_at=_JWT_NOW + timedelta(minutes=5)
    )
    authentication = SimpleNamespace(account_id="account-1", session_id="session-old")
    plan = SimpleNamespace(prior_session_id="session-old", command=object())
    changed = accounts_module.PasswordChangeResult(accounts_module.PasswordChangeStatus.CHANGED, security_epoch=2)
    refresh_response = accounts_module.RefreshTokenResponse(
        access_token="e30.e30.YQ",  # noqa: S106 - compact public test JWT
        refresh_token=accounts_module
        .RefreshTokenCodec(pepper=b"p" * 32, entropy=_RefreshEntropy())
        .issue()
        .refresh_token,
        expires_in=600,
    )
    session_auth = SimpleNamespace(
        establish=AsyncOutcome(
            VerificationUnavailable(),
            accounts_module.SessionAuthentication(
                session_id="c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M",
                binding_id="sb_aWlpaWlpaWlpaWlpaWlpaQ",
                account_id="account-1",
                security_epoch=1,
                authenticated_at=_JWT_NOW,
                expires_at=_JWT_NOW + timedelta(hours=1),
            ),
        ),
        current_authentication=lambda _request: authentication,
        prepare_password_rebind=lambda _request, _account: plan,
        activate_password_rebind=AsyncOutcome(bool(1)),
        logout=AsyncOutcome(bool(0)),
    )
    accounts = SimpleNamespace(get_by_id=AsyncOutcome(account, OSError(), None))
    services = accounts_module.LocalAuthService(
        accounts=cast("Any", accounts),
        password_login=cast("Any", SimpleNamespace(authenticate=AsyncOutcome(InvalidCredentials(), account, account))),
        password_reauthentication=cast(
            "Any", SimpleNamespace(verify=AsyncOutcome(InvalidCredentials(), proof, proof, proof, proof, proof))
        ),
        password_change=cast("Any", SimpleNamespace(change=AsyncOutcome(changed, changed, changed))),
        verification=cast("Any", object()),
        recovery=cast("Any", object()),
        session_auth=cast("Any", session_auth),
        refresh_tokens=cast("Any", SimpleNamespace(issue=AsyncOutcome(refresh_response))),
    )
    credentials = accounts_module.LocalCredentials(
        identifier="user@example.com",
        password="password",  # noqa: S106 - request DTO fixture
    )
    password_request = accounts_module.LocalPasswordChangeRequest(
        current_password="old",  # noqa: S106 - request DTO fixture
        password="new-password",  # noqa: S106 - request DTO fixture
    )
    request = cast("Any", SimpleNamespace())

    assert isinstance(await services.session_login(request, credentials), InvalidCredentials)
    assert isinstance(await services.session_login(request, credentials), VerificationUnavailable)
    assert isinstance(await services.session_login(request, credentials), accounts_module.LocalAccountResponse)
    no_session = replace(services, session_auth=None)
    no_session.password_login.authenticate.outcomes.append(account)
    assert isinstance(await no_session.session_login(request, credentials), VerificationUnavailable)

    services.password_login.authenticate.outcomes.extend((InvalidCredentials(), account))
    assert isinstance(await services.token_login(request, credentials), InvalidCredentials)
    assert await services.token_login(request, credentials) == refresh_response
    no_refresh = replace(services, refresh_tokens=None)
    no_refresh.password_login.authenticate.outcomes.append(account)
    assert isinstance(await no_refresh.token_login(request, credentials), VerificationUnavailable)

    assert isinstance(
        await services.change_session_password(request, "account-1", password_request), InvalidCredentials
    )
    compromised = accounts_module.LocalPasswordChangeRequest(
        current_password="old",  # noqa: S106 - request DTO fixture
        password="new-password",  # noqa: S106 - request DTO fixture
        compromise=True,
    )
    assert await services.change_session_password(request, "account-1", compromised) == changed
    assert session_auth.logout.outcomes == []
    compromised_failure = replace(
        services,
        password_change=cast("Any", SimpleNamespace(change=AsyncOutcome(accounts_module.InvalidLifecycleRequest()))),
    )
    assert isinstance(
        await compromised_failure.change_session_password(request, "account-1", compromised),
        accounts_module.InvalidLifecycleRequest,
    )
    assert await services.change_session_password(request, "account-1", password_request) == changed
    assert session_auth.activate_password_rebind.outcomes == []
    assert isinstance(
        await services.change_session_password(request, "account-1", password_request), VerificationUnavailable
    )
    assert isinstance(
        await services.change_session_password(request, "account-1", password_request), InvalidCredentials
    )
    assert isinstance(
        await replace(services, session_auth=None).change_session_password(request, "account-1", password_request),
        VerificationUnavailable,
    )

    services.password_reauthentication.verify.outcomes.extend((proof, proof, proof))
    no_authentication = SimpleNamespace(**vars(session_auth))
    no_authentication.current_authentication = lambda _request: None
    assert isinstance(
        await replace(services, session_auth=cast("Any", no_authentication)).change_session_password(
            request, "account-1", password_request
        ),
        InvalidCredentials,
    )

    services.accounts.get_by_id.outcomes.append(account)
    no_plan = SimpleNamespace(**vars(session_auth))
    no_plan.prepare_password_rebind = lambda _request, _account: VerificationUnavailable()
    assert isinstance(
        await replace(services, session_auth=cast("Any", no_plan)).change_session_password(
            request, "account-1", password_request
        ),
        VerificationUnavailable,
    )

    services.accounts.get_by_id.outcomes.append(account)
    unchanged_services = replace(
        services,
        password_change=cast("Any", SimpleNamespace(change=AsyncOutcome(accounts_module.InvalidLifecycleRequest()))),
    )
    assert isinstance(
        await unchanged_services.change_session_password(request, "account-1", password_request),
        accounts_module.InvalidLifecycleRequest,
    )

    services.password_reauthentication.verify.outcomes.extend((InvalidCredentials(), proof))
    assert isinstance(await services.change_token_password("account-1", password_request), InvalidCredentials)
    assert await services.change_token_password("account-1", password_request) == changed


def test_refresh_codec_rejects_runtime_non_text_token() -> None:
    codec = accounts_module.RefreshTokenCodec(pepper=b"p" * 32)
    assert isinstance(codec.verify(object()), InvalidCredentials)  # type: ignore[arg-type]


class _CollectingSink:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def emit(self, event: Any) -> None:
        self.events.append(event)


class _FailingSink:
    async def emit(self, event: Any) -> None:
        del event
        msg = "sink down"
        raise RuntimeError(msg)


class _ScriptedLimiter:
    def __init__(self, *decisions: object) -> None:
        self.decisions = list(decisions)
        self.requests: list[Any] = []

    async def acquire(self, request: Any) -> Any:
        self.requests.append(request)
        return self.decisions.pop(0) if len(self.decisions) > 1 else self.decisions[0]


class _RaisingLimiter:
    async def acquire(self, request: Any) -> Any:
        del request
        msg = "limiter down"
        raise RuntimeError(msg)


def _guard(limiter: object, **kwargs: Any) -> Any:
    kwargs.setdefault("pepper", b"p" * 32)
    return accounts_module.RateLimitGuard(limiter=cast("Any", limiter), **kwargs)


def _memory_limiter(**kwargs: Any) -> Any:
    return accounts_module.StoreRateLimiter(store=MemoryStore(), **kwargs)


@pytest.mark.parametrize(
    ("limit", "window"),
    [
        (0, timedelta(minutes=1)),
        (True, timedelta(minutes=1)),
        (10_000_000, timedelta(minutes=1)),
        (10, timedelta(0)),
        (10, timedelta(days=2)),
        (10, timedelta(seconds=1, microseconds=1)),
        (10, cast("Any", 60)),
    ],
)
def test_rate_limit_policy_rejects_unbounded_budgets(limit: object, window: object) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        accounts_module.RateLimitPolicy(limit=cast("Any", limit), window=cast("Any", window))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"operation": " "},
        {"operation": "local.login", "client_key": " "},
        {"operation": "local.login", "subject_digest": "x" * 513},
        {"operation": "local.login", "cost": 0},
        {"operation": "local.login", "cost": True},
    ],
)
def test_rate_limit_request_rejects_unbounded_bucket_keys(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="Rate limit"):
        accounts_module.RateLimitRequest(**kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"allowed": cast("Any", 1)},
        {"allowed": False, "retry_after": 0},
        {"allowed": False, "retry_after": cast("Any", "5")},
        {"allowed": True, "retry_after": 5},
    ],
)
def test_rate_limit_decision_requires_a_retry_hint_only_on_denial(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"(?i)rate limit"):
        accounts_module.RateLimitDecision(**kwargs)


@pytest.mark.anyio
async def test_unlimited_rate_limiter_allows_every_attempt() -> None:
    decision = await accounts_module.UnlimitedRateLimiter().acquire(
        accounts_module.RateLimitRequest(operation="local.login")
    )
    assert decision == accounts_module.RateLimitDecision(allowed=True)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"store_name": " "},
        {"store": cast("Any", object())},
        {"clock": cast("Any", object())},
        {"policies": {" ": accounts_module.RateLimitPolicy(limit=1, window=timedelta(minutes=1))}},
        {"policies": {"local.login": cast("Any", object())}},
    ],
)
def test_store_rate_limiter_validates_its_configuration(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        accounts_module.StoreRateLimiter(**kwargs)


def test_store_rate_limiter_binds_only_a_native_store() -> None:
    limiter = accounts_module.StoreRateLimiter()
    with pytest.raises(ImproperlyConfiguredException):
        limiter.bind(cast("Any", object()))
    assert limiter.store is None


@pytest.mark.anyio
async def test_store_rate_limiter_allows_unconfigured_operations_and_fails_closed_without_a_store() -> None:
    limiter = _memory_limiter()
    assert await limiter.acquire(accounts_module.RateLimitRequest(operation="local.unbudgeted")) == (
        accounts_module.RateLimitDecision(allowed=True)
    )
    unbound = accounts_module.StoreRateLimiter()
    with pytest.raises(RuntimeError, match="store has not been resolved"):
        await unbound.acquire(accounts_module.RateLimitRequest(operation="local.login", client_key="1.1.1.1"))


@pytest.mark.anyio
async def test_store_rate_limiter_denies_after_the_window_budget_and_recovers_next_window() -> None:
    moment = [datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)]
    limiter = _memory_limiter(clock=lambda: moment[0])
    request = accounts_module.RateLimitRequest(operation="local.login", client_key="1.1.1.1")
    decisions = [await limiter.acquire(request) for _ in range(11)]

    assert [decision.allowed for decision in decisions] == [True] * 10 + [False]
    assert decisions[-1].retry_after == 300

    moment[0] = moment[0] + timedelta(minutes=5)
    assert (await limiter.acquire(request)).allowed


@pytest.mark.anyio
async def test_store_rate_limiter_budgets_password_verify_by_default() -> None:
    limiter = _memory_limiter()
    request = accounts_module.RateLimitRequest(operation="local.password.verify", client_key="1.1.1.1")
    decisions = [await limiter.acquire(request) for _ in range(11)]

    assert [decision.allowed for decision in decisions] == [True] * 10 + [False]


@pytest.mark.anyio
async def test_store_rate_limiter_fails_closed_on_an_unreadable_counter() -> None:
    store = MemoryStore()
    limiter = accounts_module.StoreRateLimiter(store=store)
    request = accounts_module.RateLimitRequest(operation="local.login", client_key="1.1.1.1")
    await limiter.acquire(request)
    key = next(iter(store._store))  # noqa: SLF001 - assert the stored counter shape directly
    await store.set(key, b"not-a-number")

    with pytest.raises(RuntimeError, match="counter is unreadable"):
        await limiter.acquire(request)


@pytest.mark.anyio
async def test_store_rate_limiter_denies_when_either_bucket_is_exhausted() -> None:
    limiter = _memory_limiter()
    for _ in range(10):
        await limiter.acquire(accounts_module.RateLimitRequest(operation="local.login", client_key="shared"))

    fresh_subject = accounts_module.RateLimitRequest(
        operation="local.login", client_key="shared", subject_digest="unused-digest"
    )
    decision = await limiter.acquire(fresh_subject)

    assert not decision.allowed


@pytest.mark.parametrize(
    "kwargs",
    [
        {"limiter": cast("Any", object())},
        {"pepper": b"short"},
        {"events": cast("Any", object())},
        {"clock": cast("Any", object())},
        {"event_ids": cast("Any", object())},
    ],
)
def test_rate_limit_guard_validates_its_ports(kwargs: dict[str, Any]) -> None:
    base: dict[str, Any] = {"limiter": accounts_module.UnlimitedRateLimiter(), "pepper": b"p" * 32}
    with pytest.raises(ImproperlyConfiguredException):
        accounts_module.RateLimitGuard(**{**base, **kwargs})


def test_rate_limit_guard_digests_never_carry_the_identifier() -> None:
    guard = _guard(accounts_module.UnlimitedRateLimiter())

    digest = guard.subject_digest("user@example.com")

    assert "user@example.com" not in digest
    assert digest == guard.subject_digest("user@example.com")
    assert digest != guard.subject_digest("other@example.com")
    assert digest != _guard(accounts_module.UnlimitedRateLimiter(), pepper=b"q" * 32).subject_digest("user@example.com")


@pytest.mark.anyio
@pytest.mark.parametrize("limiter", [_RaisingLimiter(), _ScriptedLimiter(cast("Any", object()))])
async def test_rate_limit_guard_fails_closed_when_the_limiter_is_unusable(limiter: object) -> None:
    outcome = await _guard(limiter).check("local.login", client_key="1.1.1.1")

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.anyio
async def test_rate_limit_guard_reports_denials_and_emits_one_account_free_event() -> None:
    sink = _CollectingSink()
    guard = _guard(
        _ScriptedLimiter(accounts_module.RateLimitDecision(allowed=False, retry_after=42)),
        events=sink,
        event_ids=lambda: "event-1",
    )

    outcome = await guard.check("local.login", client_key="1.1.1.1", identifier="user@example.com")

    assert outcome == accounts_module.RateLimited(retry_after=42)
    assert [(event.operation, event.outcome, event.account_id) for event in sink.events] == [
        ("local.login", "rate_limited", None)
    ]


@pytest.mark.anyio
async def test_rate_limit_guard_allows_and_passes_a_digested_subject() -> None:
    limiter = _ScriptedLimiter(accounts_module.RateLimitDecision(allowed=True))
    guard = _guard(limiter)

    assert await guard.check("local.login", client_key="1.1.1.1", identifier="user@example.com") is None
    assert limiter.requests[0].subject_digest == guard.subject_digest("user@example.com")
    assert limiter.requests[0].client_key == "1.1.1.1"


@pytest.mark.anyio
async def test_rate_limit_guard_logs_unbuildable_denial_events_without_changing_the_denial(
    caplog: pytest.LogCaptureFixture,
) -> None:
    guard = _guard(
        _ScriptedLimiter(accounts_module.RateLimitDecision(allowed=False, retry_after=1)),
        clock=cast("Any", lambda: None),
    )

    outcome = await guard.check("local.login", client_key="1.1.1.1")

    assert outcome == accounts_module.RateLimited(retry_after=1)
    assert "Rate limit event could not be built" in caplog.text


@pytest.mark.anyio
async def test_rate_limit_guard_survives_a_failing_denial_sink(caplog: pytest.LogCaptureFixture) -> None:
    guard = _guard(
        _ScriptedLimiter(accounts_module.RateLimitDecision(allowed=False, retry_after=1)), events=_FailingSink()
    )

    outcome = await guard.check("local.login", client_key="1.1.1.1")

    assert outcome == accounts_module.RateLimited(retry_after=1)
    assert "Security event sink failed for local.login" in caplog.text


def test_validate_rate_limits_rejects_a_foreign_guard() -> None:
    rate_limits_module.validate_rate_limits(None, name="Service")
    with pytest.raises(ImproperlyConfiguredException, match="Service rate limits"):
        rate_limits_module.validate_rate_limits(object(), name="Service")


def _raising_normalizer(_identifier: str) -> str:
    msg = "normalizer down"
    raise RuntimeError(msg)


def _denying_guard(**kwargs: Any) -> Any:
    return _guard(_ScriptedLimiter(accounts_module.RateLimitDecision(allowed=False, retry_after=7)), **kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"rate_limits": cast("Any", object())},
        {"events": cast("Any", object())},
        {"clock": cast("Any", object())},
        {"event_ids": cast("Any", object())},
    ],
)
def test_password_login_service_validates_limiting_and_audit_ports(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        accounts_module.PasswordLoginService(
            accounts=_LocalAccessStore(_local_access_account()), hasher=_PasswordHasher(), **kwargs
        )


@pytest.mark.anyio
async def test_password_login_is_limited_before_any_password_work() -> None:
    hasher = _PasswordHasher()
    service = accounts_module.PasswordLoginService(
        accounts=_LocalAccessStore(_local_access_account()), hasher=hasher, rate_limits=_denying_guard()
    )

    outcome = await service.authenticate("user@example.com", "secret", client_key="1.1.1.1", now=_JWT_NOW)

    assert outcome == accounts_module.RateLimited(retry_after=7)
    assert hasher.calls == []


@pytest.mark.anyio
async def test_password_login_still_consumes_a_budget_for_an_unnormalizable_identifier() -> None:
    limiter = _ScriptedLimiter(accounts_module.RateLimitDecision(allowed=True))
    service = accounts_module.PasswordLoginService(
        accounts=_LocalAccessStore(_local_access_account()),
        hasher=_PasswordHasher(),
        normalizer=cast("Any", _raising_normalizer),
        rate_limits=_guard(limiter),
    )

    outcome = await service.authenticate("user@example.com", "secret", client_key="1.1.1.1", now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable)
    assert limiter.requests[0].subject_digest is None
    assert limiter.requests[0].client_key == "1.1.1.1"


@pytest.mark.anyio
async def test_password_login_logs_unbuildable_decision_events_without_changing_the_decision(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = accounts_module.PasswordLoginService(
        accounts=_LocalAccessStore(None), hasher=_PasswordHasher(), clock=cast("Any", lambda: None)
    )

    outcome = await service.authenticate("missing@example.com", "secret", now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert "Security event could not be built for local.login" in caplog.text


@pytest.mark.anyio
async def test_password_login_emits_one_decision_event_per_outcome() -> None:
    sink = _CollectingSink()
    service = accounts_module.PasswordLoginService(
        accounts=_LocalAccessStore(_local_access_account()),
        hasher=_PasswordHasher(
            accounts_module.PasswordVerificationResult(accounts_module.PasswordVerificationStatus.VERIFIED)
        ),
        events=sink,
        event_ids=lambda: "event-1",
    )
    denied = accounts_module.PasswordLoginService(
        accounts=_LocalAccessStore(None), hasher=_PasswordHasher(), events=sink, event_ids=lambda: "event-2"
    )

    await service.authenticate("user@example.com", "correct horse battery staple", now=_JWT_NOW)
    await denied.authenticate("missing@example.com", "correct horse battery staple", now=_JWT_NOW)

    assert [event.outcome for event in sink.events] == ["verified", "attempted"]


@pytest.mark.anyio
async def test_registration_is_limited_before_hashing() -> None:
    hasher = _PasswordHasher()
    service = accounts_module.RegistrationService(
        accounts=_LifecycleStore(),
        hasher=hasher,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        registration=accounts_module.RegistrationPolicy.public(),
        rate_limits=_denying_guard(),
    )

    outcome = await service.register("user@example.com", "correct horse battery staple", now=_JWT_NOW)

    assert outcome == accounts_module.RateLimited(retry_after=7)
    assert hasher.hash_calls == []


@pytest.mark.anyio
async def test_verification_resend_is_limited_and_reports_a_denial() -> None:
    store = _LifecycleStore()
    service = accounts_module.VerificationTokenService(
        accounts=store,
        store=store,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        rate_limits=_denying_guard(),
    )

    assert await service.resend("user@example.com", now=_JWT_NOW) == accounts_module.RateLimited(retry_after=7)


@pytest.mark.anyio
async def test_verification_resend_consumes_a_budget_for_an_unnormalizable_identifier() -> None:
    limiter = _ScriptedLimiter(accounts_module.RateLimitDecision(allowed=True))
    store = _LifecycleStore()
    service = accounts_module.VerificationTokenService(
        accounts=store,
        store=store,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        normalizer=cast("Any", _raising_normalizer),
        rate_limits=_guard(limiter),
    )

    assert isinstance(await service.resend("user@example.com", now=_JWT_NOW), accounts_module.LifecycleAccepted)
    assert limiter.requests[0].subject_digest is None


@pytest.mark.anyio
@pytest.mark.parametrize("family", ["verification", "recovery"])
async def test_uniform_durable_write_cost_for_present_and_absent_identifiers(family: str) -> None:
    counts: dict[str, int] = {}
    for name, account in (("present", _lifecycle_account()), ("absent", None)):
        store = _LifecycleStore(account=account)
        codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
        if family == "verification":
            outcome = await accounts_module.VerificationTokenService(accounts=store, store=store, tokens=codec).resend(
                "user@example.com", now=_JWT_NOW
            )
        else:
            outcome = await accounts_module.RecoveryTokenService(
                accounts=store, store=store, tokens=codec, hasher=_PasswordHasher()
            ).request("user@example.com", now=_JWT_NOW)
        assert isinstance(outcome, accounts_module.LifecycleAccepted)
        counts[name] = len(store.issues) + len(store.absent_probes)

    assert counts["present"] == counts["absent"] == 1


@pytest.mark.anyio
async def test_verification_consume_buckets_only_the_client_never_the_token() -> None:
    limiter = _ScriptedLimiter(accounts_module.RateLimitDecision(allowed=False, retry_after=7))
    store = _LifecycleStore()
    service = accounts_module.VerificationTokenService(
        accounts=store,
        store=store,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        rate_limits=_guard(limiter),
    )

    outcome = await service.consume("vt_token.secret", client_key="1.1.1.1", now=_JWT_NOW)

    assert outcome == accounts_module.RateLimited(retry_after=7)
    assert store.consumptions == []
    assert limiter.requests[0].operation == "local.verification.consume"
    assert limiter.requests[0].client_key == "1.1.1.1"
    assert limiter.requests[0].subject_digest is None


@pytest.mark.anyio
async def test_generated_verification_confirm_reports_denials_with_the_client_bucket() -> None:
    captured: dict[str, object] = {}

    async def consume(token: object, *, client_key: str | None = None) -> object:
        del token
        captured["client_key"] = client_key
        return accounts_module.RateLimited(retry_after=7)

    services = cast(
        "Any",
        SimpleNamespace(verification=SimpleNamespace(consume=consume), client_key_for=lambda _connection: "1.1.1.1"),
    )
    handler = cast("Any", controllers_module._LocalLifecycleController.confirm_verification.fn)  # noqa: SLF001

    error = await _assert_http_exception(
        handler(
            None,
            accounts_module.LocalTokenRequest(token="vt_token.secret"),  # noqa: S106 - deterministic fixture token
            cast("Any", SimpleNamespace()),
            services,
        ),
        TooManyRequestsException,
        status_code=429,
        detail="Too many requests.",
    )

    assert error.headers["Retry-After"] == "7"
    assert captured["client_key"] == "1.1.1.1"


@pytest.mark.anyio
async def test_recovery_request_and_reset_are_limited() -> None:
    store = _LifecycleStore()
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
    service = accounts_module.RecoveryTokenService(
        accounts=store, store=store, tokens=codec, hasher=_PasswordHasher(), rate_limits=_denying_guard()
    )

    assert await service.request("user@example.com", now=_JWT_NOW) == accounts_module.RateLimited(retry_after=7)
    reset = await service.reset("rc_token.secret", "correct horse battery staple", now=_JWT_NOW)
    assert reset == accounts_module.RateLimited(retry_after=7)


@pytest.mark.anyio
async def test_recovery_request_consumes_a_budget_for_an_unnormalizable_identifier() -> None:
    limiter = _ScriptedLimiter(accounts_module.RateLimitDecision(allowed=True))
    store = _LifecycleStore()
    service = accounts_module.RecoveryTokenService(
        accounts=store,
        store=store,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        hasher=_PasswordHasher(),
        normalizer=cast("Any", _raising_normalizer),
        rate_limits=_guard(limiter),
    )

    assert isinstance(await service.request("user@example.com", now=_JWT_NOW), accounts_module.LifecycleAccepted)
    assert limiter.requests[0].subject_digest is None


@pytest.mark.anyio
async def test_recovery_reset_buckets_only_the_client_never_the_token() -> None:
    limiter = _ScriptedLimiter(accounts_module.RateLimitDecision(allowed=True))
    store = _LifecycleStore()
    service = accounts_module.RecoveryTokenService(
        accounts=store,
        store=store,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        hasher=_PasswordHasher(),
        rate_limits=_guard(limiter),
    )

    await service.reset("rc_token.secret", "correct horse battery staple", client_key="1.1.1.1", now=_JWT_NOW)

    assert limiter.requests[0].subject_digest is None
    assert limiter.requests[0].client_key == "1.1.1.1"


@pytest.mark.anyio
async def test_password_login_emits_an_attempt_event_for_a_known_account_with_a_wrong_password() -> None:
    sink = _CollectingSink()
    service = accounts_module.PasswordLoginService(
        accounts=_LocalAccessStore(_local_access_account()),
        hasher=_PasswordHasher(
            accounts_module.PasswordVerificationResult(accounts_module.PasswordVerificationStatus.INVALID)
        ),
        events=sink,
        event_ids=lambda: "event-1",
    )

    outcome = await service.authenticate("user@example.com", "wrong", now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert [(event.outcome, event.account_id) for event in sink.events] == [("attempted", "account-1")]


@pytest.mark.anyio
async def test_refresh_rotation_is_limited_by_client_only() -> None:
    limiter = _ScriptedLimiter(accounts_module.RateLimitDecision(allowed=False, retry_after=7))
    service, _store, _accounts, _account = _refresh_service()
    limited = replace(service, rate_limits=_guard(limiter))

    outcome = await limited.rotate("rt_token.secret", client_key="1.1.1.1", now=_JWT_NOW)

    assert outcome == accounts_module.RateLimited(retry_after=7)
    assert limiter.requests[0].subject_digest is None
    assert limiter.requests[0].operation == "local.refresh.rotate"


def test_route_errors_map_denials_to_429_with_a_retry_hint() -> None:
    with pytest.raises(TooManyRequestsException) as limited_info:
        controllers_module._route_error(accounts_module.RateLimited(retry_after=42))  # noqa: SLF001
    with pytest.raises(TooManyRequestsException) as unhinted_info:
        controllers_module._route_error(accounts_module.RateLimited())  # noqa: SLF001

    assert limited_info.value.status_code == 429
    assert limited_info.value.detail == "Too many requests."
    assert limited_info.value.headers["Retry-After"] == "42"
    assert unhinted_info.value.status_code == 429
    assert unhinted_info.value.detail == "Too many requests."
    assert not unhinted_info.value.headers or "Retry-After" not in unhinted_info.value.headers


@pytest.mark.anyio
@pytest.mark.parametrize("handler_name", ["recovery", "verification"])
async def test_generated_lifecycle_handlers_report_denials_instead_of_the_shared_accepted_response(
    handler_name: str,
) -> None:
    limited = accounts_module.RateLimited(retry_after=7)

    async def deny(*_args: object, **_kwargs: object) -> object:
        return limited

    services = cast(
        "Any",
        SimpleNamespace(
            recovery=SimpleNamespace(request=deny),
            verification=SimpleNamespace(resend=deny),
            client_key_for=lambda _connection: "1.1.1.1",
        ),
    )
    handler = cast("Any", getattr(controllers_module._LocalLifecycleController, handler_name).fn)  # noqa: SLF001
    identifier = accounts_module.LocalIdentifierRequest(identifier="user@example.com")

    error = await _assert_http_exception(
        handler(None, identifier, cast("Any", SimpleNamespace()), services),
        TooManyRequestsException,
        status_code=429,
        detail="Too many requests.",
    )

    assert error.headers["Retry-After"] == "7"
