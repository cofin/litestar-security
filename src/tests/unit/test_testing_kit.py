"""Unit tests for the framework-neutral public testing kit."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone

import pytest
from anyio import Event, create_task_group, fail_after

import litestar_security.testing as testing_module
from litestar_security.accounts import AESGCMSecretProtector, SecretProtectorKey
from litestar_security.providers.api_key import APIKeyState, APIKeyStore
from litestar_security.providers.oauth import (
    AESGCMOAuthTransactionProtector,
    MemoryOAuthAccountStore,
    MemoryOAuthTransactionStore,
    OAuthTransaction,
    OAuthTransactionProtectorKey,
    OIDCLogoutIdentity,
    ProtectedOAuthSecret,
    UnlinkOutcome,
    UnlinkStatus,
)
from litestar_security.testing import (
    FakeClock,
    InMemorySecurityBackend,
    InMemoryWebSocketConnectTokenStore,
    StoreConformanceFactories,
    _single_winner,  # pyright: ignore[reportPrivateUsage] - T1 verifies the private contender harness directly
    assert_api_key_store_conformance,
    assert_oauth_account_store_conformance,
    assert_oauth_transaction_protector_conformance,
    assert_oauth_transaction_store_conformance,
    assert_oidc_session_logout_store_conformance,
    assert_security_backend_conformance,
    assert_websocket_connect_token_store_conformance,
)
from litestar_security.websocket import WebSocketConnectAuthorization

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


@dataclass
class _YieldingConnectTokenStore:
    """Deliberately non-atomic consume implementation for the conformance self-test."""

    records: dict[str, WebSocketConnectAuthorization] = field(default_factory=dict[str, WebSocketConnectAuthorization])
    release: Event = field(default_factory=Event)
    starters: int = 0
    first_record_id: str | None = None

    async def create(self, record: WebSocketConnectAuthorization) -> None:
        if self.first_record_id is None:
            self.first_record_id = record.connect_token_id
        self.records[record.connect_token_id] = record

    async def consume(
        self, *, connect_token_id: str, digest: bytes, now: datetime
    ) -> WebSocketConnectAuthorization | None:
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
    ) -> WebSocketConnectAuthorization | None:
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
    ) -> WebSocketConnectAuthorization | None:
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


class _BrokenOAuthAccountStore(MemoryOAuthAccountStore):
    """Report the final identity as removable without changing the underlying link."""

    async def unlink(
        self, account_id: str, provider: str, provider_account_id: str, *, require_remaining: bool, now: datetime
    ) -> UnlinkOutcome:
        result = await super().unlink(
            account_id, provider, provider_account_id, require_remaining=require_remaining, now=now
        )
        if result.status is UnlinkStatus.FINAL_METHOD:
            return UnlinkOutcome(UnlinkStatus.UNLINKED, provider_account_id)
        return result


class _BrokenOAuthOwnershipStore(MemoryOAuthAccountStore):
    """Claim another account owns a provider link."""

    async def unlink(
        self, account_id: str, provider: str, provider_account_id: str, *, require_remaining: bool, now: datetime
    ) -> UnlinkOutcome:
        result = await super().unlink(
            account_id, provider, provider_account_id, require_remaining=require_remaining, now=now
        )
        return UnlinkOutcome(UnlinkStatus.UNLINKED, provider_account_id) if account_id == "other-account" else result


class _BrokenOAuthPreservationStore(MemoryOAuthAccountStore):
    """Delete a final provider link while reporting final-method protection."""

    async def unlink(
        self, account_id: str, provider: str, provider_account_id: str, *, require_remaining: bool, now: datetime
    ) -> UnlinkOutcome:
        result = await super().unlink(
            account_id, provider, provider_account_id, require_remaining=require_remaining, now=now
        )
        if result.status is UnlinkStatus.FINAL_METHOD:
            linked = self._links.pop(provider_account_id)  # pyright: ignore[reportPrivateUsage] - deliberately violates preservation
            del self._identity_index[(linked.provider, linked.issuer, linked.subject)]  # pyright: ignore[reportPrivateUsage] - deliberately violates preservation
        return result


class _BrokenOAuthAtomicUnlinkStore(MemoryOAuthAccountStore):
    """Report every post-unlink contender as a winner."""

    async def unlink(
        self, account_id: str, provider: str, provider_account_id: str, *, require_remaining: bool, now: datetime
    ) -> UnlinkOutcome:
        result = await super().unlink(
            account_id, provider, provider_account_id, require_remaining=require_remaining, now=now
        )
        if account_id == "conformance-account" and result.status is UnlinkStatus.NOT_FOUND:
            return UnlinkOutcome(UnlinkStatus.UNLINKED, provider_account_id)
        return result


@dataclass
class _ControlledStore:
    records: dict[str, APIKeyState]
    persist_successor: bool = True
    revoke_current: bool = True
    rotated: bool = False

    async def get(self, key_id: str) -> APIKeyState | None:
        return self.records.get(key_id)

    async def create(self, record: APIKeyState) -> None:
        self.records[record.key_id] = record

    async def rotate(
        self, *, current_key_id: str, replacement: APIKeyState, overlap_until: datetime | None, now: datetime
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


async def test_api_key_conformance_names_a_non_atomic_rotation_invariant() -> None:
    @dataclass
    class BrokenStore:
        records: dict[str, APIKeyState]

        async def get(self, key_id: str) -> APIKeyState | None:
            return self.records.get(key_id)

        async def create(self, record: APIKeyState) -> None:
            self.records[record.key_id] = record

        async def rotate(
            self, *, current_key_id: str, replacement: APIKeyState, overlap_until: datetime | None, now: datetime
        ) -> None:
            del current_key_id, overlap_until, now
            self.records[replacement.key_id] = replacement

        async def revoke(self, *, key_id: str, now: datetime) -> None:
            del now
            self.records.pop(key_id, None)

    with pytest.raises(AssertionError, match=r"APIKeyStore\.rotate.*one atomic winner"):
        await assert_api_key_store_conformance(lambda: BrokenStore({}))


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


async def test_oauth_account_conformance_rejects_final_identity_removal() -> None:
    with pytest.raises(AssertionError, match="final-method invariant"):
        await assert_oauth_account_store_conformance(_BrokenOAuthAccountStore)


@pytest.mark.parametrize(
    ("store", "invariant"),
    [
        (_BrokenOAuthOwnershipStore, r"ownership invariant"),
        (_BrokenOAuthPreservationStore, r"ownership preservation invariant"),
        (_BrokenOAuthAtomicUnlinkStore, r"unlink atomicity invariant"),
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
        "webauthn_challenge_store",
        "websocket_connect_token_store",
    ]


async def test_aggregate_backend_logout_store_uses_the_injected_clock() -> None:
    clock = FakeClock(_CONFORMANCE_NOW)
    backend = InMemorySecurityBackend(clock=clock)
    identity = OIDCLogoutIdentity(
        provider="provider",
        issuer="https://issuer.example",
        subject="subject",
        session_id="session",
        token_id="expiring-logout-token",  # noqa: S106 - public replay identifier, not a secret
        expires_at=_CONFORMANCE_NOW + timedelta(seconds=1),
    )

    clock.advance(timedelta(seconds=2))

    assert await backend.oidc_session_logout.consume_backchannel(identity, now=_CONFORMANCE_NOW) is None


async def test_reference_stores_cover_unique_successful_conformance_paths() -> None:
    await assert_websocket_connect_token_store_conformance(InMemoryWebSocketConnectTokenStore)
    await assert_oauth_account_store_conformance(MemoryOAuthAccountStore)
    await assert_oauth_transaction_store_conformance(
        lambda: MemoryOAuthTransactionStore(protector=_ConformanceTransactionProtector())
    )


async def test_websocket_connect_token_conformance_detects_yielding_double_consume() -> None:
    with pytest.raises(AssertionError, match="atomicity invariant"):
        await assert_websocket_connect_token_store_conformance(_YieldingConnectTokenStore)


async def test_conformance_detects_shared_factory_state() -> None:
    shared = _ControlledStore({})

    with pytest.raises(AssertionError, match="factory invariant"):
        await assert_api_key_store_conformance(lambda: shared)


async def test_conformance_detects_non_isolated_factory_storage() -> None:
    shared_records: dict[str, APIKeyState] = {}

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


async def test_aggregate_backend_conformance_invokes_seed_account_hook() -> None:
    seeded: list[str] = []

    async def seed(account_id: str) -> None:
        seeded.append(account_id)

    await assert_security_backend_conformance(StoreConformanceFactories(), seed_account=seed)
    assert seeded == ["conformance-subject", "conformance-session-owner", "account-1"]


async def test_aggregate_backend_conformance_accepts_custom_identifier_factory() -> None:
    def custom_identifiers(prefix: str | None, marker: int) -> str:
        return f"{prefix or ''}custom-uuid-{marker}"

    await assert_security_backend_conformance(StoreConformanceFactories(), identifiers=custom_identifiers)
