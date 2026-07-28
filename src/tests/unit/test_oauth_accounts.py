import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.providers import oauth as oauth_module
from litestar_security.providers.oauth import (
    AccountLinkError,
    InvalidProviderGrantError,
    LinkedProviderAccount,
    MemoryOAuthAccountStore,
    MemoryTokenVault,
    OAuthAccountError,
    OAuthAccountService,
    OAuthAccountStore,
    OAuthLinkProof,
    OAuthLoginResolution,
    OAuthOperation,
    OAuthRevocationFailure,
    OAuthTransaction,
    OAuthTransactionStart,
    ProtectedOAuthSecret,
    ProviderGrant,
    ProviderIdentity,
    ProviderTokenReference,
    ProviderTokenSet,
    SecretStr,
    StoredProviderTokens,
    TokenVault,
    UnlinkResult,
    UnlinkStatus,
)
from litestar_security.testing import FakeOAuthHTTPTransport, FakeOAuthProvider

NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)


@dataclass
class ReversingProtector:
    active_key_version: str = "v1"
    last_plaintext: bytes | None = None
    last_ciphertext: bytes | None = None
    associated_data: bytes | None = None

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedOAuthSecret:
        self.last_plaintext = secret
        self.last_ciphertext = secret[::-1]
        self.associated_data = associated_data
        return ProtectedOAuthSecret(ciphertext=secret[::-1], key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedOAuthSecret, *, associated_data: bytes) -> bytes:
        assert associated_data == self.associated_data
        return protected.ciphertext[::-1]


@dataclass
class FaultProtector:
    active_key_version: str = "v1"
    decoded: bytes | None = None
    fail_protect: bool = False

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedOAuthSecret:
        del associated_data
        if self.fail_protect:
            raise RuntimeError
        return ProtectedOAuthSecret(ciphertext=secret, key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedOAuthSecret, *, associated_data: bytes) -> bytes:
        del protected, associated_data
        return self.decoded if self.decoded is not None else b"not-json"


class RefreshRaceVault:
    def __init__(self, *, second_missing: bool) -> None:
        self.second_missing = second_missing
        self.reads = 0
        self.stored = StoredProviderTokens(
            reference=ProviderTokenReference("provider-account", 1, frozenset({"profile"}), NOW), tokens=tokens()
        )

    async def put(self, provider_account_id: str, value: ProviderTokenSet, *, now: datetime) -> ProviderTokenReference:
        del provider_account_id, value, now
        return self.stored.reference

    async def get_for_refresh(self, provider_account_id: str, *, now: datetime) -> StoredProviderTokens | None:
        del provider_account_id, now
        self.reads += 1
        return None if self.second_missing and self.reads == 2 else self.stored

    async def replace(
        self, provider_account_id: str, *, expected_version: int, tokens: ProviderTokenSet, now: datetime
    ) -> bool:
        del provider_account_id, expected_version, tokens, now
        return False

    async def delete(self, provider_account_id: str) -> None:
        del provider_account_id


class RevocationRetries:
    def __init__(self) -> None:
        self.scheduled: list[tuple[OAuthRevocationFailure, ProviderTokenSet]] = []

    async def schedule(self, failure: OAuthRevocationFailure, value: ProviderTokenSet) -> None:
        self.scheduled.append((failure, value))


class BrokenRevocationRetries:
    async def schedule(self, failure: OAuthRevocationFailure, value: ProviderTokenSet) -> None:
        del failure, value
        raise RuntimeError


def identity(*, subject: str = "subject") -> ProviderIdentity:
    return ProviderIdentity(
        provider="example",
        issuer="https://issuer.example",
        subject=subject,
        display_name="User",
        email="user@example.com",
        email_verified=True,
        raw_claims={"sub": subject},
    )


def grant(*scopes: str) -> ProviderGrant:
    return ProviderGrant(scopes=frozenset(scopes or {"profile"}), expires_at=NOW + timedelta(hours=1))


def tokens(*, access: str = "access", refresh: str | None = "refresh") -> ProviderTokenSet:
    return ProviderTokenSet(
        access_token=SecretStr(access),
        token_type="Bearer",  # noqa: S106 - standardized OAuth token type, not a credential
        scopes=frozenset({"profile"}),
        expires_at=NOW + timedelta(hours=1),
        refresh_token=SecretStr(refresh) if refresh is not None else None,
    )


def proof(purpose: str, **overrides: object) -> OAuthLinkProof:
    values: dict[str, object] = {
        "account_id": "account-1",
        "purpose": purpose,
        "security_epoch": 2,
        "transaction_account_id": "account-1",
        "transaction_security_epoch": 2,
        "consumed": True,
    }
    values.update(overrides)
    return OAuthLinkProof(**values)  # type: ignore[arg-type]


def transaction() -> OAuthTransaction:
    return OAuthTransaction(
        state_digest=b"s" * 32,
        binding_digest=b"b" * 32,
        operation=OAuthOperation.LOGIN,
        provider="example",
        expected_issuer="https://issuer.example",
        redirect_uri="https://app.example/callback",
        return_to="/",
        requested_scopes=frozenset({"profile"}),
        pkce_verifier=SecretStr("v" * 43),
        nonce=None,
        expires_at=NOW + timedelta(minutes=10),
    )


def test_oauth_account_lifecycle_public_contracts_import() -> None:
    assert OAuthAccountStore.__name__ == "OAuthAccountStore"
    assert TokenVault.__name__ == "TokenVault"
    assert OAuthAccountService.__name__ == "OAuthAccountService"
    assert OAuthLinkProof.__name__ == "OAuthLinkProof"
    assert OAuthLoginResolution.__name__ == "OAuthLoginResolution"
    assert LinkedProviderAccount.__name__ == "LinkedProviderAccount"
    assert UnlinkResult.__name__ == "UnlinkResult"
    assert ProviderTokenReference.__name__ == "ProviderTokenReference"
    assert MemoryOAuthAccountStore.__name__ == "MemoryOAuthAccountStore"
    assert MemoryTokenVault.__name__ == "MemoryTokenVault"
    with pytest.raises(AttributeError, match="has no attribute"):
        getattr(oauth_module, "missing")  # noqa: B009 - explicitly exercise the module lazy-export hook


@pytest.mark.parametrize(
    "factory",
    [
        lambda: LinkedProviderAccount("", "account", "provider", "issuer", "subject", grant(), NOW),
        lambda: UnlinkResult(UnlinkStatus.UNLINKED),
        lambda: ProviderTokenReference("", 0, frozenset(), NOW),
    ],
)
def test_oauth_account_value_objects_reject_invalid_direct_construction(factory: Callable[[], object]) -> None:
    with pytest.raises(ValueError, match="invalid"):
        factory()


@pytest.mark.parametrize("counts", [{"": 1}, {"account": -1}, {"account": True}])
def test_memory_account_store_rejects_invalid_method_counts(counts: dict[str, int]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="login method counts"):
        MemoryOAuthAccountStore(login_method_counts=counts)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"provider": "", "client_id": "client", "protector": ReversingProtector()},
        {"provider": "provider", "client_id": "", "protector": ReversingProtector()},
        {"provider": "provider", "client_id": "client", "protector": object()},
    ],
)
def test_memory_token_vault_rejects_invalid_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="token vault configuration"):
        MemoryTokenVault(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"store": object()},
        {"store": MemoryOAuthAccountStore(), "vault": object()},
        {"store": MemoryOAuthAccountStore(), "revocation_retries": object()},
    ],
)
def test_account_service_rejects_invalid_ports(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="account service configuration"):
        OAuthAccountService(**kwargs)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_exact_lookup_cross_account_link_and_atomic_final_unlink() -> None:
    store = MemoryOAuthAccountStore(login_method_counts={"account-1": 1, "account-2": 1})
    linked = await store.link_identity("account-1", identity(), grant(), now=NOW)

    assert (await store.resolve_login(identity())).linked == linked
    assert (await store.resolve_login(identity(subject="other"))).linked is None
    with pytest.raises(AccountLinkError):
        await store.link_identity("account-2", identity(), grant(), now=NOW)
    updated = await store.link_identity("account-1", identity(), grant("email"), now=NOW)
    assert updated.grant.scopes == frozenset({"email"})
    assert (
        await store.unlink_identity("account-2", linked.provider_account_id, require_remaining=True, now=NOW)
    ).status is UnlinkStatus.NOT_FOUND

    assert (
        await store.unlink_identity("account-1", linked.provider_account_id, require_remaining=True, now=NOW)
    ).status is UnlinkStatus.UNLINKED

    only_provider = MemoryOAuthAccountStore()
    final = await only_provider.link_identity("account-1", identity(), grant(), now=NOW)
    result = await only_provider.unlink_identity(
        "account-1", final.provider_account_id, require_remaining=True, now=NOW
    )
    assert result.status is UnlinkStatus.FINAL_METHOD
    assert (await only_provider.resolve_login(identity())).linked == final


@pytest.mark.anyio
async def test_account_store_rejects_invalid_inputs_and_missing_grant_target() -> None:
    store = MemoryOAuthAccountStore()
    naive = NOW.replace(tzinfo=None)

    with pytest.raises(OAuthAccountError):
        await store.resolve_login(object())  # type: ignore[arg-type]
    with pytest.raises(OAuthAccountError):
        await store.link_identity("", identity(), grant(), now=NOW)
    with pytest.raises(OAuthAccountError):
        await store.unlink_identity("account", "", require_remaining=True, now=NOW)
    with pytest.raises(OAuthAccountError):
        await store.apply_grant("account", "missing", grant(), now=NOW)
    with pytest.raises(OAuthAccountError):
        await store.apply_grant("account", "missing", grant(), now=naive)
    with pytest.raises(OAuthAccountError):
        await store.resolve_provider_account("", "example")


@pytest.mark.anyio
async def test_account_store_rejects_ambiguous_provider_account_resolution() -> None:
    store = MemoryOAuthAccountStore(login_method_counts={"account-1": 2})
    await store.link_identity("account-1", identity(subject="one"), grant(), now=NOW)
    await store.link_identity("account-1", identity(subject="two"), grant(), now=NOW)

    with pytest.raises(OAuthAccountError):
        await store.resolve_provider_account("account-1", "example")


@pytest.mark.anyio
async def test_unknown_login_requires_explicit_provision_and_no_vault_discards_tokens() -> None:
    store = MemoryOAuthAccountStore(login_method_counts={"account-1": 1})
    denied = OAuthAccountService(store=store)

    with pytest.raises(OAuthAccountError):
        await denied.login(identity(), grant(), tokens(), now=NOW)

    seen: list[ProviderIdentity] = []

    async def provision(value: ProviderIdentity) -> str:
        seen.append(value)
        return "account-1"

    service = OAuthAccountService(store=store, provision=provision)
    linked = await service.login(identity(), grant(), tokens(), now=NOW)

    assert linked.account_id == "account-1"
    assert seen == [identity()]
    assert service.vault is None


@pytest.mark.anyio
async def test_existing_login_link_unlink_and_scope_upgrade_use_vault() -> None:
    store = MemoryOAuthAccountStore(login_method_counts={"account-1": 1})
    vault = MemoryTokenVault(provider="example", client_id="client", protector=ReversingProtector())
    service = OAuthAccountService(store=store, vault=vault)
    linked = await store.link_identity("account-1", identity(), grant(), now=NOW)

    resolved = await service.login(identity(), grant("email"), tokens(), now=NOW)
    assert resolved.grant.scopes == frozenset({"email"})
    assert await vault.get_for_refresh(linked.provider_account_id, now=NOW) is not None

    upgraded = await service.apply_scope_upgrade(
        proof("oauth-scope-upgrade"),
        linked.provider_account_id,
        grant("email", "profile"),
        required_scopes=frozenset({"email"}),
        now=NOW,
    )
    assert upgraded.grant.scopes == frozenset({"email", "profile"})
    with pytest.raises(OAuthAccountError):
        await service.apply_scope_upgrade(
            proof("oauth-scope-upgrade", account_id="account-2", transaction_account_id="account-2"),
            linked.provider_account_id,
            grant("email"),
            required_scopes=frozenset({"email"}),
            now=NOW,
        )

    result = await service.unlink(proof("oauth-unlink"), linked.provider_account_id, now=NOW)
    assert result.status is UnlinkStatus.UNLINKED
    assert await vault.get_for_refresh(linked.provider_account_id, now=NOW) is None


@pytest.mark.anyio
async def test_link_with_vault_and_scope_upgrade_failures() -> None:
    store = MemoryOAuthAccountStore(login_method_counts={"account-1": 1})
    vault = MemoryTokenVault(provider="example", client_id="client", protector=ReversingProtector())
    service = OAuthAccountService(store=store, vault=vault)

    linked = await service.link(proof("oauth-link"), identity(), grant(), tokens(), now=NOW)
    assert await vault.get_for_refresh(linked.provider_account_id, now=NOW) is not None

    with pytest.raises(OAuthAccountError):
        await service.apply_scope_upgrade(
            proof("oauth-link"), linked.provider_account_id, grant(), required_scopes=frozenset({"email"}), now=NOW
        )
    with pytest.raises(OAuthAccountError):
        await service.unlink(proof("oauth-link"), linked.provider_account_id, now=NOW)

    without_vault = OAuthAccountService(store=MemoryOAuthAccountStore(login_method_counts={"account-1": 1}))
    unretained = await without_vault.link(proof("oauth-link"), identity(subject="other"), grant(), tokens(), now=NOW)
    assert (
        await without_vault.unlink(proof("oauth-unlink"), unretained.provider_account_id, now=NOW)
    ).status is UnlinkStatus.UNLINKED


@pytest.mark.anyio
@pytest.mark.parametrize(
    "invalid_proof",
    [
        proof("oauth-link", consumed=False),
        proof("oauth-link", transaction_account_id="other"),
        proof("oauth-link", transaction_security_epoch=1),
        proof("oauth-unlink"),
    ],
)
async def test_link_rejects_stale_or_wrong_step_up(invalid_proof: OAuthLinkProof) -> None:
    service = OAuthAccountService(store=MemoryOAuthAccountStore())

    with pytest.raises(OAuthAccountError):
        await service.link(invalid_proof, identity(), grant(), tokens(), now=NOW)


@pytest.mark.anyio
async def test_encrypted_vault_round_trip_version_and_cas() -> None:
    protector = ReversingProtector()
    vault = MemoryTokenVault(provider="example", client_id="client", protector=protector)

    reference = await vault.put("provider-account", tokens(), now=NOW)
    stored = await vault.get_for_refresh("provider-account", now=NOW)

    assert reference.version == 1
    assert stored is not None
    assert stored.tokens.access_token.get_secret_value() == "access"
    assert b"access" not in (protector.last_ciphertext or b"")
    assert b"example" in (protector.associated_data or b"")
    assert "access" not in repr(reference)
    assert "access" not in repr(stored)
    assert await vault.replace("provider-account", expected_version=1, tokens=tokens(access="rotated"), now=NOW)
    assert not await vault.replace("provider-account", expected_version=1, tokens=tokens(access="lost-race"), now=NOW)
    rotated = await vault.get_for_refresh("provider-account", now=NOW)
    assert rotated is not None
    assert rotated.reference.version == 2
    assert rotated.tokens.access_token.get_secret_value() == "rotated"
    await vault.delete("provider-account")
    assert await vault.get_for_refresh("provider-account", now=NOW) is None


@pytest.mark.anyio
async def test_vault_rejects_invalid_inputs_and_classifies_protector_failures() -> None:
    vault = MemoryTokenVault(provider="example", client_id="client", protector=ReversingProtector())
    naive = NOW.replace(tzinfo=None)

    with pytest.raises(OAuthAccountError):
        await vault.put("", tokens(), now=NOW)
    with pytest.raises(OAuthAccountError):
        await vault.put("provider-account", object(), now=NOW)  # type: ignore[arg-type]
    with pytest.raises(OAuthAccountError):
        await vault.get_for_refresh("", now=NOW)
    with pytest.raises(OAuthAccountError):
        await vault.get_for_refresh("provider-account", now=naive)
    with pytest.raises(OAuthAccountError):
        await vault.replace("provider-account", expected_version=0, tokens=tokens(), now=NOW)
    with pytest.raises(OAuthAccountError):
        await vault.delete("")

    failing = MemoryTokenVault(provider="example", client_id="client", protector=FaultProtector(fail_protect=True))
    with pytest.raises(OAuthAccountError) as captured:
        await failing.put("provider-account", tokens(), now=NOW)
    assert captured.value.code == "oauth_vault_unavailable"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "decoded",
    [b"[]", b'{"access_token":"a","token_type":"Bearer","scopes":"profile","expires_at":"2026-07-28T18:00:00+00:00"}'],
)
async def test_vault_rejects_authenticated_corrupt_payloads(decoded: bytes) -> None:
    protector = FaultProtector(decoded=decoded)
    vault = MemoryTokenVault(provider="example", client_id="client", protector=protector)
    await vault.put("provider-account", tokens(), now=NOW)

    with pytest.raises(OAuthAccountError) as captured:
        await vault.get_for_refresh("provider-account", now=NOW)
    assert captured.value.code == "oauth_vault_unavailable"


def test_scope_upgrade_requests_only_allowlisted_missing_scopes() -> None:
    assert OAuthAccountService.missing_scopes(
        current=frozenset({"profile"}),
        requested=frozenset({"profile", "email"}),
        allowed=frozenset({"profile", "email"}),
    ) == frozenset({"email"})

    with pytest.raises(OAuthAccountError):
        OAuthAccountService.missing_scopes(
            current=frozenset(), requested=frozenset({"admin"}), allowed=frozenset({"profile"})
        )


class RefreshProvider:
    name = "example"

    def __init__(self, *, invalid: bool = False, revoke_failures: frozenset[str] = frozenset()) -> None:
        self.calls = 0
        self.invalid = invalid
        self.revocations: list[str | None] = []
        self.revoke_failures = revoke_failures

    def build_authorization_url(self, start: OAuthTransactionStart) -> str:
        del start
        return "https://issuer.example/authorize"

    async def exchange_code(
        self, *, code: SecretStr, transaction: OAuthTransaction, now: datetime | None = None
    ) -> ProviderTokenSet:
        del code, transaction, now
        return tokens()

    async def resolve_identity(
        self, tokens: ProviderTokenSet, *, transaction: OAuthTransaction, now: datetime | None = None
    ) -> ProviderIdentity:
        del tokens, transaction, now
        return identity()

    async def refresh(
        self, refresh_token: SecretStr, *, current_scopes: frozenset[str] | None = None, now: datetime | None = None
    ) -> ProviderTokenSet:
        del refresh_token, current_scopes, now
        self.calls += 1
        await asyncio.sleep(0)
        if self.invalid:
            raise InvalidProviderGrantError
        return tokens(access=f"rotated-{self.calls}")

    async def revoke(self, token: SecretStr, *, token_type_hint: str | None) -> None:
        del token
        self.revocations.append(token_type_hint)
        if token_type_hint in self.revoke_failures:
            raise RuntimeError


@pytest.mark.anyio
async def test_refresh_is_single_flight_and_invalid_grant_deletes_vault() -> None:
    vault = MemoryTokenVault(provider="example", client_id="client", protector=ReversingProtector())
    await vault.put("provider-account", tokens(), now=NOW)
    service = OAuthAccountService(store=MemoryOAuthAccountStore(), vault=vault)
    provider = RefreshProvider()

    first, second = await asyncio.gather(
        service.refresh("provider-account", provider, now=NOW), service.refresh("provider-account", provider, now=NOW)
    )

    assert first.access_token.get_secret_value() == "rotated-1"
    assert second.access_token.get_secret_value() == "rotated-1"
    assert provider.calls == 1
    assert not service._refresh_locks  # noqa: SLF001 - regression asserts bounded lock cleanup

    invalid = RefreshProvider(invalid=True)
    with pytest.raises(OAuthAccountError) as captured:
        await service.refresh("provider-account", invalid, now=NOW)
    assert captured.value.code == "oauth_reauthorization_required"
    assert await vault.get_for_refresh("provider-account", now=NOW) is None


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("vault", "code"),
    [
        (RefreshRaceVault(second_missing=True), "oauth_reauthorization_required"),
        (RefreshRaceVault(second_missing=False), "oauth_refresh_raced"),
    ],
)
async def test_refresh_classifies_external_vault_races(vault: RefreshRaceVault, code: str) -> None:
    service = OAuthAccountService(store=MemoryOAuthAccountStore(), vault=vault)

    with pytest.raises(OAuthAccountError) as captured:
        await service.refresh("provider-account", RefreshProvider(), now=NOW)

    assert captured.value.code == code


@pytest.mark.anyio
async def test_refresh_without_retention_or_refresh_token_and_revoke_cleanup() -> None:
    provider = RefreshProvider()
    without_vault = OAuthAccountService(store=MemoryOAuthAccountStore())
    with pytest.raises(OAuthAccountError) as captured:
        await without_vault.refresh("provider-account", provider, now=NOW)
    assert captured.value.code == "oauth_tokens_not_retained"
    await without_vault.revoke("provider-account", provider, now=NOW)

    vault = MemoryTokenVault(provider="example", client_id="client", protector=ReversingProtector())
    service = OAuthAccountService(store=MemoryOAuthAccountStore(), vault=vault)
    await vault.put("provider-account", tokens(refresh=None), now=NOW)
    with pytest.raises(OAuthAccountError) as captured:
        await service.refresh("provider-account", provider, now=NOW)
    assert captured.value.code == "oauth_reauthorization_required"
    await service.revoke("provider-account", provider, now=NOW)
    assert provider.revocations == ["access_token"]

    await vault.put("provider-account", tokens(), now=NOW)
    await service.revoke("provider-account", provider, now=NOW)
    assert provider.revocations == ["access_token", "refresh_token", "access_token"]
    assert await vault.get_for_refresh("provider-account", now=NOW) is None
    await service.revoke("provider-account", provider, now=NOW)


@pytest.mark.anyio
async def test_revoke_attempts_every_token_and_schedules_secret_retry_before_local_delete() -> None:
    vault = MemoryTokenVault(provider="example", client_id="client", protector=ReversingProtector())
    retries = RevocationRetries()
    service = OAuthAccountService(store=MemoryOAuthAccountStore(), vault=vault, revocation_retries=retries)
    await vault.put("provider-account", tokens(), now=NOW)
    provider = RefreshProvider(revoke_failures=frozenset({"refresh_token", "access_token"}))

    with pytest.raises(OAuthAccountError) as captured:
        await service.revoke("provider-account", provider, now=NOW)

    assert captured.value.code == "oauth_revocation_pending"
    assert provider.revocations == ["refresh_token", "access_token"]
    assert retries.scheduled[0][0] == OAuthRevocationFailure(
        "provider-account", frozenset({"refresh_token", "access_token"}), NOW
    )
    assert retries.scheduled[0][1].access_token.get_secret_value() == "access"
    assert await vault.get_for_refresh("provider-account", now=NOW) is None


@pytest.mark.anyio
@pytest.mark.parametrize("retries", [None, BrokenRevocationRetries()])
async def test_revoke_retains_vault_when_retry_persistence_is_unavailable(retries: object | None) -> None:
    vault = MemoryTokenVault(provider="example", client_id="client", protector=ReversingProtector())
    service = OAuthAccountService(
        store=MemoryOAuthAccountStore(),
        vault=vault,
        revocation_retries=retries,  # type: ignore[arg-type]
    )
    await vault.put("provider-account", tokens(), now=NOW)

    with pytest.raises(OAuthAccountError) as captured:
        await service.revoke("provider-account", RefreshProvider(revoke_failures=frozenset({"access_token"})), now=NOW)

    assert captured.value.code == "oauth_revocation_pending"
    assert await vault.get_for_refresh("provider-account", now=NOW) is not None


@pytest.mark.anyio
async def test_public_oauth_conformance_fakes_record_calls_and_http() -> None:
    fake = FakeOAuthProvider(name="example", tokens=tokens(), identity=identity())
    tx = transaction()
    start = OAuthTransactionStart(
        state=SecretStr("state"),
        browser_binding=SecretStr("binding"),
        pkce_challenge="challenge",
        nonce=None,
        transaction=tx,
    )

    assert "state=state" in fake.build_authorization_url(start)
    assert await fake.exchange_code(code=SecretStr("code"), transaction=tx, now=NOW) == tokens()
    assert await fake.resolve_identity(tokens(), transaction=tx, now=NOW) == identity()
    assert await fake.refresh(SecretStr("refresh"), now=NOW) == tokens()
    await fake.revoke(SecretStr("access"), token_type_hint=None)
    assert fake.calls == ["authorize", "exchange", "identity", "refresh", "revoke"]

    transport = FakeOAuthHTTPTransport([httpx.Response(200, content=b"ok")])
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get("https://provider.example/user")
    assert response.text == "ok"
    assert transport.requests[0].url == "https://provider.example/user"
    assert "authorization" not in transport.requests[0].header_names
    assert "access" not in repr(transport.requests[0])

    with pytest.raises(AssertionError, match="responses exhausted"):
        async with httpx.AsyncClient(transport=transport) as client:
            await client.get("https://provider.example/user")
