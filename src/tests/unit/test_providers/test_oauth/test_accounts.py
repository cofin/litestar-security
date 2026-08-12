import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import httpx
import pytest
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.providers import oauth as oauth_module
from litestar_security.providers.oauth import (
    AccountLinkError,
    InvalidProviderGrantError,
    LinkedProviderAccount,
    MemoryOAuthAccountStore,
    OAuthAccountError,
    OAuthAccountService,
    OAuthAccountStore,
    OAuthLinkProof,
    OAuthOperation,
    OAuthTransaction,
    OAuthTransactionStart,
    ProtectedOAuthSecret,
    ProviderGrant,
    ProviderIdentity,
    ProviderTokenReference,
    ProviderTokenSet,
    SecretStr,
    UnlinkOutcome,
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
class BoundRecordingProtector:
    """Record encrypted retry material while authenticating associated data."""

    active_key_version: str = "v1"
    last_ciphertext: bytes | None = None

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedOAuthSecret:
        ciphertext = sha256(associated_data).digest() + secret[::-1]
        self.last_ciphertext = ciphertext
        return ProtectedOAuthSecret(ciphertext=ciphertext, key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedOAuthSecret, *, associated_data: bytes) -> bytes:
        prefix = sha256(associated_data).digest()
        if not protected.ciphertext.startswith(prefix):
            message = "associated data did not match"
            raise ValueError(message)
        return protected.ciphertext[len(prefix) :][::-1]


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
    assert OAuthAccountService.__name__ == "OAuthAccountService"
    assert OAuthLinkProof.__name__ == "OAuthLinkProof"
    assert LinkedProviderAccount.__name__ == "LinkedProviderAccount"
    assert UnlinkOutcome.__name__ == "UnlinkOutcome"
    assert ProviderTokenReference.__name__ == "ProviderTokenReference"
    assert MemoryOAuthAccountStore.__name__ == "MemoryOAuthAccountStore"
    with pytest.raises(AttributeError, match="has no attribute"):
        getattr(oauth_module, "missing")  # noqa: B009 - explicitly exercise the module lazy-export hook


@pytest.mark.parametrize(
    "factory",
    [
        lambda: LinkedProviderAccount("", "account", "provider", "issuer", "subject", grant(), NOW),
        lambda: UnlinkOutcome(UnlinkStatus.UNLINKED),
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


@pytest.mark.parametrize("kwargs", [{"store": object()}, {"store": MemoryOAuthAccountStore(), "provision_unknown": 1}])
def test_account_service_rejects_invalid_ports(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="account service configuration"):
        OAuthAccountService(**kwargs)  # type: ignore[arg-type]


async def test_exact_lookup_cross_account_link_and_atomic_final_unlink() -> None:
    store = MemoryOAuthAccountStore(login_method_counts={"account-1": 1, "account-2": 1})
    linked = await store.link("account-1", identity(), grant(), tokens(), retain_tokens=False, now=NOW)

    assert await store.resolve_provider_account("account-1", "example") == linked
    with pytest.raises(AccountLinkError):
        await store.link("account-2", identity(), grant(), tokens(), retain_tokens=False, now=NOW)
    updated = await store.link("account-1", identity(), grant("email"), tokens(), retain_tokens=False, now=NOW)
    assert updated.grant.scopes == frozenset({"email"})
    assert (
        await store.unlink("account-2", "example", linked.provider_account_id, require_remaining=True, now=NOW)
    ).status is UnlinkStatus.NOT_FOUND

    assert (
        await store.unlink("account-1", "example", linked.provider_account_id, require_remaining=True, now=NOW)
    ).status is UnlinkStatus.UNLINKED

    only_provider = MemoryOAuthAccountStore()
    final = await only_provider.link("account-1", identity(), grant(), tokens(), retain_tokens=False, now=NOW)
    result = await only_provider.unlink(
        "account-1", "example", final.provider_account_id, require_remaining=True, now=NOW
    )
    assert result.status is UnlinkStatus.FINAL_METHOD
    assert await only_provider.resolve_provider_account("account-1", "example") == final


async def test_simultaneous_oauth_unlink_has_one_atomic_winner() -> None:
    store = MemoryOAuthAccountStore(login_method_counts={"account-1": 2})
    linked = await store.link("account-1", identity(), grant(), tokens(), retain_tokens=False, now=NOW)

    results = await asyncio.gather(
        store.unlink("account-1", "example", linked.provider_account_id, require_remaining=True, now=NOW),
        store.unlink("account-1", "example", linked.provider_account_id, require_remaining=True, now=NOW),
    )

    assert {result.status for result in results} == {UnlinkStatus.UNLINKED, UnlinkStatus.NOT_FOUND}


async def test_account_store_rejects_invalid_inputs_and_missing_grant_target() -> None:
    store = MemoryOAuthAccountStore()
    naive = NOW.replace(tzinfo=None)

    with pytest.raises(OAuthAccountError):
        await store.link("", identity(), grant(), tokens(), retain_tokens=False, now=NOW)
    with pytest.raises(OAuthAccountError):
        await store.unlink("account", "example", "", require_remaining=True, now=NOW)
    with pytest.raises(OAuthAccountError):
        await store.upgrade("account", "missing", identity(), grant(), tokens(), retain_tokens=False, now=naive)
    with pytest.raises(OAuthAccountError):
        await store.resolve_provider_account("", "example")


async def test_account_store_rejects_ambiguous_provider_account_resolution() -> None:
    store = MemoryOAuthAccountStore(login_method_counts={"account-1": 2})
    await store.link("account-1", identity(subject="one"), grant(), tokens(), retain_tokens=False, now=NOW)
    with pytest.raises(AccountLinkError):
        await store.link("account-1", identity(subject="two"), grant(), tokens(), retain_tokens=False, now=NOW)


async def test_unknown_login_requires_explicit_provision_and_no_vault_discards_tokens() -> None:
    store = MemoryOAuthAccountStore(login_method_counts={"account-1": 1})
    denied = OAuthAccountService(store=store)

    with pytest.raises(OAuthAccountError):
        await denied.login(identity(), grant(), tokens(), now=NOW)

    service = OAuthAccountService(store=store, provision_unknown=True)
    first, second = await asyncio.gather(
        service.login(identity(), grant(), tokens(), now=NOW), service.login(identity(), grant(), tokens(), now=NOW)
    )

    assert first.linked == second.linked
    assert {first.provisioned, second.provisioned} == {False, True}


async def test_aggregate_link_scope_upgrade_and_unlink_apply_token_policy() -> None:
    store = MemoryOAuthAccountStore(login_method_counts={"account-1": 1}, protector=ReversingProtector())
    service = OAuthAccountService(store=store)
    linked = await service.link(proof("oauth-link"), identity(), grant(), tokens(), retain_tokens=True, now=NOW)
    assert await store.get_tokens(linked.provider_account_id, now=NOW) is not None

    upgraded = await service.apply_scope_upgrade(
        proof("oauth-scope-upgrade"),
        linked.provider_account_id,
        identity(),
        grant("email"),
        tokens(access="upgraded"),
        required_scopes=frozenset({"email"}),
        retain_tokens=True,
        now=NOW,
    )
    stored = await store.get_tokens(linked.provider_account_id, now=NOW)
    assert upgraded.grant.scopes == frozenset({"email"})
    assert stored is not None
    assert stored.tokens.access_token.get_secret_value() == "upgraded"

    discarded = await service.login(identity(), grant(), tokens(), retain_tokens=False, now=NOW)
    assert discarded.linked.provider_account_id == upgraded.provider_account_id
    assert await store.get_tokens(linked.provider_account_id, now=NOW) is None


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


async def test_refresh_is_single_flight_and_invalid_grant_deletes_vault() -> None:
    store = MemoryOAuthAccountStore(protector=BoundRecordingProtector())
    linked = await store.link("account-1", identity(), grant(), tokens(), retain_tokens=True, now=NOW)
    service = OAuthAccountService(store=store)
    provider = RefreshProvider()

    first, second = await asyncio.gather(
        service.refresh(linked.provider_account_id, provider, now=NOW),
        service.refresh(linked.provider_account_id, provider, now=NOW),
    )

    assert first.access_token.get_secret_value() == "rotated-1"
    assert second.access_token.get_secret_value() == "rotated-1"
    assert provider.calls == 1
    assert not service._refresh_locks  # noqa: SLF001 - regression asserts bounded lock cleanup

    invalid = RefreshProvider(invalid=True)
    with pytest.raises(OAuthAccountError) as captured:
        await service.refresh(linked.provider_account_id, invalid, now=NOW)
    assert captured.value.code == "oauth_reauthorization_required"
    assert await store.get_tokens(linked.provider_account_id, now=NOW) is None


async def test_refresh_without_retention_or_refresh_token_and_revoke_cleanup() -> None:
    provider = RefreshProvider()
    without_vault = OAuthAccountService(store=MemoryOAuthAccountStore())
    with pytest.raises(OAuthAccountError) as captured:
        await without_vault.refresh("provider-account", provider, now=NOW)
    assert captured.value.code == "oauth_reauthorization_required"
    await without_vault.revoke("provider-account", provider, now=NOW)

    store = MemoryOAuthAccountStore(protector=ReversingProtector())
    linked = await store.link("account-1", identity(), grant(), tokens(refresh=None), retain_tokens=True, now=NOW)
    service = OAuthAccountService(store=store)
    with pytest.raises(OAuthAccountError) as captured:
        await service.refresh(linked.provider_account_id, provider, now=NOW)
    assert captured.value.code == "oauth_reauthorization_required"
    await service.revoke(linked.provider_account_id, provider, now=NOW)
    assert provider.revocations == ["access_token"]

    await store.upgrade(
        "account-1", linked.provider_account_id, identity(), grant(), tokens(), retain_tokens=True, now=NOW
    )
    await service.revoke(linked.provider_account_id, provider, now=NOW)
    assert provider.revocations == ["access_token", "refresh_token", "access_token"]
    assert await store.get_tokens(linked.provider_account_id, now=NOW) is None
    await service.revoke(linked.provider_account_id, provider, now=NOW)


async def test_revoke_attempts_every_token_and_schedules_secret_retry_before_local_delete() -> None:
    store = MemoryOAuthAccountStore(protector=BoundRecordingProtector())
    linked = await store.link("account-1", identity(), grant(), tokens(), retain_tokens=True, now=NOW)
    service = OAuthAccountService(store=store)
    provider = RefreshProvider(revoke_failures=frozenset({"refresh_token", "access_token"}))

    with pytest.raises(OAuthAccountError) as captured:
        await service.revoke(linked.provider_account_id, provider, now=NOW)

    assert captured.value.code == "oauth_revocation_pending"
    assert provider.revocations == ["refresh_token", "access_token"]
    assert await store.get_tokens(linked.provider_account_id, now=NOW) is None


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
