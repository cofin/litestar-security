import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from litestar_security.providers.oauth import (
    AccountLinkError,
    InvalidProviderGrant,
    LinkedProviderAccount,
    MemoryOAuthAccountStore,
    MemoryTokenVault,
    OAuthAccountError,
    OAuthAccountService,
    OAuthAccountStore,
    OAuthLinkProof,
    OAuthLoginResolution,
    OAuthTransaction,
    OAuthTransactionStart,
    ProtectedOAuthSecret,
    ProviderGrant,
    ProviderIdentity,
    ProviderTokenReference,
    ProviderTokenSet,
    SecretStr,
    TokenVault,
    UnlinkResult,
    UnlinkStatus,
)

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


@pytest.mark.anyio
async def test_exact_lookup_cross_account_link_and_atomic_final_unlink() -> None:
    store = MemoryOAuthAccountStore(login_method_counts={"account-1": 1, "account-2": 1})
    linked = await store.link_identity("account-1", identity(), grant(), now=NOW)

    assert (await store.resolve_login(identity())).linked == linked
    assert (await store.resolve_login(identity(subject="other"))).linked is None
    with pytest.raises(AccountLinkError):
        await store.link_identity("account-2", identity(), grant(), now=NOW)

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

    def __init__(self, *, invalid: bool = False) -> None:
        self.calls = 0
        self.invalid = invalid

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

    async def refresh(self, refresh_token: SecretStr, *, now: datetime | None = None) -> ProviderTokenSet:
        del refresh_token, now
        self.calls += 1
        await asyncio.sleep(0)
        if self.invalid:
            raise InvalidProviderGrant
        return tokens(access=f"rotated-{self.calls}")

    async def revoke(self, token: SecretStr, *, token_type_hint: str | None) -> None:
        del token, token_type_hint


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

    invalid = RefreshProvider(invalid=True)
    with pytest.raises(OAuthAccountError) as captured:
        await service.refresh("provider-account", invalid, now=NOW)
    assert captured.value.code == "oauth_reauthorization_required"
    assert await vault.get_for_refresh("provider-account", now=NOW) is None
