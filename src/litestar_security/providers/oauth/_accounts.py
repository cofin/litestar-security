"""Atomic provider-account lifecycle and encrypted token-vault contracts."""

from __future__ import annotations

import json
from collections.abc import Mapping  # noqa: TC003 - runtime protocol and JSON shape checks require Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum
from hashlib import sha256
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

from anyio import Lock
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.providers._internal import reject_non_finite, unique_object, validate_depth
from litestar_security.providers.oauth._provider import (
    OAuthProvider,
    OAuthProviderError,
    ProviderGrant,
    ProviderIdentity,
    ProviderTokenSet,
)
from litestar_security.providers.oauth._transactions import OAuthTransactionProtector, ProtectedOAuthSecret, SecretStr

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

__all__ = (
    "AccountLinkError",
    "InvalidProviderGrant",
    "LinkedProviderAccount",
    "MemoryOAuthAccountStore",
    "MemoryTokenVault",
    "OAuthAccountError",
    "OAuthAccountService",
    "OAuthAccountStore",
    "OAuthLinkProof",
    "OAuthLoginResolution",
    "ProviderTokenReference",
    "StoredProviderTokens",
    "TokenVault",
    "UnlinkResult",
    "UnlinkStatus",
)


_MAXIMUM_VAULT_DOCUMENT_DEPTH = 8
_PURPOSES = frozenset({"oauth-link", "oauth-unlink", "oauth-scope-upgrade"})
_VAULT_UNAVAILABLE = "oauth_vault_unavailable"
_TOKENS_NOT_RETAINED = "oauth_tokens_not_retained"
_REAUTHORIZATION_REQUIRED = "oauth_reauthorization_required"
_REFRESH_RACED = "oauth_refresh_raced"


@dataclass(frozen=True, slots=True)
class LinkedProviderAccount:
    """One exact provider identity linked to one application account."""

    provider_account_id: str
    account_id: str
    provider: str
    issuer: str
    subject: str
    grant: ProviderGrant
    linked_at: datetime

    def __post_init__(self) -> None:
        """Require stable identifiers, a validated grant, and aware time."""
        if (
            any(
                not _strict_text(value)
                for value in (self.provider_account_id, self.account_id, self.provider, self.issuer, self.subject)
            )
            or self.grant.__class__ is not ProviderGrant
            or not _aware(self.linked_at)
        ):
            message = "Linked provider account is invalid"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class OAuthLoginResolution:
    """Exact provider-identity lookup result; absence never implies email matching."""

    linked: LinkedProviderAccount | None


class UnlinkStatus(str, Enum):
    """Atomic provider unlink outcomes."""

    UNLINKED = "unlinked"
    NOT_FOUND = "not-found"
    FINAL_METHOD = "final-method"


@dataclass(frozen=True, slots=True)
class UnlinkResult:
    """Result of one atomic identity, login-method, and grant removal."""

    status: UnlinkStatus
    provider_account_id: str | None = None

    def __post_init__(self) -> None:
        """Require a provider account only for successful removal."""
        if self.status.__class__ is not UnlinkStatus or (self.status is UnlinkStatus.UNLINKED) != (
            self.provider_account_id is not None
        ):
            message = "OAuth unlink result is invalid"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class ProviderTokenReference:
    """Secret-free optimistic token-vault reference."""

    provider_account_id: str
    version: int
    scopes: frozenset[str]
    expires_at: datetime

    def __post_init__(self) -> None:
        """Require a positive version and immutable expiry metadata."""
        if (
            not _strict_text(self.provider_account_id)
            or self.version.__class__ is not int
            or self.version < 1
            or self.scopes.__class__ is not frozenset
            or not _aware(self.expires_at)
        ):
            message = "Provider token reference is invalid"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class StoredProviderTokens:
    """Versioned decrypted tokens returned only to the refresh service."""

    reference: ProviderTokenReference
    tokens: ProviderTokenSet = field(repr=False)


@dataclass(frozen=True, slots=True)
class OAuthLinkProof:
    """Consumed purpose-bound proof tied to account and security epoch."""

    account_id: str
    purpose: str
    security_epoch: int
    transaction_account_id: str
    transaction_security_epoch: int
    consumed: bool

    def valid_for(self, purpose: str) -> bool:
        """Return whether every callback binding remains current.

        Args:
            purpose: Required operation purpose.

        Returns:
            Whether account, epoch, purpose, and consumption all match.
        """
        return (
            self.consumed
            and self.purpose == purpose
            and purpose in _PURPOSES
            and self.account_id == self.transaction_account_id
            and self.security_epoch == self.transaction_security_epoch
            and self.security_epoch.__class__ is int
            and self.security_epoch >= 0
        )


@runtime_checkable
class OAuthAccountStore(Protocol):
    """Atomic behavior-oriented provider account persistence boundary."""

    async def resolve_login(self, identity: ProviderIdentity) -> OAuthLoginResolution:
        """Resolve only the exact provider, issuer, and subject identity."""
        ...  # pragma: no cover

    async def link_identity(
        self, account_id: str, identity: ProviderIdentity, grant: ProviderGrant, *, now: datetime
    ) -> LinkedProviderAccount:
        """Atomically link or reject a cross-account identity."""
        ...  # pragma: no cover

    async def unlink_identity(
        self, account_id: str, provider_account_id: str, *, require_remaining: bool, now: datetime
    ) -> UnlinkResult:
        """Atomically remove identity, login method, and grant."""
        ...  # pragma: no cover

    async def apply_grant(
        self, provider_account_id: str, grant: ProviderGrant, *, now: datetime
    ) -> LinkedProviderAccount:
        """Atomically replace the actually granted provider scopes."""
        ...  # pragma: no cover


@runtime_checkable
class TokenVault(Protocol):
    """Encrypted optimistic provider-token persistence boundary."""

    async def put(self, provider_account_id: str, tokens: ProviderTokenSet, *, now: datetime) -> ProviderTokenReference:
        """Encrypt and store a token set."""
        ...  # pragma: no cover

    async def get_for_refresh(self, provider_account_id: str, *, now: datetime) -> StoredProviderTokens | None:
        """Decrypt a token set only for refresh."""
        ...  # pragma: no cover

    async def replace(
        self, provider_account_id: str, *, expected_version: int, tokens: ProviderTokenSet, now: datetime
    ) -> bool:
        """Replace tokens only at the expected version."""
        ...  # pragma: no cover

    async def delete(self, provider_account_id: str) -> None:
        """Delete retained provider credentials."""
        ...  # pragma: no cover


class OAuthAccountError(RuntimeError):
    """Stable secret-free account lifecycle failure."""

    def __init__(self, code: str = "oauth_account_denied") -> None:
        """Initialize one stable application-facing code."""
        self.code = code
        super().__init__("OAuth account operation denied")


class AccountLinkError(OAuthAccountError):
    """Reject a duplicate cross-account provider identity."""


class InvalidProviderGrant(OAuthProviderError):  # noqa: N818 - domain outcome matches OAuth invalid_grant
    """Indicate that refresh requires provider reauthorization."""


class MemoryOAuthAccountStore:
    """Atomic in-memory reference store for provider account behavior."""

    __slots__ = ("_identity_index", "_links", "_lock", "_method_counts")

    def __init__(self, *, login_method_counts: Mapping[str, int] | None = None) -> None:
        """Create a store with authoritative total login-method counts.

        Args:
            login_method_counts: Existing local and provider methods per account.
        """
        counts = dict(login_method_counts or {})
        if any(not _strict_text(key) or value.__class__ is not int or value < 0 for key, value in counts.items()):
            raise ImproperlyConfiguredException(detail="OAuth login method counts are invalid")
        self._method_counts = counts
        self._identity_index: dict[tuple[str, str, str], str] = {}
        self._links: dict[str, LinkedProviderAccount] = {}
        self._lock = Lock()

    async def resolve_login(self, identity: ProviderIdentity) -> OAuthLoginResolution:
        """Resolve one exact provider identity."""
        key = _identity_key(identity)
        async with self._lock:
            provider_account_id = self._identity_index.get(key)
            return OAuthLoginResolution(None if provider_account_id is None else self._links[provider_account_id])

    async def link_identity(
        self, account_id: str, identity: ProviderIdentity, grant: ProviderGrant, *, now: datetime
    ) -> LinkedProviderAccount:
        """Atomically create one provider login method and grant."""
        if not _strict_text(account_id) or not _aware(now):
            raise OAuthAccountError
        key = _identity_key(identity)
        async with self._lock:
            existing_id = self._identity_index.get(key)
            if existing_id is not None:
                existing = self._links[existing_id]
                if existing.account_id != account_id:
                    raise AccountLinkError
                updated = replace(existing, grant=grant)
                self._links[existing_id] = updated
                return updated
            digest = sha256("\0".join(key).encode()).hexdigest()
            linked = LinkedProviderAccount(
                provider_account_id=f"oauth_{digest}",
                account_id=account_id,
                provider=identity.provider,
                issuer=identity.issuer,
                subject=identity.subject,
                grant=grant,
                linked_at=now,
            )
            self._identity_index[key] = linked.provider_account_id
            self._links[linked.provider_account_id] = linked
            self._method_counts[account_id] = self._method_counts.get(account_id, 0) + 1
            return linked

    async def unlink_identity(
        self, account_id: str, provider_account_id: str, *, require_remaining: bool, now: datetime
    ) -> UnlinkResult:
        """Atomically remove provider identity, method, and grant."""
        if not _strict_text(account_id) or not _strict_text(provider_account_id) or not _aware(now):
            raise OAuthAccountError
        async with self._lock:
            linked = self._links.get(provider_account_id)
            if linked is None or linked.account_id != account_id:
                return UnlinkResult(UnlinkStatus.NOT_FOUND)
            count = self._method_counts.get(account_id, 0)
            if require_remaining and count <= 1:
                return UnlinkResult(UnlinkStatus.FINAL_METHOD)
            del self._links[provider_account_id]
            del self._identity_index[(linked.provider, linked.issuer, linked.subject)]
            self._method_counts[account_id] = max(0, count - 1)
            return UnlinkResult(UnlinkStatus.UNLINKED, provider_account_id)

    async def apply_grant(
        self, provider_account_id: str, grant: ProviderGrant, *, now: datetime
    ) -> LinkedProviderAccount:
        """Atomically replace a provider grant."""
        if not _aware(now):
            raise OAuthAccountError
        async with self._lock:
            linked = self._links.get(provider_account_id)
            if linked is None:
                raise OAuthAccountError
            updated = replace(linked, grant=grant)
            self._links[provider_account_id] = updated
            return updated


@dataclass(slots=True)
class _VaultRecord:
    protected: ProtectedOAuthSecret
    reference: ProviderTokenReference


class MemoryTokenVault:
    """Encrypted in-memory reference vault with optimistic versioning."""

    __slots__ = ("_lock", "_protector", "_records", "client_id", "provider")

    def __init__(self, *, provider: str, client_id: str, protector: OAuthTransactionProtector) -> None:
        """Create a vault bound to one provider client.

        Args:
            provider: Stable provider name.
            client_id: Registered provider client.
            protector: Application-owned encryption boundary.
        """
        protector_value = cast("object", protector)
        if (
            not _strict_text(provider)
            or not _strict_text(client_id)
            or not isinstance(protector_value, OAuthTransactionProtector)
        ):
            raise ImproperlyConfiguredException(detail="OAuth token vault configuration is invalid")
        self.provider = provider
        self.client_id = client_id
        self._protector = protector
        self._records: dict[str, _VaultRecord] = {}
        self._lock = Lock()

    async def put(self, provider_account_id: str, tokens: ProviderTokenSet, *, now: datetime) -> ProviderTokenReference:
        """Encrypt and store a token set with a new version."""
        _validate_vault_input(provider_account_id, tokens, now)
        async with self._lock:
            previous = self._records.get(provider_account_id)
            version = 1 if previous is None else previous.reference.version + 1
            record = await self._protect(provider_account_id, version, tokens)
            self._records[provider_account_id] = record
            return record.reference

    async def get_for_refresh(self, provider_account_id: str, *, now: datetime) -> StoredProviderTokens | None:
        """Decrypt current tokens for the refresh service only."""
        if not _strict_text(provider_account_id) or not _aware(now):
            raise OAuthAccountError
        async with self._lock:
            record = self._records.get(provider_account_id)
        if record is None:
            return None
        try:
            body = await self._protector.unprotect(
                record.protected,
                associated_data=self._associated_data(provider_account_id, record.protected.key_version),
            )
            tokens = _decode_tokens(body)
        except Exception as exc:
            raise OAuthAccountError(_VAULT_UNAVAILABLE) from exc
        return StoredProviderTokens(reference=record.reference, tokens=tokens)

    async def replace(
        self, provider_account_id: str, *, expected_version: int, tokens: ProviderTokenSet, now: datetime
    ) -> bool:
        """Encrypt then atomically compare-and-swap a rotated token set."""
        _validate_vault_input(provider_account_id, tokens, now)
        if expected_version.__class__ is not int or expected_version < 1:
            raise OAuthAccountError
        replacement = await self._protect(provider_account_id, expected_version + 1, tokens)
        async with self._lock:
            current = self._records.get(provider_account_id)
            if current is None or current.reference.version != expected_version:
                return False
            self._records[provider_account_id] = replacement
            return True

    async def delete(self, provider_account_id: str) -> None:
        """Delete retained credentials idempotently."""
        if not _strict_text(provider_account_id):
            raise OAuthAccountError
        async with self._lock:
            self._records.pop(provider_account_id, None)

    async def _protect(self, provider_account_id: str, version: int, tokens: ProviderTokenSet) -> _VaultRecord:
        key_version = self._protector.active_key_version
        try:
            protected = await self._protector.protect(
                _encode_tokens(tokens), associated_data=self._associated_data(provider_account_id, key_version)
            )
        except Exception as exc:
            raise OAuthAccountError(_VAULT_UNAVAILABLE) from exc
        reference = ProviderTokenReference(
            provider_account_id=provider_account_id, version=version, scopes=tokens.scopes, expires_at=tokens.expires_at
        )
        return _VaultRecord(protected=protected, reference=reference)

    def _associated_data(self, provider_account_id: str, key_version: str) -> bytes:
        return f"oauth-vault-v1\0{self.provider}\0{self.client_id}\0{provider_account_id}\0{key_version}".encode()


class OAuthAccountService:
    """Coordinate exact login/link/scope/vault behavior over atomic ports."""

    __slots__ = ("_refresh_locks", "provision", "store", "vault")

    def __init__(
        self,
        *,
        store: OAuthAccountStore,
        vault: TokenVault | None = None,
        provision: Callable[[ProviderIdentity], Awaitable[str]] | None = None,
    ) -> None:
        """Create the account lifecycle service.

        Args:
            store: Atomic provider-account store.
            vault: Optional encrypted token retention.
            provision: Explicit unknown-identity account callback.
        """
        store_value = cast("object", store)
        vault_value = cast("object", vault)
        if not isinstance(store_value, OAuthAccountStore) or (
            vault_value is not None and not isinstance(vault_value, TokenVault)
        ):
            raise ImproperlyConfiguredException(detail="OAuth account service configuration is invalid")
        self.store = store
        self.vault = vault
        self.provision = provision
        self._refresh_locks: dict[str, Lock] = {}

    async def login(
        self, identity: ProviderIdentity, grant: ProviderGrant, tokens: ProviderTokenSet, *, now: datetime
    ) -> LinkedProviderAccount:
        """Resolve exact identity or invoke explicit provisioning."""
        resolution = await self.store.resolve_login(identity)
        if resolution.linked is None:
            if self.provision is None:
                raise OAuthAccountError
            account_id = await self.provision(identity)
            linked = await self.store.link_identity(account_id, identity, grant, now=now)
        else:
            linked = await self.store.apply_grant(resolution.linked.provider_account_id, grant, now=now)
        if self.vault is not None:
            await self.vault.put(linked.provider_account_id, tokens, now=now)
        return linked

    async def link(
        self,
        proof: OAuthLinkProof,
        identity: ProviderIdentity,
        grant: ProviderGrant,
        tokens: ProviderTokenSet,
        *,
        now: datetime,
    ) -> LinkedProviderAccount:
        """Link after exact fresh purpose and epoch validation."""
        if not proof.valid_for("oauth-link"):
            raise OAuthAccountError
        linked = await self.store.link_identity(proof.account_id, identity, grant, now=now)
        if self.vault is not None:
            await self.vault.put(linked.provider_account_id, tokens, now=now)
        return linked

    async def unlink(self, proof: OAuthLinkProof, provider_account_id: str, *, now: datetime) -> UnlinkResult:
        """Atomically preserve a remaining login method, then discard tokens."""
        if not proof.valid_for("oauth-unlink"):
            raise OAuthAccountError
        result = await self.store.unlink_identity(
            proof.account_id, provider_account_id, require_remaining=True, now=now
        )
        if result.status is UnlinkStatus.UNLINKED and self.vault is not None:
            await self.vault.delete(provider_account_id)
        return result

    @staticmethod
    def missing_scopes(
        *, current: frozenset[str], requested: frozenset[str], allowed: frozenset[str]
    ) -> frozenset[str]:
        """Return only allowlisted scopes absent from the current grant."""
        if not requested.issubset(allowed):
            raise OAuthAccountError
        return requested.difference(current)

    async def apply_scope_upgrade(
        self,
        proof: OAuthLinkProof,
        provider_account_id: str,
        grant: ProviderGrant,
        *,
        required_scopes: frozenset[str],
        now: datetime,
    ) -> LinkedProviderAccount:
        """Record only the provider's actual grant after step-up."""
        if not proof.valid_for("oauth-scope-upgrade") or not required_scopes.issubset(grant.scopes):
            raise OAuthAccountError
        return await self.store.apply_grant(provider_account_id, grant, now=now)

    async def refresh(self, provider_account_id: str, provider: OAuthProvider, *, now: datetime) -> ProviderTokenSet:
        """Single-flight refresh and optimistic rotation for one provider account."""
        if self.vault is None:
            raise OAuthAccountError(_TOKENS_NOT_RETAINED)
        observed = await self.vault.get_for_refresh(provider_account_id, now=now)
        if observed is None or observed.tokens.refresh_token is None:
            raise OAuthAccountError(_REAUTHORIZATION_REQUIRED)
        lock = self._refresh_locks.setdefault(provider_account_id, Lock())
        async with lock:
            stored = await self.vault.get_for_refresh(provider_account_id, now=now)
            if stored is None or stored.tokens.refresh_token is None:
                raise OAuthAccountError(_REAUTHORIZATION_REQUIRED)
            if stored.reference.version != observed.reference.version:
                return stored.tokens
            try:
                refreshed = await provider.refresh(stored.tokens.refresh_token, now=now)
            except InvalidProviderGrant:
                await self.vault.delete(provider_account_id)
                raise OAuthAccountError(_REAUTHORIZATION_REQUIRED) from None
            if not await self.vault.replace(
                provider_account_id, expected_version=stored.reference.version, tokens=refreshed, now=now
            ):
                raise OAuthAccountError(_REFRESH_RACED)
            return refreshed

    async def revoke(self, provider_account_id: str, provider: OAuthProvider, *, now: datetime) -> None:
        """Revoke retained credentials and always delete the local vault record."""
        if self.vault is None:
            return
        stored = await self.vault.get_for_refresh(provider_account_id, now=now)
        try:
            if stored is not None:
                if stored.tokens.refresh_token is not None:
                    await provider.revoke(
                        stored.tokens.refresh_token,
                        token_type_hint="refresh_token",  # noqa: S106 - standardized OAuth token kind
                    )
                await provider.revoke(
                    stored.tokens.access_token,
                    token_type_hint="access_token",  # noqa: S106 - standardized OAuth token kind
                )
        finally:
            await self.vault.delete(provider_account_id)


def _identity_key(identity: ProviderIdentity) -> tuple[str, str, str]:
    if identity.__class__ is not ProviderIdentity:
        raise OAuthAccountError
    return identity.provider, identity.issuer, identity.subject


def _validate_vault_input(provider_account_id: str, tokens: ProviderTokenSet, now: datetime) -> None:
    if not _strict_text(provider_account_id) or tokens.__class__ is not ProviderTokenSet or not _aware(now):
        raise OAuthAccountError


def _encode_tokens(tokens: ProviderTokenSet) -> bytes:
    document = {
        "access_token": tokens.access_token.get_secret_value(),
        "token_type": tokens.token_type,
        "scopes": sorted(tokens.scopes),
        "expires_at": tokens.expires_at.isoformat(),
        "refresh_token": tokens.refresh_token.get_secret_value() if tokens.refresh_token is not None else None,
        "id_token": tokens.id_token.get_secret_value() if tokens.id_token is not None else None,
    }
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def _decode_tokens(body: bytes) -> ProviderTokenSet:
    document = json.loads(body, object_pairs_hook=unique_object, parse_constant=reject_non_finite)
    validate_depth(document, maximum=_MAXIMUM_VAULT_DOCUMENT_DEPTH)
    if not isinstance(document, dict):
        raise TypeError
    values = cast("dict[str, object]", document)
    scopes = values.get("scopes")
    scope_values = cast("list[object]", scopes)
    if not isinstance(scopes, list) or any(not _strict_text(scope) for scope in scope_values):
        raise ValueError
    return ProviderTokenSet(
        access_token=SecretStr(cast("str", values["access_token"])),
        token_type=cast("str", values["token_type"]),
        scopes=frozenset(cast("list[str]", scopes)),
        expires_at=datetime.fromisoformat(cast("str", values["expires_at"])),
        refresh_token=(
            SecretStr(cast("str", values["refresh_token"])) if values.get("refresh_token") is not None else None
        ),
        id_token=SecretStr(cast("str", values["id_token"])) if values.get("id_token") is not None else None,
    )


def _strict_text(value: object) -> bool:
    return isinstance(value, str) and value.__class__ is str and bool(value.strip())


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None
