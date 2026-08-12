"""Atomic provider-account lifecycle and encrypted token-vault contracts."""

import json
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum
from hashlib import sha256
from types import MappingProxyType
from typing import Protocol, cast, runtime_checkable

from anyio import Lock
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.providers._internal import reject_non_finite, unique_object, validate_depth
from litestar_security.providers.oauth._provider import (
    InvalidProviderGrantError,
    OAuthProvider,
    ProviderGrant,
    ProviderIdentity,
    ProviderTokenSet,
)
from litestar_security.providers.oauth._transactions import OAuthTransactionProtector, ProtectedOAuthSecret, SecretStr

__all__ = (
    "AccountLinkError",
    "InvalidProviderGrantError",
    "LinkedProviderAccount",
    "MemoryOAuthAccountStore",
    "OAuthAccountError",
    "OAuthAccountService",
    "OAuthAccountStore",
    "OAuthLinkProof",
    "OAuthLoginOutcome",
    "OAuthRevocationFailure",
    "ProviderTokenReference",
    "StoredProviderTokens",
    "UnlinkOutcome",
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
class OAuthLoginOutcome:
    """Atomic login result and first-provisioning signal."""

    linked: LinkedProviderAccount
    provisioned: bool


class UnlinkStatus(str, Enum):
    """Atomic provider unlink outcomes."""

    UNLINKED = "unlinked"
    NOT_FOUND = "not-found"
    FINAL_METHOD = "final-method"


@dataclass(frozen=True, slots=True)
class UnlinkOutcome:
    """Outcome of one atomic identity, login-method, and grant removal."""

    status: UnlinkStatus
    provider_account_id: str | None = None

    def __post_init__(self) -> None:
        """Require a provider account only for successful removal."""
        if self.status.__class__ is not UnlinkStatus or (self.status is UnlinkStatus.UNLINKED) != (
            self.provider_account_id is not None
        ):
            message = "OAuth unlink outcome is invalid"
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
class OAuthRevocationFailure:
    """Secret-free upstream revocation retry classification."""

    provider_account_id: str
    failed_token_types: frozenset[str]
    occurred_at: datetime


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

    async def login(  # noqa: PLR0913 - aggregate mutation inputs remain explicit
        self,
        identity: ProviderIdentity,
        grant: ProviderGrant,
        tokens: ProviderTokenSet,
        *,
        provision_unknown: bool,
        retain_tokens: bool,
        now: datetime,
    ) -> OAuthLoginOutcome:
        """Atomically resolve or provision, link, observe, and retain or discard tokens."""
        ...  # pragma: no cover

    async def get_tokens(self, provider_account_id: str, *, now: datetime) -> StoredProviderTokens | None:
        """Return decrypted provider tokens for the owning coordinator."""
        ...  # pragma: no cover

    async def link(  # noqa: PLR0913 - aggregate mutation inputs remain explicit
        self,
        account_id: str,
        identity: ProviderIdentity,
        grant: ProviderGrant,
        tokens: ProviderTokenSet,
        *,
        retain_tokens: bool,
        now: datetime,
    ) -> LinkedProviderAccount:
        """Atomically link an identity, grant, and optional retained tokens."""
        ...  # pragma: no cover

    async def upgrade(  # noqa: PLR0913 - aggregate mutation inputs remain explicit
        self,
        account_id: str,
        provider_account_id: str,
        identity: ProviderIdentity,
        grant: ProviderGrant,
        tokens: ProviderTokenSet,
        *,
        retain_tokens: bool,
        now: datetime,
    ) -> LinkedProviderAccount:
        """Atomically replace a grant and its newly exchanged tokens."""
        ...  # pragma: no cover

    async def unlink(
        self, account_id: str, provider: str, provider_account_id: str, *, require_remaining: bool, now: datetime
    ) -> UnlinkOutcome:
        """Atomically remove the link, grant, and retained tokens while preserving another method."""
        ...  # pragma: no cover

    async def replace_tokens(
        self, provider_account_id: str, *, expected_version: int, tokens: ProviderTokenSet, now: datetime
    ) -> bool:
        """Compare and replace retained tokens atomically."""
        ...  # pragma: no cover

    async def discard_tokens(self, provider_account_id: str, *, expected_version: int | None = None) -> bool:
        """Discard tokens, optionally only at one observed version."""
        ...  # pragma: no cover

    async def stage_revocation_retry(
        self, failure: OAuthRevocationFailure, tokens: ProviderTokenSet, *, expected_version: int
    ) -> bool:
        """Atomically move active tokens into durable revocation-retry state."""
        ...  # pragma: no cover

    async def resolve_provider_account(self, account_id: str, provider: str) -> LinkedProviderAccount | None:
        """Resolve one account-owned provider link without crossing ownership."""
        ...  # pragma: no cover


class OAuthAccountError(RuntimeError):
    """Stable secret-free account lifecycle failure."""

    def __init__(self, code: str = "oauth_account_denied") -> None:
        """Initialize one stable application-facing code."""
        self.code = code
        super().__init__("OAuth account operation denied")


class AccountLinkError(OAuthAccountError):
    """Reject a duplicate cross-account provider identity."""


class MemoryOAuthAccountStore:
    """Atomic in-memory reference store for provider account behavior."""

    __slots__ = ("_identity_index", "_links", "_lock", "_method_counts", "_next_account", "_retry_store", "_vault")

    def __init__(
        self,
        *,
        login_method_counts: Mapping[str, int] | None = None,
        provider: str = "example",
        client_id: str = "client",
        protector: OAuthTransactionProtector | None = None,
    ) -> None:
        """Create a store with authoritative total login-method counts.

        Args:
            login_method_counts: Existing local and provider methods per account.
            provider: Provider namespace used in token associated data.
            client_id: OAuth client identifier used in token associated data.
            protector: Optional encryption port enabling retained tokens.
        """
        counts = dict(login_method_counts or {})
        if any(not _strict_text(key) or value.__class__ is not int or value < 0 for key, value in counts.items()):
            raise ImproperlyConfiguredException(detail="OAuth login method counts are invalid")
        self._method_counts = counts
        self._identity_index: dict[tuple[str, str, str], str] = {}
        self._links: dict[str, LinkedProviderAccount] = {}
        self._lock = Lock()
        self._next_account = 1
        self._vault = (
            _MemoryTokenVault(provider=provider, client_id=client_id, protector=protector)
            if protector is not None
            else None
        )
        self._retry_store = _MemoryOAuthRevocationRetryStore(protector) if protector is not None else None

    async def login(  # noqa: PLR0913 - aggregate mutation inputs remain explicit
        self,
        identity: ProviderIdentity,
        grant: ProviderGrant,
        tokens: ProviderTokenSet,
        *,
        provision_unknown: bool,
        retain_tokens: bool = False,
        now: datetime,
    ) -> OAuthLoginOutcome:
        """Atomically resolve or provision one exact identity.

        Args:
            identity: Exact provider identity.
            grant: Provider-observed grant.
            tokens: Exchanged provider tokens.
            provision_unknown: Whether an unknown identity may create an account.
            retain_tokens: Whether the aggregate should retain the token set.
            now: Aware mutation time.

        Returns:
            The linked account and whether this call provisioned it.

        Raises:
            OAuthAccountError: If the identity is unknown and provisioning is disabled.
        """
        key = _identity_key(identity)
        if grant.__class__ is not ProviderGrant or not _aware(now):
            raise OAuthAccountError
        async with self._lock:
            provider_account_id = self._identity_index.get(key)
            if provider_account_id is not None:
                linked = replace(self._links[provider_account_id], grant=grant)
                self._links[provider_account_id] = linked
                outcome = OAuthLoginOutcome(linked=linked, provisioned=False)
                await self._retain_or_discard(linked.provider_account_id, tokens, retain_tokens=retain_tokens, now=now)
                return outcome
            if not provision_unknown:
                raise OAuthAccountError
            account_id = f"account-{self._next_account}"
            self._next_account += 1
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
            self._method_counts[account_id] = 1
            try:
                await self._retain_or_discard(linked.provider_account_id, tokens, retain_tokens=retain_tokens, now=now)
            except Exception:
                del self._identity_index[key]
                del self._links[linked.provider_account_id]
                del self._method_counts[account_id]
                self._next_account -= 1
                raise
            return OAuthLoginOutcome(linked=linked, provisioned=True)

    async def _retain_or_discard(
        self, provider_account_id: str, tokens: ProviderTokenSet, *, retain_tokens: bool, now: datetime
    ) -> None:
        if retain_tokens:
            if self._vault is None:
                raise OAuthAccountError(_VAULT_UNAVAILABLE)
            await self._vault.put(provider_account_id, tokens, now=now)
        elif self._vault is not None:
            await self._vault.delete(provider_account_id)

    async def get_tokens(self, provider_account_id: str, *, now: datetime) -> StoredProviderTokens | None:
        """Return retained tokens when configured."""
        return None if self._vault is None else await self._vault.get_for_refresh(provider_account_id, now=now)

    async def replace_tokens(
        self, provider_account_id: str, *, expected_version: int, tokens: ProviderTokenSet, now: datetime
    ) -> bool:
        """Compare and replace retained tokens."""
        return (
            False
            if self._vault is None
            else await self._vault.replace(
                provider_account_id, expected_version=expected_version, tokens=tokens, now=now
            )
        )

    async def discard_tokens(self, provider_account_id: str, *, expected_version: int | None = None) -> bool:
        """Discard retained tokens at an optional observed version."""
        if self._vault is None:
            return False
        if expected_version is not None:
            stored = await self._vault.get_for_refresh(provider_account_id, now=datetime.now().astimezone())
            if stored is None or stored.reference.version != expected_version:
                return False
        await self._vault.delete(provider_account_id)
        return True

    async def stage_revocation_retry(
        self, failure: OAuthRevocationFailure, tokens: ProviderTokenSet, *, expected_version: int
    ) -> bool:
        """Discard active tokens only when their observed version still matches."""
        if self._vault is None or self._retry_store is None:
            return False
        stored = await self._vault.get_for_refresh(failure.provider_account_id, now=failure.occurred_at)
        if stored is None or stored.reference.version != expected_version:
            return False
        await self._retry_store.schedule(failure, tokens)
        return await self.discard_tokens(failure.provider_account_id, expected_version=expected_version)

    async def resolve_provider_account(self, account_id: str, provider: str) -> LinkedProviderAccount | None:
        """Resolve one exact account-owned provider link."""
        if not _strict_text(account_id) or not _strict_text(provider):
            raise OAuthAccountError
        async with self._lock:
            matches = [
                linked
                for linked in self._links.values()
                if linked.account_id == account_id and linked.provider == provider
            ]
        if len(matches) > 1:
            raise OAuthAccountError
        return matches[0] if matches else None

    async def link(  # noqa: PLR0913 - aggregate mutation inputs remain explicit
        self,
        account_id: str,
        identity: ProviderIdentity,
        grant: ProviderGrant,
        tokens: ProviderTokenSet,
        *,
        retain_tokens: bool = False,
        now: datetime,
    ) -> LinkedProviderAccount:
        """Commit an exact identity and its token policy under one aggregate lock."""
        if not _strict_text(account_id) or not _aware(now):
            raise OAuthAccountError
        key = _identity_key(identity)
        async with self._lock:
            existing_id = self._identity_index.get(key)
            if existing_id is not None:
                existing = self._links[existing_id]
                if existing.account_id != account_id:
                    raise AccountLinkError
                linked = replace(existing, grant=grant)
            else:
                if any(
                    link.account_id == account_id and link.provider == identity.provider
                    for link in self._links.values()
                ):
                    raise AccountLinkError
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
            await self._retain_or_discard(linked.provider_account_id, tokens, retain_tokens=retain_tokens, now=now)
            self._identity_index[key] = linked.provider_account_id
            self._links[linked.provider_account_id] = linked
            if existing_id is None:
                self._method_counts[account_id] = self._method_counts.get(account_id, 0) + 1
            return linked

    async def upgrade(  # noqa: PLR0913 - aggregate mutation inputs remain explicit
        self,
        account_id: str,
        provider_account_id: str,
        identity: ProviderIdentity,
        grant: ProviderGrant,
        tokens: ProviderTokenSet,
        *,
        retain_tokens: bool,
        now: datetime,
    ) -> LinkedProviderAccount:
        """Commit one grant and the exchanged token policy together."""
        async with self._lock:
            linked = self._links.get(provider_account_id)
            if (
                linked is None
                or linked.account_id != account_id
                or _identity_key(identity) != (linked.provider, linked.issuer, linked.subject)
            ):
                raise OAuthAccountError
            updated = replace(linked, grant=grant)
            await self._retain_or_discard(provider_account_id, tokens, retain_tokens=retain_tokens, now=now)
            self._links[provider_account_id] = updated
            return updated

    async def unlink(
        self, account_id: str, provider: str, provider_account_id: str, *, require_remaining: bool, now: datetime
    ) -> UnlinkOutcome:
        """Remove one owned link and all retained credentials under the aggregate lock."""
        if not _strict_text(account_id) or not _strict_text(provider_account_id) or not _aware(now):
            raise OAuthAccountError
        async with self._lock:
            linked = self._links.get(provider_account_id)
            if linked is None or linked.account_id != account_id or linked.provider != provider:
                return UnlinkOutcome(UnlinkStatus.NOT_FOUND)
            count = self._method_counts.get(account_id, 0)
            if require_remaining and count <= 1:
                return UnlinkOutcome(UnlinkStatus.FINAL_METHOD)
            if self._vault is not None:
                await self._vault.delete(provider_account_id)
            del self._links[provider_account_id]
            del self._identity_index[(linked.provider, linked.issuer, linked.subject)]
            self._method_counts[account_id] = max(0, count - 1)
            return UnlinkOutcome(UnlinkStatus.UNLINKED, provider_account_id)


@dataclass(slots=True)
class _VaultRecord:
    protected: ProtectedOAuthSecret
    reference: ProviderTokenReference


class _MemoryTokenVault:
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


@dataclass(frozen=True, slots=True)
class _OAuthRevocationRetryRecord:
    """One encrypted retry payload paired with secret-free metadata."""

    failure: OAuthRevocationFailure
    protected: ProtectedOAuthSecret = field(repr=False)


class _MemoryOAuthRevocationRetryStore:
    """Lock-protected encrypted reference persistence for OAuth revocation retries."""

    __slots__ = ("_lock", "_protector", "_records")

    def __init__(self, protector: OAuthTransactionProtector) -> None:
        """Initialize an isolated retry store with the caller's AEAD protector.

        Args:
            protector: Protector used to encrypt each provider-account token set.

        Raises:
            ImproperlyConfiguredException: If ``protector`` does not implement the transaction protection protocol.
        """
        protector_value = cast("object", protector)
        if not isinstance(protector_value, OAuthTransactionProtector):
            raise ImproperlyConfiguredException(detail="OAuth revocation retry store configuration is invalid")
        self._protector = protector
        self._records: dict[str, _OAuthRevocationRetryRecord] = {}
        self._lock = Lock()

    @property
    def failures(self) -> Mapping[str, OAuthRevocationFailure]:
        """Return immutable, secret-free metadata for the current retry records.

        Returns:
            A copy of the current metadata indexed by provider account id.
        """
        return MappingProxyType({
            provider_account_id: record.failure for provider_account_id, record in self._records.items()
        })

    async def schedule(self, failure: OAuthRevocationFailure, tokens: ProviderTokenSet) -> None:
        """Encrypt and atomically replace retry material for one provider account.

        Args:
            failure: Secret-free upstream revocation failure metadata.
            tokens: The token set to retain only in encrypted form.

        Raises:
            OAuthAccountError: If encryption cannot preserve retry material.
        """
        provider_account_id = failure.provider_account_id
        if not _strict_text(provider_account_id) or tokens.__class__ is not ProviderTokenSet:
            raise OAuthAccountError
        key_version = self._protector.active_key_version
        try:
            protected = await self._protector.protect(
                _encode_tokens(tokens), associated_data=self._associated_data(provider_account_id, key_version)
            )
        except Exception as exc:
            raise OAuthAccountError(_VAULT_UNAVAILABLE) from exc
        async with self._lock:
            self._records[provider_account_id] = _OAuthRevocationRetryRecord(failure, protected)

    @staticmethod
    def _associated_data(provider_account_id: str, key_version: str) -> bytes:
        """Return provider-account-bound associated data for retry material.

        Args:
            provider_account_id: Exact provider account owning the retry material.
            key_version: Version of the key that protects the token set.

        Returns:
            Stable domain-separated associated data.
        """
        return f"oauth-revocation-retry-v1\0{provider_account_id}\0{key_version}".encode()


@dataclass(slots=True)
class _RefreshLock:
    lock: Lock = field(default_factory=Lock)
    references: int = 0


class OAuthAccountService:
    """Coordinate exact login/link/scope/vault behavior over atomic ports."""

    __slots__ = ("_refresh_locks", "_refresh_locks_guard", "provision_unknown", "store")

    def __init__(self, *, store: OAuthAccountStore, provision_unknown: bool = False) -> None:
        """Create the account lifecycle service.

        Args:
            store: Atomic provider-account store.
            provision_unknown: Whether the aggregate store may provision an unknown identity.
        """
        store_value = cast("object", store)
        if not isinstance(store_value, OAuthAccountStore) or provision_unknown.__class__ is not bool:
            raise ImproperlyConfiguredException(detail="OAuth account service configuration is invalid")
        self.store = store
        self.provision_unknown = provision_unknown
        self._refresh_locks: dict[str, _RefreshLock] = {}
        self._refresh_locks_guard = Lock()

    async def login(
        self,
        identity: ProviderIdentity,
        grant: ProviderGrant,
        tokens: ProviderTokenSet,
        *,
        retain_tokens: bool = False,
        now: datetime,
    ) -> OAuthLoginOutcome:
        """Delegate the complete login mutation to the aggregate store."""
        return await self.store.login(
            identity, grant, tokens, provision_unknown=self.provision_unknown, retain_tokens=retain_tokens, now=now
        )

    async def link(  # noqa: PLR0913 - coordinator keeps validation inputs explicit
        self,
        proof: OAuthLinkProof,
        identity: ProviderIdentity,
        grant: ProviderGrant,
        tokens: ProviderTokenSet,
        *,
        retain_tokens: bool = False,
        now: datetime,
    ) -> LinkedProviderAccount:
        """Link after exact fresh purpose and epoch validation."""
        if not proof.valid_for("oauth-link"):
            raise OAuthAccountError
        return await self.store.link(proof.account_id, identity, grant, tokens, retain_tokens=retain_tokens, now=now)

    async def unlink(
        self, proof: OAuthLinkProof, provider: str, provider_account_id: str, *, now: datetime
    ) -> UnlinkOutcome:
        """Atomically preserve a remaining login method, then discard tokens."""
        if not proof.valid_for("oauth-unlink"):
            raise OAuthAccountError
        return await self.store.unlink(proof.account_id, provider, provider_account_id, require_remaining=True, now=now)

    @staticmethod
    def missing_scopes(
        *, current: frozenset[str], requested: frozenset[str], allowed: frozenset[str]
    ) -> frozenset[str]:
        """Return only allowlisted scopes absent from the current grant."""
        if not requested.issubset(allowed):
            raise OAuthAccountError
        return requested.difference(current)

    async def apply_scope_upgrade(  # noqa: PLR0913 - coordinator keeps validation inputs explicit
        self,
        proof: OAuthLinkProof,
        provider_account_id: str,
        identity: ProviderIdentity,
        grant: ProviderGrant,
        tokens: ProviderTokenSet,
        *,
        required_scopes: frozenset[str],
        retain_tokens: bool = False,
        now: datetime,
    ) -> LinkedProviderAccount:
        """Record only the provider's actual grant after step-up."""
        if not proof.valid_for("oauth-scope-upgrade") or not required_scopes.issubset(grant.scopes):
            raise OAuthAccountError
        return await self.store.upgrade(
            proof.account_id, provider_account_id, identity, grant, tokens, retain_tokens=retain_tokens, now=now
        )

    async def refresh(self, provider_account_id: str, provider: OAuthProvider, *, now: datetime) -> ProviderTokenSet:
        """Single-flight refresh and optimistic rotation for one provider account."""
        observed = await self.store.get_tokens(provider_account_id, now=now)
        if observed is None or observed.tokens.refresh_token is None:
            raise OAuthAccountError(_REAUTHORIZATION_REQUIRED)
        entry = await self._acquire_refresh_lock(provider_account_id)
        try:
            async with entry.lock:
                stored = await self.store.get_tokens(provider_account_id, now=now)
                if stored is None or stored.tokens.refresh_token is None:
                    raise OAuthAccountError(_REAUTHORIZATION_REQUIRED)
                if stored.reference.version != observed.reference.version:
                    return stored.tokens
                try:
                    refreshed = await provider.refresh(
                        stored.tokens.refresh_token, current_scopes=stored.tokens.scopes, now=now
                    )
                except InvalidProviderGrantError:
                    await self.store.discard_tokens(provider_account_id, expected_version=stored.reference.version)
                    raise OAuthAccountError(_REAUTHORIZATION_REQUIRED) from None
                if not await self.store.replace_tokens(
                    provider_account_id, expected_version=stored.reference.version, tokens=refreshed, now=now
                ):
                    raise OAuthAccountError(_REFRESH_RACED)
                return refreshed
        finally:
            await self._release_refresh_lock(provider_account_id, entry)

    async def _acquire_refresh_lock(self, provider_account_id: str) -> "_RefreshLock":
        async with self._refresh_locks_guard:
            entry = self._refresh_locks.get(provider_account_id)
            if entry is None:
                entry = _RefreshLock()
                self._refresh_locks[provider_account_id] = entry
            entry.references += 1
            return entry

    async def _release_refresh_lock(self, provider_account_id: str, entry: "_RefreshLock") -> None:
        async with self._refresh_locks_guard:
            entry.references -= 1
            if entry.references == 0 and self._refresh_locks.get(provider_account_id) is entry:
                del self._refresh_locks[provider_account_id]

    async def revoke(self, provider_account_id: str, provider: OAuthProvider, *, now: datetime) -> None:
        """Revoke retained credentials without losing material needed for retry."""
        stored = await self.store.get_tokens(provider_account_id, now=now)
        failed: set[str] = set()
        if stored is not None:
            if stored.tokens.refresh_token is not None:
                try:
                    await provider.revoke(
                        stored.tokens.refresh_token,
                        token_type_hint="refresh_token",  # noqa: S106 - standardized OAuth token kind
                    )
                except Exception:  # noqa: BLE001 - attempt every credential and sanitize provider failure
                    failed.add("refresh_token")
            try:
                await provider.revoke(
                    stored.tokens.access_token,
                    token_type_hint="access_token",  # noqa: S106 - standardized OAuth token kind
                )
            except Exception:  # noqa: BLE001 - attempt every credential and sanitize provider failure
                failed.add("access_token")
            if failed:
                await self.store.stage_revocation_retry(
                    OAuthRevocationFailure(provider_account_id, frozenset(failed), now),
                    stored.tokens,
                    expected_version=stored.reference.version,
                )
                msg = "oauth_revocation_pending"
                raise OAuthAccountError(msg)
            await self.store.discard_tokens(provider_account_id, expected_version=stored.reference.version)


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
