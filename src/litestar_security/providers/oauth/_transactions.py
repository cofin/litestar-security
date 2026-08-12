"""Atomic OAuth transaction and dedicated browser-binding contracts."""

from base64 import urlsafe_b64encode
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
from hmac import compare_digest
from hmac import digest as hmac_digest
from secrets import token_bytes
from types import MappingProxyType
from typing import NoReturn, Protocol, cast, runtime_checkable
from urllib.parse import urlsplit

from anyio import Lock
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from litestar.datastructures import Cookie
from litestar.exceptions import ImproperlyConfiguredException

__all__ = (
    "OAUTH_BINDING_COOKIE_NAME",
    "AESGCMOAuthTransactionProtector",
    "InvalidOAuthCallback",
    "MemoryOAuthTransactionStore",
    "OAuthOperation",
    "OAuthRedirectPolicy",
    "OAuthTransaction",
    "OAuthTransactionProtector",
    "OAuthTransactionProtectorKey",
    "OAuthTransactionService",
    "OAuthTransactionStart",
    "OAuthTransactionStore",
    "OAuthTransactionUnavailable",
    "ProtectedOAuthSecret",
    "SecretStr",
    "oauth_binding_cookie",
    "pkce_s256",
)


OAUTH_BINDING_COOKIE_NAME = "__Host-litestar-security-oauth"
_DEFAULT_TRANSACTION_LIFETIME = timedelta(minutes=10)
_STATE_BYTES = 32
_BINDING_BYTES = 32
_PKCE_BYTES = 32
_NONCE_BYTES = 32
_MINIMUM_PEPPER_BYTES = 32
_MINIMUM_PKCE_CHARACTERS = 43
_MAXIMUM_PKCE_CHARACTERS = 128
_MAXIMUM_COOKIE_AGE = 600
_STATE_DIGEST_DOMAIN = b"litestar-security:oauth:state:v1\x00"
_BINDING_DIGEST_DOMAIN = b"litestar-security:oauth:binding:v1\x00"
_PROTECTED_SECRET_DOMAIN = b"litestar-security:oauth:transaction:v1\x00"
_PKCE_CHARACTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_AES_256_KEY_BYTES = 32
_AES_GCM_NONCE_BYTES = 12


class OAuthOperation(str, Enum):
    """Purpose bound to one OAuth authorization transaction."""

    LOGIN = "login"
    LINK = "link"
    SCOPE_UPGRADE = "scope-upgrade"


@dataclass(frozen=True, slots=True)
class SecretStr:
    """A string whose normal representations never reveal its value."""

    _value: str = field(repr=False)

    def __post_init__(self) -> None:
        """Require a non-empty exact string."""
        if self._value.__class__ is not str or not self._value:
            message = "Secret string must not be empty"
            raise ValueError(message)

    def __repr__(self) -> str:
        """Return a stable redacted representation."""
        return "SecretStr('**********')"

    def __str__(self) -> str:
        """Return a stable redacted string."""
        return "**********"

    def get_secret_value(self) -> str:
        """Return the secret to the narrow protocol boundary that needs it.

        Returns:
            The original secret string.
        """
        return self._value


@dataclass(frozen=True, slots=True)
class ProtectedOAuthSecret:
    """Opaque application-protected OAuth transaction secret."""

    ciphertext: bytes = field(repr=False)
    key_version: str

    def __post_init__(self) -> None:
        """Require non-empty ciphertext and a stable key version."""
        if (
            self.ciphertext.__class__ is not bytes
            or not self.ciphertext
            or self.key_version.__class__ is not str
            or not self.key_version.strip()
        ):
            message = "Protected OAuth secret requires ciphertext and a key version"
            raise ValueError(message)


@runtime_checkable
class OAuthTransactionProtector(Protocol):
    """Protect recoverable transaction secrets with application-owned keys."""

    @property
    def active_key_version(self) -> str:
        """Return the stable version used by the next protection operation."""
        ...  # pragma: no cover

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedOAuthSecret:
        """Protect one secret under exact transaction-associated data.

        Args:
            secret: The plaintext secret to protect.
            associated_data: The transaction identity and secret purpose.

        Returns:
            An opaque ciphertext envelope.
        """
        ...  # pragma: no cover

    async def unprotect(self, protected: ProtectedOAuthSecret, *, associated_data: bytes) -> bytes:
        """Recover one secret under its original transaction-associated data.

        Args:
            protected: The stored opaque envelope.
            associated_data: The transaction identity and secret purpose.

        Returns:
            The recovered plaintext for immediate protocol use.
        """
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class OAuthTransactionProtectorKey:
    """One AES-256-GCM OAuth transaction key selected by a non-secret version."""

    key_version: str
    key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Require a stable version and exact AES-256 key material."""
        if not _strict_text(self.key_version) or self.key.__class__ is not bytes or len(self.key) != _AES_256_KEY_BYTES:
            message = "OAuth transaction protector key requires a version and 32-byte key"
            raise ImproperlyConfiguredException(detail=message)


@dataclass(frozen=True, slots=True)
class AESGCMOAuthTransactionProtector:
    """Protect OAuth transaction secrets with AES-256-GCM application-owned keys."""

    active_key: OAuthTransactionProtectorKey = field(repr=False)
    retained_keys: tuple[OAuthTransactionProtectorKey, ...] = field(default=(), repr=False)
    entropy: Callable[[int], bytes] = field(default=token_bytes, repr=False, compare=False)
    _keys: Mapping[str, OAuthTransactionProtectorKey] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Compile a unique versioned key ring and validate the entropy source."""
        keys = (self.active_key, *self.retained_keys)
        if (
            any(key.__class__ is not OAuthTransactionProtectorKey for key in keys)
            or len({key.key_version for key in keys}) != len(keys)
            or not callable(self.entropy)
        ):
            message = "OAuth transaction protector requires unique keys and callable entropy"
            raise ImproperlyConfiguredException(detail=message)
        object.__setattr__(self, "_keys", {key.key_version: key for key in keys})

    @property
    def active_key_version(self) -> str:
        """Return the version used by the next protection operation."""
        return self.active_key.key_version

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedOAuthSecret:
        """Encrypt one transaction secret under exact associated data.

        Args:
            secret: Plaintext transaction secret bytes.
            associated_data: Unencrypted transaction and purpose binding.

        Returns:
            A versioned, nonce-prefixed ciphertext envelope.

        Raises:
            ValueError: If the entropy source does not return a 12-byte nonce.
        """
        nonce = self.entropy(_AES_GCM_NONCE_BYTES)
        if nonce.__class__ is not bytes or len(nonce) != _AES_GCM_NONCE_BYTES:
            message = "OAuth transaction protector entropy must return a 12-byte nonce"
            raise ValueError(message)
        ciphertext = nonce + AESGCM(self.active_key.key).encrypt(nonce, secret, associated_data)
        return ProtectedOAuthSecret(ciphertext=ciphertext, key_version=self.active_key.key_version)

    async def unprotect(self, protected: ProtectedOAuthSecret, *, associated_data: bytes) -> bytes:
        """Decrypt one envelope only under its original associated data.

        Args:
            protected: Versioned ciphertext envelope.
            associated_data: Exact unencrypted transaction and purpose binding.

        Returns:
            The authenticated plaintext bytes.

        Raises:
            ValueError: If the key version or ciphertext envelope is invalid.
            cryptography.exceptions.InvalidTag: If authentication fails.
        """
        key = self._keys.get(protected.key_version)
        if key is None or len(protected.ciphertext) <= _AES_GCM_NONCE_BYTES:
            message = "OAuth transaction protector envelope is invalid"
            raise ValueError(message)
        nonce, ciphertext = protected.ciphertext[:_AES_GCM_NONCE_BYTES], protected.ciphertext[_AES_GCM_NONCE_BYTES:]
        return AESGCM(key.key).decrypt(nonce, ciphertext, associated_data)


@dataclass(frozen=True, slots=True)
class OAuthTransaction:
    """Server-side state for one purpose-bound OAuth authorization request."""

    state_digest: bytes = field(repr=False)
    binding_digest: bytes = field(repr=False)
    operation: OAuthOperation
    provider: str
    expected_issuer: str | None
    redirect_uri: str
    return_to: str
    requested_scopes: frozenset[str]
    pkce_verifier: SecretStr = field(repr=False)
    nonce: SecretStr | None = field(default=None, repr=False)
    account_id: str | None = None
    session_binding: str | None = field(default=None, repr=False)
    security_epoch: int | None = None
    provider_account_id: str | None = None
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Reject malformed storage-facing transaction state."""
        if (
            self.state_digest.__class__ is not bytes
            or len(self.state_digest) != sha256().digest_size
            or self.binding_digest.__class__ is not bytes
            or len(self.binding_digest) != sha256().digest_size
            or self.operation.__class__ is not OAuthOperation
            or not _strict_text(self.provider)
            or self.requested_scopes.__class__ is not frozenset
            or any(not _strict_text(scope) for scope in self.requested_scopes)
            or self.pkce_verifier.__class__ is not SecretStr
            or (self.nonce is not None and self.nonce.__class__ is not SecretStr)
            or (self.expected_issuer is not None and not _strict_text(self.expected_issuer))
            or (self.account_id is not None and not _strict_text(self.account_id))
            or (self.session_binding is not None and not _strict_text(self.session_binding))
            or (
                self.security_epoch is not None
                and (self.security_epoch.__class__ is not int or self.security_epoch < 0)
            )
            or (self.provider_account_id is not None and not _strict_text(self.provider_account_id))
            or not _aware_time(self.expires_at)
        ):
            message = "OAuth transaction is invalid"
            raise ValueError(message)


@runtime_checkable
class OAuthTransactionStore(Protocol):
    """Persist transactions and consume a matching transaction atomically.

    Implementations must protect the recoverable PKCE verifier and nonce at
    rest. ``consume()`` must perform matching and deletion as one atomic
    operation so no two callbacks can receive the same transaction.
    """

    async def create(self, transaction: OAuthTransaction) -> None:
        """Persist one new transaction.

        Args:
            transaction: The validated server-side transaction.
        """
        ...  # pragma: no cover

    async def consume(
        self, *, state_digest: bytes, binding_digest: bytes, provider: str, now: datetime
    ) -> OAuthTransaction | None:
        """Atomically return and remove one exact, unexpired match.

        Args:
            state_digest: The state lookup digest.
            binding_digest: The dedicated browser-cookie digest.
            provider: The provider route receiving the callback.
            now: The authoritative callback time.

        Returns:
            The one consumed transaction, or ``None`` for every lookup miss.
        """
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class _StoredOAuthTransaction:
    transaction: OAuthTransaction
    pkce_verifier: ProtectedOAuthSecret
    nonce: ProtectedOAuthSecret | None


class MemoryOAuthTransactionStore:
    """Atomic in-memory reference store with protected recoverable secrets."""

    __slots__ = ("_capacity", "_clock", "_lock", "_protector", "_records")

    def __init__(
        self,
        *,
        protector: OAuthTransactionProtector,
        capacity: int = 1_024,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize the reference store.

        Args:
            protector: Application-owned transaction secret protection.
            capacity: Maximum number of live transactions retained.
            clock: Aware time source used for bounded expiry cleanup.

        Raises:
            ImproperlyConfiguredException: If the protector contract is absent.
        """
        protector_value = cast("object", protector)
        if (
            not isinstance(protector_value, OAuthTransactionProtector)
            or capacity.__class__ is not int
            or capacity < 1
            or (clock is not None and not callable(clock))
        ):
            message = "OAuth transaction protector must implement OAuthTransactionProtector"
            raise ImproperlyConfiguredException(detail=message)
        self._protector = protector
        self._capacity = capacity
        self._clock = clock
        self._records: dict[tuple[bytes, bytes, str], _StoredOAuthTransaction] = {}
        self._lock = Lock()

    async def create(self, transaction: OAuthTransaction) -> None:
        """Protect and persist one new transaction.

        Args:
            transaction: The validated server-side transaction.

        Raises:
            ValueError: If an identical transaction lookup already exists.
        """
        associated_data = _associated_data(transaction)
        pkce_verifier = await self._protector.protect(
            transaction.pkce_verifier.get_secret_value().encode("ascii"), associated_data=associated_data + b"pkce"
        )
        nonce = (
            await self._protector.protect(
                transaction.nonce.get_secret_value().encode("ascii"), associated_data=associated_data + b"nonce"
            )
            if transaction.nonce is not None
            else None
        )
        redacted = _replace_secrets(transaction, pkce_verifier=SecretStr("*"), nonce=None)
        key = (transaction.state_digest, transaction.binding_digest, transaction.provider)
        async with self._lock:
            if self._clock is not None:
                now = self._clock()
                if not _aware_time(now):
                    message = "OAuth transaction store clock must return aware time"
                    raise ValueError(message)
                expired = tuple(key for key, stored in self._records.items() if now >= stored.transaction.expires_at)
                for expired_key in expired:
                    del self._records[expired_key]
            if key in self._records:
                message = "OAuth transaction already exists"
                raise ValueError(message)
            if len(self._records) >= self._capacity:
                message = "OAuth transaction store capacity reached"
                raise OverflowError(message)
            self._records[key] = _StoredOAuthTransaction(transaction=redacted, pkce_verifier=pkce_verifier, nonce=nonce)

    async def consume(
        self, *, state_digest: bytes, binding_digest: bytes, provider: str, now: datetime
    ) -> OAuthTransaction | None:
        """Atomically return and remove one exact, unexpired match.

        Args:
            state_digest: The state lookup digest.
            binding_digest: The dedicated browser-cookie digest.
            provider: The provider route receiving the callback.
            now: The authoritative callback time.

        Returns:
            The one consumed transaction, or ``None`` for every lookup miss.
        """
        key = (state_digest, binding_digest, provider)
        async with self._lock:
            expired = tuple(key for key, value in self._records.items() if now >= value.transaction.expires_at)
            for expired_key in expired:
                del self._records[expired_key]
            stored = self._records.pop(key, None)
        if stored is None or now >= stored.transaction.expires_at:
            return None
        associated_data = _associated_data(stored.transaction)
        pkce_verifier = await self._protector.unprotect(stored.pkce_verifier, associated_data=associated_data + b"pkce")
        nonce = (
            await self._protector.unprotect(stored.nonce, associated_data=associated_data + b"nonce")
            if stored.nonce is not None
            else None
        )
        return _replace_secrets(
            stored.transaction,
            pkce_verifier=SecretStr(pkce_verifier.decode("ascii")),
            nonce=SecretStr(nonce.decode("ascii")) if nonce is not None else None,
        )


class InvalidOAuthCallback(RuntimeError):  # noqa: N818 - public domain outcome is intentionally adjective-first
    """Reject every invalid OAuth callback with one stable public outcome."""

    def __init__(self) -> None:
        """Initialize a generic secret-free failure."""
        super().__init__("OAuth callback is invalid")


class OAuthTransactionUnavailable(RuntimeError):  # noqa: N818 - matches the established VerificationUnavailable outcome
    """Indicate that transaction persistence or protection is unavailable."""

    def __init__(self) -> None:
        """Initialize a stable secret-free failure."""
        super().__init__("OAuth transaction service is unavailable")


@dataclass(frozen=True, slots=True)
class OAuthRedirectPolicy:
    """Configured exact callback and same-origin return destinations."""

    callback_uris: Mapping[str, frozenset[str]]
    return_to: frozenset[str] = frozenset({"/"})
    allow_insecure_localhost: bool = False

    def __post_init__(self) -> None:
        """Normalize and validate every configured destination."""
        normalized: dict[str, frozenset[str]] = {}
        callback_origins: set[str] = set()
        callback_uris_value = cast("object", self.callback_uris)
        if not isinstance(callback_uris_value, Mapping) or not self.callback_uris:
            message = "OAuth callback URI configuration must not be empty"
            raise ImproperlyConfiguredException(detail=message)
        for provider, uris in self.callback_uris.items():
            if (
                not _strict_text(provider)
                or provider != provider.strip()
                or uris.__class__ is not frozenset
                or not uris
            ):
                message = "OAuth callback URI configuration is invalid"
                raise ImproperlyConfiguredException(detail=message)
            for uri in uris:
                callback_origins.add(_configured_absolute_uri(uri, allow_localhost=self.allow_insecure_localhost))
            normalized[provider] = uris
        if self.return_to.__class__ is not frozenset or not self.return_to:
            message = "OAuth return destination configuration must not be empty"
            raise ImproperlyConfiguredException(detail=message)
        for destination in self.return_to:
            _configured_return_to(destination, callback_origins=callback_origins)
        object.__setattr__(self, "callback_uris", MappingProxyType(normalized))

    def validate(self, *, provider: str, redirect_uri: str, return_to: str) -> None:
        """Require exact configured callback and return destinations.

        Args:
            provider: The statically configured provider name.
            redirect_uri: The exact callback URI sent to the provider.
            return_to: The server-side post-login destination.

        Raises:
            InvalidOAuthCallback: If any value is absent or not an exact match.
        """
        configured = self.callback_uris.get(provider)
        if configured is None or redirect_uri not in configured or return_to not in self.return_to:
            raise InvalidOAuthCallback


@dataclass(frozen=True, slots=True)
class OAuthTransactionStart:
    """Fresh browser-facing material plus its server-side transaction."""

    state: SecretStr = field(repr=False)
    browser_binding: SecretStr = field(repr=False)
    pkce_challenge: str
    nonce: SecretStr | None = field(repr=False)
    transaction: OAuthTransaction


@dataclass(frozen=True, slots=True)
class OAuthTransactionService:
    """Generate, persist, and atomically consume OAuth transactions."""

    store: OAuthTransactionStore
    pepper: bytes = field(repr=False)
    redirects: OAuthRedirectPolicy
    lifetime: timedelta = _DEFAULT_TRANSACTION_LIFETIME
    entropy: Callable[[int], bytes] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate strong explicit configuration."""
        store_value = cast("object", self.store)
        if not isinstance(store_value, OAuthTransactionStore):
            message = "OAuth transaction store must implement OAuthTransactionStore"
            raise ImproperlyConfiguredException(detail=message)
        if self.pepper.__class__ is not bytes or len(self.pepper) < _MINIMUM_PEPPER_BYTES:
            message = "OAuth transaction pepper must contain at least 32 bytes"
            raise ImproperlyConfiguredException(detail=message)
        if self.redirects.__class__ is not OAuthRedirectPolicy:
            message = "OAuth redirect policy is invalid"
            raise ImproperlyConfiguredException(detail=message)
        if not timedelta() < self.lifetime <= _DEFAULT_TRANSACTION_LIFETIME:
            message = "OAuth transaction lifetime must be positive and at most ten minutes"
            raise ImproperlyConfiguredException(detail=message)
        entropy_value: object = self.entropy
        if entropy_value is not None and not callable(entropy_value):
            message = "OAuth transaction entropy must be callable"
            raise ImproperlyConfiguredException(detail=message)
        if self.entropy is None:
            object.__setattr__(self, "entropy", token_bytes)

    async def start(  # noqa: PLR0913 - every security binding is explicit
        self,
        *,
        operation: OAuthOperation,
        provider: str,
        redirect_uri: str,
        return_to: str,
        requested_scopes: frozenset[str],
        now: datetime,
        include_nonce: bool,
        expected_issuer: str | None = None,
        account_id: str | None = None,
        session_binding: str | None = None,
        browser_binding: SecretStr | None = None,
        security_epoch: int | None = None,
        provider_account_id: str | None = None,
    ) -> OAuthTransactionStart:
        """Create and persist one independent browser transaction.

        Args:
            operation: The exact login, link, or scope-upgrade purpose.
            provider: The configured provider receiving the authorization request.
            redirect_uri: The configured exact callback URI.
            return_to: The configured server-side post-login destination.
            requested_scopes: The immutable provider scope request.
            now: The authoritative creation time.
            include_nonce: Whether the provider uses an OIDC nonce.
            expected_issuer: The fixed issuer expected on callback.
            account_id: The account bound to a link or scope upgrade.
            session_binding: The optional Litestar session binding.
            browser_binding: An existing dedicated browser binding to reuse
                across concurrent transactions.
            security_epoch: Authoritative epoch bound by consumed step-up.
            provider_account_id: Provider link targeted by scope upgrade.

        Returns:
            Browser-facing state, binding, challenge, nonce, and stored transaction.

        Raises:
            InvalidOAuthCallback: If redirect or transaction inputs are invalid.
            OAuthTransactionUnavailable: If entropy, protection, or persistence fails.
        """
        self.redirects.validate(provider=provider, redirect_uri=redirect_uri, return_to=return_to)
        if (
            operation.__class__ is not OAuthOperation
            or requested_scopes.__class__ is not frozenset
            or any(not _strict_text(scope) for scope in requested_scopes)
            or not _aware_time(now)
        ):
            raise InvalidOAuthCallback
        try:
            entropy = cast("Callable[[int], bytes]", self.entropy)
            state = SecretStr(_encode_random(_entropy(entropy, _STATE_BYTES)))
            if browser_binding is None:
                browser_binding = SecretStr(_encode_random(_entropy(entropy, _BINDING_BYTES)))
            elif _callback_secret(browser_binding) is None:
                raise ValueError  # noqa: TRY301 - normalize invalid caller-supplied binding through one failure path
            verifier = SecretStr(_encode_random(_entropy(entropy, _PKCE_BYTES)))
            nonce = SecretStr(_encode_random(_entropy(entropy, _NONCE_BYTES))) if include_nonce else None
            transaction = OAuthTransaction(
                state_digest=self._digest(_STATE_DIGEST_DOMAIN, state),
                binding_digest=self._digest(_BINDING_DIGEST_DOMAIN, browser_binding),
                operation=operation,
                provider=provider,
                expected_issuer=expected_issuer,
                redirect_uri=redirect_uri,
                return_to=return_to,
                requested_scopes=requested_scopes,
                pkce_verifier=verifier,
                nonce=nonce,
                account_id=account_id,
                session_binding=session_binding,
                security_epoch=security_epoch,
                provider_account_id=provider_account_id,
                expires_at=now + self.lifetime,
            )
            await self.store.create(transaction)
        except Exception:  # noqa: BLE001 - sanitize entropy, protector, and application-store failures
            raise OAuthTransactionUnavailable from None
        return OAuthTransactionStart(
            state=state,
            browser_binding=browser_binding,
            pkce_challenge=pkce_s256(verifier),
            nonce=nonce,
            transaction=transaction,
        )

    async def consume(  # noqa: PLR0913 - every callback binding is explicit
        self,
        *,
        state: SecretStr | str,
        browser_binding: SecretStr | str,
        provider: str,
        operation: OAuthOperation | None,
        session_binding: str | None,
        now: datetime,
    ) -> OAuthTransaction:
        """Atomically consume one exact callback transaction.

        Args:
            state: The provider-returned opaque state.
            browser_binding: The dedicated cookie value.
            provider: The provider route receiving the callback.
            operation: The operation expected by that route, or ``None`` when a
                shared callback dispatches from the consumed transaction.
            session_binding: The optional current Litestar session binding.
            now: The authoritative callback time.

        Returns:
            The consumed, recovered transaction.

        Raises:
            InvalidOAuthCallback: For every absent, expired, replayed, or mismatched callback.
            OAuthTransactionUnavailable: If persistence or protection fails.
        """
        state_value = _callback_secret(state)
        binding_value = _callback_secret(browser_binding)
        if (
            state_value is None
            or binding_value is None
            or not _strict_text(provider)
            or (operation is not None and operation.__class__ is not OAuthOperation)
            or not _aware_time(now)
        ):
            raise InvalidOAuthCallback
        try:
            transaction = await self.store.consume(
                state_digest=self._digest(_STATE_DIGEST_DOMAIN, state_value),
                binding_digest=self._digest(_BINDING_DIGEST_DOMAIN, binding_value),
                provider=provider,
                now=now,
            )
        except Exception:  # noqa: BLE001 - sanitize protector and application-store failures
            raise OAuthTransactionUnavailable from None
        if (
            transaction is None
            or (operation is not None and transaction.operation is not operation)
            or not _session_matches(transaction.session_binding, session_binding)
        ):
            raise InvalidOAuthCallback
        return transaction

    def _digest(self, domain: bytes, secret: SecretStr) -> bytes:
        return hmac_digest(self.pepper, domain + secret.get_secret_value().encode("ascii"), sha256)


def pkce_s256(verifier: SecretStr | str) -> str:
    """Build an RFC 7636 S256 challenge from one strict verifier.

    Args:
        verifier: A 43-128 character PKCE verifier.

    Returns:
        The unpadded base64url SHA-256 challenge.

    Raises:
        ValueError: If the verifier is not canonical PKCE material.
    """
    value = verifier.get_secret_value() if isinstance(verifier, SecretStr) else verifier
    if (
        value.__class__ is not str
        or not _MINIMUM_PKCE_CHARACTERS <= len(value) <= _MAXIMUM_PKCE_CHARACTERS
        or any(character not in _PKCE_CHARACTERS for character in value)
    ):
        message = "PKCE verifier must contain 43-128 unreserved ASCII characters"
        raise ValueError(message)
    return _encode_random(sha256(value.encode("ascii")).digest())


def oauth_binding_cookie(binding: SecretStr | str, *, max_age: int = 600) -> Cookie:
    """Build the dedicated host-only OAuth browser-binding cookie.

    Args:
        binding: The fresh browser-binding value.
        max_age: The bounded cookie lifetime in seconds.

    Returns:
        A secure native Litestar cookie value.

    Raises:
        ValueError: If the cookie value or lifetime is invalid.
    """
    value = binding.get_secret_value() if isinstance(binding, SecretStr) else binding
    if (
        value.__class__ is not str
        or not value
        or max_age.__class__ is not int
        or not 0 < max_age <= _MAXIMUM_COOKIE_AGE
    ):
        message = "OAuth binding cookie value or lifetime is invalid"
        raise ValueError(message)
    return Cookie(
        key=OAUTH_BINDING_COOKIE_NAME,
        value=value,
        max_age=max_age,
        secure=True,
        httponly=True,
        samesite="lax",
        path="/",
        domain=None,
    )


def _configured_absolute_uri(value: str, *, allow_localhost: bool) -> str:
    if value.__class__ is not str or not value or value != value.strip() or "*" in value or "\\" in value:
        _raise_redirect_config()
    try:
        split = urlsplit(value)
        hostname = split.hostname
        port = split.port
    except ValueError:
        _raise_redirect_config()
    local = hostname in {"localhost", "127.0.0.1", "::1"}
    if (
        not split.scheme
        or not split.netloc
        or split.username is not None
        or split.password is not None
        or split.fragment
        or hostname is None
        or (split.scheme != "https" and not (allow_localhost and local and split.scheme == "http"))
    ):
        _raise_redirect_config()
    default_port = 443 if split.scheme == "https" else 80
    authority_host = f"[{hostname.lower()}]" if ":" in hostname else hostname.lower()
    authority = authority_host if port in {None, default_port} else f"{authority_host}:{port}"
    return f"{split.scheme}://{authority}"


def _configured_return_to(value: str, *, callback_origins: set[str]) -> None:
    if value.__class__ is not str or not value or value != value.strip() or "*" in value or "\\" in value:
        _raise_redirect_config()
    split = urlsplit(value)
    if split.fragment or split.username is not None or split.password is not None:
        _raise_redirect_config()
    if not split.scheme and not split.netloc:
        if not value.startswith("/") or value.startswith("//"):
            _raise_redirect_config()
        return
    origin = _configured_absolute_uri(value, allow_localhost=False)
    if origin not in callback_origins:
        _raise_redirect_config()


def _raise_redirect_config() -> NoReturn:
    message = "OAuth redirect configuration requires exact secure destinations"
    raise ImproperlyConfiguredException(detail=message)


def _replace_secrets(
    transaction: OAuthTransaction, *, pkce_verifier: SecretStr, nonce: SecretStr | None
) -> OAuthTransaction:
    return OAuthTransaction(
        state_digest=transaction.state_digest,
        binding_digest=transaction.binding_digest,
        operation=transaction.operation,
        provider=transaction.provider,
        expected_issuer=transaction.expected_issuer,
        redirect_uri=transaction.redirect_uri,
        return_to=transaction.return_to,
        requested_scopes=transaction.requested_scopes,
        pkce_verifier=pkce_verifier,
        nonce=nonce,
        account_id=transaction.account_id,
        session_binding=transaction.session_binding,
        security_epoch=transaction.security_epoch,
        provider_account_id=transaction.provider_account_id,
        expires_at=transaction.expires_at,
    )


def _associated_data(transaction: OAuthTransaction) -> bytes:
    return (
        _PROTECTED_SECRET_DOMAIN
        + transaction.state_digest
        + transaction.binding_digest
        + transaction.provider.encode("utf-8")
        + b"\x00"
    )


def _callback_secret(value: SecretStr | str) -> SecretStr | None:
    text = value.get_secret_value() if isinstance(value, SecretStr) else value
    if (
        text.__class__ is not str
        or len(text) != _MINIMUM_PKCE_CHARACTERS
        or any(character not in _PKCE_CHARACTERS for character in text)
    ):
        return None
    return SecretStr(text)


def _session_matches(stored: str | None, presented: str | None) -> bool:
    if stored is None or presented is None:
        return stored is presented
    return compare_digest(stored.encode("utf-8"), presented.encode("utf-8"))


def _entropy(source: Callable[[int], bytes], length: int) -> bytes:
    value = source(length)
    if value.__class__ is not bytes or len(value) != length:
        raise ValueError
    return value


def _encode_random(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _strict_text(value: object) -> bool:
    return isinstance(value, str) and value.__class__ is str and bool(value.strip())


def _aware_time(value: object) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None
