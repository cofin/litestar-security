"""Explicit session, token, and hybrid local-authentication profiles."""

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import timedelta
from hashlib import sha256
from hmac import digest as hmac_digest
from logging import getLogger
from typing import TYPE_CHECKING, Any, Generic, TypeVar, cast

from litestar import Router
from litestar.connection import ASGIConnection
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security._docs import LOCAL_TAG_KEYS, RouteDocs, resolve_tags
from litestar_security.accounts._access_tokens import (
    LocalAccessTokenIssuer,
    LocalAccessVerifier,
    LocalBearerIdentityResolver,
    validate_access_token_lifetime,
)
from litestar_security.accounts._auth_service import LocalAuthService, trusted_client_key
from litestar_security.accounts._login import PasswordLoginService, PasswordReauthenticationService
from litestar_security.accounts._mfa import MFAService
from litestar_security.accounts._mfa_login import MFALoginChallengeStore, MFALoginService
from litestar_security.accounts._passwords import Argon2PasswordHasher, PasswordHasher, PasswordPolicy
from litestar_security.accounts._purpose_tokens import PurposeTokenCodec
from litestar_security.accounts._rate_limits import RateLimiter, RateLimitGuard, StoreRateLimiter
from litestar_security.accounts._receipts import RefreshReceiptKey, RefreshReceiptSealer
from litestar_security.accounts._records import (
    LocalAuthMode,
    NoOpSecurityEventSink,
    RegistrationMode,
    SecurityEventSink,
)
from litestar_security.accounts._recovery import PasswordChangeService, RecoveryTokenService
from litestar_security.accounts._refresh import RefreshTokenFamilyStore, RefreshTokenService
from litestar_security.accounts._refresh_tokens import RefreshTokenCodec
from litestar_security.accounts._registration import RegistrationService, VerificationTokenService
from litestar_security.accounts._sessions import (
    NativeSessionAuth,
    NativeSessionStore,
    SessionBindingConfig,
    SessionRegistry,
    UserAuthSessionResolver,
)
from litestar_security.accounts._stores import (
    AccountLookup,
    LocalAccountCapabilities,
    LoginMethodStore,
    PasswordCredentialStore,
    RecoveryTokenStore,
    RegistrationPolicy,
    RegistrationStore,
    SecurityEpochStore,
    VerificationTokenStore,
)
from litestar_security.accounts.controllers import build_local_auth_routes
from litestar_security.providers.jwt import BearerSlotSelector, BearerTokenSlot, JWTValidationConfig, LocalKeyRing
from litestar_security.schema import WirePolicy

if TYPE_CHECKING:
    from litestar.openapi.spec import Tag
    from litestar.stores.registry import StoreRegistry

    from litestar_security.config import MFAConfig

__all__ = ("LocalAuth", "LocalAuthConfig", "LocalAuthSecrets", "LocalAuthService", "trusted_client_key")

UserT = TypeVar("UserT")
_ASCII_CONTROL_LIMIT = 32
_DEFAULT_ACCESS_TOKEN_LIFETIME = timedelta(minutes=10)
_DEFAULT_LOCAL_CLIENT_ID = "local"
_DISABLED_REGISTRATION = RegistrationPolicy.disabled()
_RATE_LIMIT_PEPPER_LABEL = b"litestar-security/rate-limit/pepper"
_MFA_LOGIN_PEPPER_LABEL = b"litestar-security/mfa-login-challenge/pepper"
_LOGGER = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class LocalAuthSecrets:
    """Explicit stable cryptographic inputs for local lifecycle routes."""

    purpose_tokens: PurposeTokenCodec = field(repr=False)
    refresh_codec: RefreshTokenCodec | None = field(default=None, repr=False)
    refresh_receipts: RefreshReceiptSealer | None = field(default=None, repr=False)
    rate_limit_pepper: bytes = field(init=False, repr=False, compare=False)
    mfa_login_pepper: bytes = field(init=False, repr=False, compare=False)

    @classmethod
    def session(cls, *, purpose_token_pepper: bytes) -> "LocalAuthSecrets":
        """Build the stable secrets required by session-only local authentication.

        Args:
            purpose_token_pepper: The pepper for verification, recovery, and
                invitation token digests. At least 32 bytes.

        Returns:
            Secrets sufficient for a session profile.
        """
        return cls(purpose_tokens=PurposeTokenCodec(purpose_token_pepper))

    @classmethod
    def tokens(
        cls,
        *,
        purpose_token_pepper: bytes,
        refresh_token_pepper: bytes,
        active_receipt_key_id: str,
        active_receipt_key: bytes,
        retained_receipt_keys: tuple[RefreshReceiptKey, ...] = (),
    ) -> "LocalAuthSecrets":
        """Build the stable secrets required by token or hybrid local authentication.

        Args:
            purpose_token_pepper: The pepper for verification, recovery, and
                invitation token digests. At least 32 bytes.
            refresh_token_pepper: The pepper for refresh-token digests. At least 32 bytes.
            active_receipt_key_id: The identifier of the key sealing new receipts.
            active_receipt_key: The key sealing new receipts.
            retained_receipt_keys: Superseded keys kept so receipts sealed before a
                rotation can still be opened.

        Returns:
            Secrets sufficient for a token or hybrid profile.
        """
        return cls(
            purpose_tokens=PurposeTokenCodec(purpose_token_pepper),
            refresh_codec=RefreshTokenCodec(refresh_token_pepper),
            refresh_receipts=RefreshReceiptSealer(
                active_key=RefreshReceiptKey(active_receipt_key_id, active_receipt_key),
                retained_keys=retained_receipt_keys,
            ),
        )

    def __post_init__(self) -> None:
        """Require exact codecs and a complete optional refresh pair."""
        if self.purpose_tokens.__class__ is not PurposeTokenCodec:
            msg = "Local authentication purpose tokens must be a PurposeTokenCodec"
            raise ImproperlyConfiguredException(detail=msg)
        has_refresh_codec = self.refresh_codec is not None
        has_refresh_receipts = self.refresh_receipts is not None
        if has_refresh_codec != has_refresh_receipts:
            msg = "Local authentication refresh codec and receipts must be configured together"
            raise ImproperlyConfiguredException(detail=msg)
        if has_refresh_codec and self.refresh_codec.__class__ is not RefreshTokenCodec:
            msg = "Local authentication refresh codec must be a RefreshTokenCodec"
            raise ImproperlyConfiguredException(detail=msg)
        if has_refresh_receipts and self.refresh_receipts.__class__ is not RefreshReceiptSealer:
            msg = "Local authentication refresh receipts must be a RefreshReceiptSealer"
            raise ImproperlyConfiguredException(detail=msg)
        # Derived rather than configured: rate-limit buckets need a stable secret, and
        # asking for a second pepper would make the common setup harder without making
        # it safer. Domain separation keeps this value unusable as a purpose-token key.
        object.__setattr__(
            self, "rate_limit_pepper", hmac_digest(self.purpose_tokens.pepper, _RATE_LIMIT_PEPPER_LABEL, sha256)
        )
        object.__setattr__(
            self, "mfa_login_pepper", hmac_digest(self.purpose_tokens.pepper, _MFA_LOGIN_PEPPER_LABEL, sha256)
        )


@dataclass(frozen=True, slots=True)
class LocalAuthConfig(Generic[UserT]):
    """Explicit local-authentication transport and capability selection."""

    mode: LocalAuthMode
    accounts: LocalAccountCapabilities[UserT] = field(repr=False)
    secrets: LocalAuthSecrets = field(repr=False)
    registration: RegistrationPolicy
    route_prefix: str
    register_routes: bool = True
    binding: SessionBindingConfig | None = field(default=None, repr=False)
    key_ring: LocalKeyRing | None = field(default=None, repr=False)
    token_audience: str | None = None
    token_client_id: str = _DEFAULT_LOCAL_CLIENT_ID
    access_token_lifetime: timedelta = _DEFAULT_ACCESS_TOKEN_LIFETIME
    password_hasher: PasswordHasher = field(default_factory=Argon2PasswordHasher, repr=False, compare=False)
    password_policy: PasswordPolicy = field(default_factory=PasswordPolicy, repr=False)
    session_auth: NativeSessionAuth[UserT] | None = field(default=None, repr=False, compare=False)
    session_resolver: UserAuthSessionResolver[UserT] | None = field(default=None, repr=False, compare=False)
    rate_limiter: RateLimiter | None = field(default=None, repr=False, compare=False)
    events: SecurityEventSink = field(default_factory=NoOpSecurityEventSink, repr=False, compare=False)
    client_key: "Callable[[ASGIConnection[Any, Any, Any, Any]], str | None]" = field(
        default=trusted_client_key, repr=False, compare=False
    )
    docs: RouteDocs = field(default_factory=RouteDocs, repr=False)
    rate_limits: RateLimitGuard = field(init=False, repr=False, compare=False)
    password_login: PasswordLoginService[UserT] = field(init=False, repr=False, compare=False)
    access_token_issuer: LocalAccessTokenIssuer[UserT] | None = field(
        init=False, default=None, repr=False, compare=False
    )
    bearer_slot: BearerTokenSlot | None = field(init=False, default=None, repr=False, compare=False)
    bearer_resolver: LocalBearerIdentityResolver[UserT] | None = field(
        init=False, default=None, repr=False, compare=False
    )
    local_auth_service: LocalAuthService[UserT] = field(init=False, repr=False, compare=False)
    mfa_login: "MFALoginService | None" = field(init=False, default=None, repr=False, compare=False)
    _mfa_login_config: object | None = field(init=False, default=None, repr=False, compare=False)
    _route_handlers: "dict[WirePolicy, tuple[Router, ...]]" = field(
        init=False, default_factory=dict[WirePolicy, "tuple[Router, ...]"], repr=False, compare=False
    )

    def __post_init__(self) -> None:  # noqa: C901, PLR0912, PLR0915 - transport invariants remain centralized
        """Validate transport-specific values and structural capabilities."""
        if self.mode.__class__ is not LocalAuthMode:
            msg = "Local authentication mode must be a LocalAuthMode"
            raise ImproperlyConfiguredException(detail=msg)
        if self.registration.__class__ is not RegistrationPolicy:
            msg = "Local authentication registration must be a RegistrationPolicy"
            raise ImproperlyConfiguredException(detail=msg)
        if self.secrets.__class__ is not LocalAuthSecrets:
            msg = "Local authentication secrets must be LocalAuthSecrets"
            raise ImproperlyConfiguredException(detail=msg)
        if self.docs.__class__ is not RouteDocs:
            msg = "Local authentication documentation metadata must be RouteDocs"
            raise ImproperlyConfiguredException(detail=msg)
        register_routes_value: object = self.register_routes
        if register_routes_value.__class__ is not bool:
            msg = "Local authentication route registration must be boolean"
            raise ImproperlyConfiguredException(detail=msg)
        password_hasher_value: object = object.__getattribute__(self, "password_hasher")
        if not isinstance(password_hasher_value, PasswordHasher):
            msg = "Local authentication password_hasher must implement PasswordHasher"
            raise ImproperlyConfiguredException(detail=msg)
        if self.password_policy.__class__ is not PasswordPolicy:
            msg = "Local authentication password policy must be PasswordPolicy"
            raise ImproperlyConfiguredException(detail=msg)
        if self.route_prefix.__class__ is not str:
            msg = "Local authentication route prefix must be an absolute non-root path"
            raise ImproperlyConfiguredException(detail=msg)
        route_prefix = self.route_prefix.rstrip("/")
        if (
            not route_prefix.startswith("/")
            or route_prefix == ""
            or "//" in route_prefix
            or any(value in route_prefix for value in ("\\", "{", "}", "?", "#"))
            or any(segment in {".", ".."} for segment in route_prefix.split("/"))
            or any(character.isspace() or ord(character) < _ASCII_CONTROL_LIMIT for character in route_prefix)
        ):
            msg = "Local authentication route prefix must be an absolute non-root path"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(self, "route_prefix", route_prefix)
        if self.mode in {LocalAuthMode.SESSION, LocalAuthMode.HYBRID} and not isinstance(
            self.binding, SessionBindingConfig
        ):
            msg = "Session local authentication requires explicit binding configuration"
            raise ImproperlyConfiguredException(detail=msg)
        if self.mode in {LocalAuthMode.TOKENS, LocalAuthMode.HYBRID}:
            audience = self.token_audience.strip() if isinstance(self.token_audience, str) else ""
            if not isinstance(self.key_ring, LocalKeyRing) or not audience:
                msg = "Token local authentication requires an explicit key ring and audience"
                raise ImproperlyConfiguredException(detail=msg)
            client_id_value: object = object.__getattribute__(self, "token_client_id")
            client_id = client_id_value.strip() if isinstance(client_id_value, str) else ""
            if not client_id:
                msg = "Token local authentication client id must be non-empty text"
                raise ImproperlyConfiguredException(detail=msg)
            validate_access_token_lifetime(self.access_token_lifetime)
            object.__setattr__(self, "token_audience", audience)
            object.__setattr__(self, "token_client_id", client_id)
        self._validate_capabilities()
        self._configure_rate_limits()
        object.__setattr__(
            self,
            "password_login",
            PasswordLoginService(
                accounts=self.accounts, hasher=self.password_hasher, rate_limits=self.rate_limits, events=self.events
            ),
        )
        self._configure_session_auth()
        self._configure_token_auth()
        self._configure_services()

    def _configure_session_auth(self) -> None:
        if self.mode not in {LocalAuthMode.SESSION, LocalAuthMode.HYBRID}:
            if self.session_auth is not None:
                msg = "Token-only local authentication cannot configure native session authentication"
                raise ImproperlyConfiguredException(detail=msg)
            return
        binding = self.binding
        if not isinstance(binding, SessionBindingConfig):  # pragma: no cover - guarded above
            return
        session_auth = self.session_auth
        if session_auth is None:
            object.__setattr__(
                self,
                "session_auth",
                NativeSessionAuth[UserT](
                    accounts=cast("NativeSessionStore[UserT]", self.accounts),
                    binding=binding,
                    resolver=self.session_resolver,
                ),
            )
        elif (
            id(session_auth.accounts) != id(self.accounts)
            or session_auth.binding is not binding
            or (self.session_resolver is not None and session_auth.resolver is not self.session_resolver)
        ):
            msg = "Custom native session authentication must share the configured accounts and binding"
            raise ImproperlyConfiguredException(detail=msg)

    def _configure_rate_limits(self) -> None:
        events_value: object = object.__getattribute__(self, "events")
        if not isinstance(events_value, SecurityEventSink):
            msg = "Local authentication events must implement SecurityEventSink"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(object.__getattribute__(self, "client_key")):
            msg = "Local authentication client key extractor must be callable"
            raise ImproperlyConfiguredException(detail=msg)
        limiter_value: object = object.__getattribute__(self, "rate_limiter")
        if limiter_value is None:
            # On by default: these routes are unauthenticated and run Argon2, so an
            # unlimited default would ship the amplification surface switched on.
            limiter_value = StoreRateLimiter()
        elif not isinstance(limiter_value, RateLimiter):
            msg = "Local authentication rate limiter must implement RateLimiter"
            raise ImproperlyConfiguredException(detail=msg)
        limiter = limiter_value
        object.__setattr__(self, "rate_limiter", limiter)
        object.__setattr__(
            self,
            "rate_limits",
            RateLimitGuard(limiter=limiter, pepper=self.secrets.rate_limit_pepper, events=self.events),
        )

    def bind_rate_limit_store(self, stores: "StoreRegistry") -> None:
        """Resolve the bundled limiter's store from the application registry.

        Called once during startup. A limiter the application supplied owns its own
        backend and is left alone.

        Args:
            stores: The application store registry. An unregistered limiter store
                name yields Litestar's in-memory default.
        """
        limiter = self.rate_limiter
        if isinstance(limiter, StoreRateLimiter) and limiter.store is None:
            limiter.bind(stores.get(limiter.store_name))

    def bind_mfa_login(self, mfa: "MFAConfig") -> None:
        """Bind one opt-in MFA-login challenge service before route generation.

        Args:
            mfa: The MFA configuration providing the MFA and challenge-store ports.

        Raises:
            ImproperlyConfiguredException: If binding is late, conflicting, or incomplete.
        """
        if mfa.require_at_login is not True and mfa.require_at_login != "enrolled":
            msg = "MFA login binding requires an MFAConfig with require_at_login enabled"
            raise ImproperlyConfiguredException(detail=msg)
        current = self.mfa_login
        if current is not None:
            if self._mfa_login_config is mfa:
                return
            msg = "Local authentication MFA login is already bound to a different MFA configuration"
            raise ImproperlyConfiguredException(detail=msg)
        if self._route_handlers:
            msg = "Local authentication MFA login must bind before route handlers are cached"
            raise ImproperlyConfiguredException(detail=msg)
        store = mfa.login_challenge_store
        if not isinstance(store, MFALoginChallengeStore) or not isinstance(mfa.mfa_service, MFAService):
            msg = "MFA login binding requires configured challenge and MFA services"
            raise ImproperlyConfiguredException(detail=msg)
        service = MFALoginService(store=store, mfa=mfa.mfa_service, pepper=self.secrets.mfa_login_pepper)
        object.__setattr__(self, "mfa_login", service)
        object.__setattr__(self, "_mfa_login_config", mfa)
        object.__setattr__(
            self,
            "local_auth_service",
            replace(self.local_auth_service, mfa_login=service, mfa_require_at_login=mfa.require_at_login),
        )

    def _validate_capabilities(self) -> None:
        required: list[type[Any]] = [
            AccountLookup,
            PasswordCredentialStore,
            LoginMethodStore,
            VerificationTokenStore,
            RecoveryTokenStore,
            SecurityEpochStore,
        ]
        if self.registration.mode is not RegistrationMode.DISABLED:
            required.append(RegistrationStore)
        if self.mode in {LocalAuthMode.SESSION, LocalAuthMode.HYBRID}:
            required.append(SessionRegistry)
        if self.mode in {LocalAuthMode.TOKENS, LocalAuthMode.HYBRID}:
            required.append(RefreshTokenFamilyStore)
        missing = tuple(protocol.__name__ for protocol in required if not isinstance(self.accounts, protocol))
        if missing:
            msg = f"Local authentication account capabilities missing for {self.mode.value}: {', '.join(missing)}"
            raise ImproperlyConfiguredException(detail=msg)

    def _configure_token_auth(self) -> None:
        if self.mode not in {LocalAuthMode.TOKENS, LocalAuthMode.HYBRID}:
            if self.secrets.refresh_codec is not None or self.secrets.refresh_receipts is not None:
                msg = "Session-only local authentication cannot configure refresh-token secrets"
                raise ImproperlyConfiguredException(detail=msg)
            return
        if self.secrets.refresh_codec is None or self.secrets.refresh_receipts is None:
            msg = "Token local authentication requires explicit refresh codec and receipt keys"
            raise ImproperlyConfiguredException(detail=msg)
        key_ring = cast("LocalKeyRing", self.key_ring)
        audience = cast("str", self.token_audience)
        validation = JWTValidationConfig(
            issuer=key_ring.issuer,
            audiences=frozenset({audience}),
            algorithms=frozenset(key.algorithm for key in key_ring.all_verification_keys),
            required_claims=frozenset({"se"}),
            maximum_lifetime=self.access_token_lifetime,
        )
        verifier = LocalAccessVerifier(
            config=validation, verifier=key_ring.build_verifier(validation, mechanism_name="bearer", slot_name="local")
        )
        object.__setattr__(
            self,
            "access_token_issuer",
            LocalAccessTokenIssuer(
                signer=key_ring.build_signer(),
                issuer=key_ring.issuer,
                audience=audience,
                client_id=self.token_client_id,
                lifetime=self.access_token_lifetime,
            ),
        )
        object.__setattr__(
            self,
            "bearer_slot",
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({key_ring.issuer}), audiences=frozenset({audience})),
                verifier=verifier,
            ),
        )
        object.__setattr__(self, "bearer_resolver", LocalBearerIdentityResolver(accounts=self.accounts))

    def _configure_services(self) -> None:
        session_registry = (
            cast("SessionRegistry", self.accounts)
            if self.mode in {LocalAuthMode.SESSION, LocalAuthMode.HYBRID}
            else None
        )
        refresh_store = (
            cast("RefreshTokenFamilyStore", self.accounts)
            if self.mode in {LocalAuthMode.TOKENS, LocalAuthMode.HYBRID}
            else None
        )
        password_reauthentication = PasswordReauthenticationService(
            accounts=self.accounts, hasher=self.password_hasher, events=self.events
        )
        password_change = PasswordChangeService(
            accounts=self.accounts,
            hasher=self.password_hasher,
            sessions=session_registry,
            refresh_tokens=refresh_store,
            password_policy=self.password_policy,
        )
        verification = VerificationTokenService(
            accounts=self.accounts,
            store=self.accounts,
            tokens=self.secrets.purpose_tokens,
            rate_limits=self.rate_limits,
        )
        recovery = RecoveryTokenService(
            accounts=self.accounts,
            store=self.accounts,
            tokens=self.secrets.purpose_tokens,
            hasher=self.password_hasher,
            sessions=session_registry,
            refresh_tokens=refresh_store,
            rate_limits=self.rate_limits,
            password_policy=self.password_policy,
        )
        effective_registration_policy = (
            self.registration.password_policy if self.registration.password_policy is not None else self.password_policy
        )
        registration = (
            RegistrationService(
                accounts=cast("RegistrationStore[UserT]", self.accounts),
                hasher=self.password_hasher,
                tokens=self.secrets.purpose_tokens,
                registration=self.registration,
                password_policy=effective_registration_policy,
                rate_limits=self.rate_limits,
            )
            if self.registration.mode is not RegistrationMode.DISABLED
            else None
        )
        refresh_tokens = None
        if self.mode in {LocalAuthMode.TOKENS, LocalAuthMode.HYBRID}:
            access_token_issuer = self.access_token_issuer
            refresh_codec = self.secrets.refresh_codec
            refresh_receipts = self.secrets.refresh_receipts
            if (
                access_token_issuer is None
                or refresh_store is None
                or refresh_codec is None
                or refresh_receipts is None
            ):  # pragma: no cover - mode invariants
                msg = "Token local authentication services are incomplete"
                raise ImproperlyConfiguredException(detail=msg)
            refresh_tokens = RefreshTokenService(
                accounts=self.accounts,
                store=refresh_store,
                codec=refresh_codec,
                receipts=refresh_receipts,
                access_tokens=access_token_issuer,
                rate_limits=self.rate_limits,
            )
        object.__setattr__(
            self,
            "local_auth_service",
            LocalAuthService(
                accounts=self.accounts,
                password_login=self.password_login,
                password_reauthentication=password_reauthentication,
                password_change=password_change,
                verification=verification,
                recovery=recovery,
                registration=registration,
                session_auth=self.session_auth,
                refresh_tokens=refresh_tokens,
                rate_limits=self.rate_limits,
                client_key=self.client_key,
            ),
        )

    def build_route_handlers(self, *, wire: "WirePolicy | None" = None) -> tuple[Router, ...]:
        """Build and cache the standard end-user route tree.

        One router is cached per wire policy rather than one overall, so a
        router stays a pure function of the configuration that caches it. Two
        applications sharing this configuration with different casing each get
        their own, and neither finds the other's already built.

        Args:
            wire: How the generated bodies are spelled on the wire. Defaults to
                the field names as Python spells them, with unknown members
                rejected.

        Returns:
            One router, or an empty tuple when ``register_routes`` is ``False``.
            The same object is returned for every call naming the same policy.
        """
        if not self.register_routes:
            return ()
        policy = WirePolicy() if wire is None else wire
        cached = self._route_handlers.get(policy)
        if cached is None:
            cached = self._route_handlers[policy] = (build_local_auth_routes(self, policy),)
        return cached

    def openapi_tags(self) -> "tuple[Tag, ...]":
        """Return the documented tag groups the generated routes are filed under.

        Returns:
            The effective tags after this profile's documentation metadata is
            applied, or an empty tuple when no routes are generated.
        """
        if not self.register_routes:
            return ()
        return resolve_tags(LOCAL_TAG_KEYS, self.docs)


class LocalAuth:
    """Construct explicit session, token, or hybrid local-auth profiles."""

    @classmethod
    def session(  # noqa: PLR0913 - explicit configuration surface; every input is named
        cls,
        *,
        accounts: LocalAccountCapabilities[UserT],
        secrets: LocalAuthSecrets,
        binding: SessionBindingConfig,
        session_auth: NativeSessionAuth[UserT] | None = None,
        session_resolver: UserAuthSessionResolver[UserT] | None = None,
        password_hasher: PasswordHasher | None = None,
        password_policy: PasswordPolicy | None = None,
        registration: RegistrationPolicy = _DISABLED_REGISTRATION,
        route_prefix: str = "/auth",
        register_routes: bool = True,
        docs: RouteDocs | None = None,
        rate_limiter: RateLimiter | None = None,
        events: SecurityEventSink | None = None,
        client_key: Callable[[ASGIConnection[Any, Any, Any, Any]], str | None] = trusted_client_key,
    ) -> "LocalAuthConfig[UserT]":
        """Select native-session local authentication.

        Args:
            binding: The proof-of-possession cookie configuration bound to each session.
            session_auth: Override the bundled native session backend.
            session_resolver: Optional one-read authoritative session resolver.
            accounts: The application store implementing every local account capability.
            secrets: The stable cryptographic inputs for purpose tokens and, in
                token profiles, refresh tokens and receipts.
            password_hasher: Override the Argon2 hasher, for example to tune its
                cost parameters.
            password_policy: Optional password policy validating lengths, shapes,
                compromised lists, or identifier overlaps.
            registration: The self-service registration policy. Registration is
                disabled unless a policy allows it.
            route_prefix: The path the generated route tree is mounted under.
            register_routes: Build the services without generating routes when
                ``False``, so an application can mount its own controllers.
            docs: Application-owned OpenAPI documentation for the generated
                routes: tag renames, tag descriptions, and optional operation-id
                and route-name transforms.
            rate_limiter: Override the bundled store-backed limiter, or pass
                ``UnlimitedRateLimiter`` to limit only at the edge.
            events: The sink offered every observational security event.
            client_key: Derive the rate-limit client bucket from a connection. The
                default trusts only the peer address, never a forwarding header.
                A misconfigured proxy-aware extractor can collapse unrelated
                clients into one bucket or return ``None`` and remove the bucket.

        Returns:
            A configuration that generates session routes only.
        """
        return LocalAuthConfig(
            mode=LocalAuthMode.SESSION,
            accounts=accounts,
            secrets=secrets,
            binding=binding,
            session_auth=session_auth,
            session_resolver=session_resolver,
            password_hasher=Argon2PasswordHasher() if password_hasher is None else password_hasher,
            password_policy=PasswordPolicy() if password_policy is None else password_policy,
            registration=registration,
            route_prefix=route_prefix,
            register_routes=register_routes,
            docs=RouteDocs() if docs is None else docs,
            rate_limiter=rate_limiter,
            events=NoOpSecurityEventSink() if events is None else events,
            client_key=client_key,
        )

    @classmethod
    def tokens(  # noqa: PLR0913 - explicit configuration surface; every input is named
        cls,
        *,
        accounts: LocalAccountCapabilities[UserT],
        secrets: LocalAuthSecrets,
        key_ring: LocalKeyRing,
        token_audience: str,
        token_client_id: str = _DEFAULT_LOCAL_CLIENT_ID,
        access_token_lifetime: timedelta = _DEFAULT_ACCESS_TOKEN_LIFETIME,
        password_hasher: PasswordHasher | None = None,
        password_policy: PasswordPolicy | None = None,
        registration: RegistrationPolicy = _DISABLED_REGISTRATION,
        route_prefix: str = "/auth",
        register_routes: bool = True,
        docs: RouteDocs | None = None,
        rate_limiter: RateLimiter | None = None,
        events: SecurityEventSink | None = None,
        client_key: Callable[[ASGIConnection[Any, Any, Any, Any]], str | None] = trusted_client_key,
    ) -> "LocalAuthConfig[UserT]":
        """Select bearer access/refresh-token local authentication.

        Args:
            key_ring: The signing keys and issuer for local access tokens.
            token_audience: The audience claim local access tokens are issued for.
            token_client_id: The client identifier recorded on issued tokens.
            access_token_lifetime: How long an issued access token stays valid.
            accounts: The application store implementing every local account capability.
            secrets: The stable cryptographic inputs for purpose tokens and, in
                token profiles, refresh tokens and receipts.
            password_hasher: Override the Argon2 hasher, for example to tune its
                cost parameters.
            password_policy: Optional password policy validating lengths, shapes,
                compromised lists, or identifier overlaps.
            registration: The self-service registration policy. Registration is
                disabled unless a policy allows it.
            route_prefix: The path the generated route tree is mounted under.
            register_routes: Build the services without generating routes when
                ``False``, so an application can mount its own controllers.
            docs: Application-owned OpenAPI documentation for the generated
                routes: tag renames, tag descriptions, and optional operation-id
                and route-name transforms.
            rate_limiter: Override the bundled store-backed limiter, or pass
                ``UnlimitedRateLimiter`` to limit only at the edge.
            events: The sink offered every observational security event.
            client_key: Derive the rate-limit client bucket from a connection. The
                default trusts only the peer address, never a forwarding header.
                A misconfigured proxy-aware extractor can collapse unrelated
                clients into one bucket or return ``None`` and remove the bucket.

        Returns:
            A configuration that generates token routes only.
        """
        return LocalAuthConfig(
            mode=LocalAuthMode.TOKENS,
            accounts=accounts,
            secrets=secrets,
            key_ring=key_ring,
            token_audience=token_audience,
            token_client_id=token_client_id,
            access_token_lifetime=access_token_lifetime,
            password_hasher=(
                Argon2PasswordHasher(worker_limits=key_ring.worker_limits)
                if password_hasher is None
                else password_hasher
            ),
            password_policy=PasswordPolicy() if password_policy is None else password_policy,
            registration=registration,
            route_prefix=route_prefix,
            register_routes=register_routes,
            docs=RouteDocs() if docs is None else docs,
            rate_limiter=rate_limiter,
            events=NoOpSecurityEventSink() if events is None else events,
            client_key=client_key,
        )

    @classmethod
    def hybrid(  # noqa: PLR0913 - explicit configuration surface; every input is named
        cls,
        *,
        accounts: LocalAccountCapabilities[UserT],
        secrets: LocalAuthSecrets,
        binding: SessionBindingConfig,
        key_ring: LocalKeyRing,
        token_audience: str,
        token_client_id: str = _DEFAULT_LOCAL_CLIENT_ID,
        access_token_lifetime: timedelta = _DEFAULT_ACCESS_TOKEN_LIFETIME,
        session_auth: NativeSessionAuth[UserT] | None = None,
        session_resolver: UserAuthSessionResolver[UserT] | None = None,
        password_hasher: PasswordHasher | None = None,
        password_policy: PasswordPolicy | None = None,
        registration: RegistrationPolicy = _DISABLED_REGISTRATION,
        route_prefix: str = "/auth",
        register_routes: bool = True,
        docs: RouteDocs | None = None,
        rate_limiter: RateLimiter | None = None,
        events: SecurityEventSink | None = None,
        client_key: Callable[[ASGIConnection[Any, Any, Any, Any]], str | None] = trusted_client_key,
    ) -> "LocalAuthConfig[UserT]":
        """Select distinct native-session and bearer-token local transports.

        Args:
            binding: The proof-of-possession cookie configuration bound to each session.
            session_auth: Override the bundled native session backend.
            session_resolver: Optional one-read authoritative session resolver.
            key_ring: The signing keys and issuer for local access tokens.
            token_audience: The audience claim local access tokens are issued for.
            token_client_id: The client identifier recorded on issued tokens.
            access_token_lifetime: How long an issued access token stays valid.
            accounts: The application store implementing every local account capability.
            secrets: The stable cryptographic inputs for purpose tokens and, in
                token profiles, refresh tokens and receipts.
            password_hasher: Override the Argon2 hasher, for example to tune its
                cost parameters.
            password_policy: Optional password policy validating lengths, shapes,
                compromised lists, or identifier overlaps.
            registration: The self-service registration policy. Registration is
                disabled unless a policy allows it.
            route_prefix: The path the generated route tree is mounted under.
            register_routes: Build the services without generating routes when
                ``False``, so an application can mount its own controllers.
            docs: Application-owned OpenAPI documentation for the generated
                routes: tag renames, tag descriptions, and optional operation-id
                and route-name transforms.
            rate_limiter: Override the bundled store-backed limiter, or pass
                ``UnlimitedRateLimiter`` to limit only at the edge.
            events: The sink offered every observational security event.
            client_key: Derive the rate-limit client bucket from a connection. The
                default trusts only the peer address, never a forwarding header.
                A misconfigured proxy-aware extractor can collapse unrelated
                clients into one bucket or return ``None`` and remove the bucket.

        Returns:
            A configuration that generates both session and token routes. Password
            change is served on ``/password/change`` for sessions and
            ``/token/password/change`` for bearers.
        """
        return LocalAuthConfig(
            mode=LocalAuthMode.HYBRID,
            accounts=accounts,
            secrets=secrets,
            binding=binding,
            key_ring=key_ring,
            token_audience=token_audience,
            token_client_id=token_client_id,
            access_token_lifetime=access_token_lifetime,
            session_auth=session_auth,
            session_resolver=session_resolver,
            password_hasher=(
                Argon2PasswordHasher(worker_limits=key_ring.worker_limits)
                if password_hasher is None
                else password_hasher
            ),
            password_policy=PasswordPolicy() if password_policy is None else password_policy,
            registration=registration,
            route_prefix=route_prefix,
            register_routes=register_routes,
            docs=RouteDocs() if docs is None else docs,
            rate_limiter=rate_limiter,
            events=NoOpSecurityEventSink() if events is None else events,
            client_key=client_key,
        )
