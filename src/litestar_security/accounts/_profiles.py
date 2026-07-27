"""Explicit session, token, and hybrid local-authentication profiles."""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from hashlib import sha256
from hmac import digest as hmac_digest
from logging import getLogger
from typing import TYPE_CHECKING, Any, Generic, TypeVar, cast

from litestar import Request, Router
from litestar.config.csrf import CSRFConfig
from litestar.connection import ASGIConnection
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._access_tokens import (
    LocalAccessTokenIssuer,
    LocalAccessVerifier,
    LocalBearerIdentityResolver,
    validate_access_token_lifetime,
)
from litestar_security.accounts._login import PasswordLoginService, PasswordReauthenticationService
from litestar_security.accounts._passwords import Argon2PasswordHasher, PasswordHasher, PasswordPolicyResult
from litestar_security.accounts._purpose_tokens import PurposeTokenCodec
from litestar_security.accounts._rate_limits import RateLimited, RateLimiter, RateLimitGuard, StoreRateLimiter
from litestar_security.accounts._receipts import RefreshReceiptKey, RefreshReceiptSealer
from litestar_security.accounts._records import (
    InvalidLifecycleRequest,
    LocalAccount,
    LocalAuthMode,
    NoOpSecurityEventSink,
    PasswordChangeResult,
    PasswordChangeStatus,
    PasswordReauthenticationProof,
    RegistrationMode,
    SecurityEventSink,
)
from litestar_security.accounts._recovery import PasswordChangeService, RecoveryTokenService
from litestar_security.accounts._refresh import RefreshTokenFamilyStore, RefreshTokenService
from litestar_security.accounts._refresh_tokens import RefreshTokenCodec, RefreshTokenResponse
from litestar_security.accounts._registration import RegistrationService, VerificationTokenService
from litestar_security.accounts._schemas import LocalAccountResponse, LocalCredentials, LocalPasswordChangeRequest
from litestar_security.accounts._sessions import (
    NativeSessionAuth,
    NativeSessionStore,
    SessionAuthentication,
    SessionBindingConfig,
    SessionRegistry,
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
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.config import ExternalCSRF
from litestar_security.providers.jwt import BearerSlotSelector, BearerTokenSlot, JWTValidationConfig, LocalKeyRing

if TYPE_CHECKING:
    from litestar.openapi.spec import Tag
    from litestar.stores.registry import StoreRegistry

__all__ = ("LocalAuth", "LocalAuthConfig", "LocalAuthSecrets", "LocalAuthServices", "trusted_client_key")

UserT = TypeVar("UserT")
_ASCII_CONTROL_LIMIT = 32
_DEFAULT_ACCESS_TOKEN_LIFETIME = timedelta(minutes=10)
_DEFAULT_LOCAL_CLIENT_ID = "local"
_DISABLED_REGISTRATION = RegistrationPolicy.disabled()
_RATE_LIMIT_PEPPER_LABEL = b"litestar-security/rate-limit/pepper"
_LOGGER = getLogger(__name__)


def trusted_client_key(connection: "ASGIConnection[Any, Any, Any, Any]") -> str | None:
    """Return the peer address, without trusting any forwarding header.

    This deliberately matches Litestar's own default: ``X-Forwarded-For`` and
    friends are attacker-controlled unless a proxy you operate rewrote them, so
    an application behind a proxy must replace this with an extractor that knows
    which hops it trusts. Returning ``None`` disables the client bucket and
    leaves the identifier bucket in force.

    Args:
        connection: The connection the attempt arrived on.

    Returns:
        The peer host, or ``None`` when the connection reports no client.
    """
    client = connection.client
    return client.host if client is not None else None


@dataclass(frozen=True, slots=True)
class LocalAuthSecrets:
    """Explicit stable cryptographic inputs for local lifecycle routes."""

    purpose_tokens: PurposeTokenCodec = field(repr=False)
    refresh_codec: RefreshTokenCodec | None = field(default=None, repr=False)
    refresh_receipts: RefreshReceiptSealer | None = field(default=None, repr=False)
    rate_limit_pepper: bytes = field(init=False, repr=False, compare=False)

    @classmethod
    def session(cls, *, purpose_token_pepper: bytes) -> "LocalAuthSecrets":
        """Build the stable secrets required by session-only local authentication."""
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
        """Build the stable secrets required by token or hybrid local authentication."""
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


@dataclass(frozen=True, slots=True)
class LocalAuthServices(Generic[UserT]):
    """Singleton service graph shared by generated and application controllers."""

    accounts: LocalAccountCapabilities[UserT] = field(repr=False)
    password_login: PasswordLoginService[UserT] = field(repr=False)
    password_reauthentication: PasswordReauthenticationService = field(repr=False)
    password_change: PasswordChangeService = field(repr=False)
    verification: VerificationTokenService[UserT] = field(repr=False)
    recovery: RecoveryTokenService[UserT] = field(repr=False)
    registration: RegistrationService[UserT] | None = field(default=None, repr=False)
    session_auth: NativeSessionAuth[UserT] | None = field(default=None, repr=False)
    refresh_tokens: RefreshTokenService[UserT] | None = field(default=None, repr=False)
    client_key: "Callable[[ASGIConnection[Any, Any, Any, Any]], str | None]" = field(
        default=trusted_client_key, repr=False, compare=False
    )

    def client_key_for(self, connection: "ASGIConnection[Any, Any, Any, Any]") -> str | None:
        """Return the trusted client bucket key, or ``None`` when it cannot be derived.

        A failing extractor degrades to identifier-only limiting rather than
        failing the request, because the subject bucket still bounds the attempt.
        """
        try:
            return self.client_key(connection)
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; degrade, do not fail
            _LOGGER.error("Local authentication client key extractor failed")  # noqa: TRY400 - omit untrusted details
            return None

    async def session_login(
        self, request: Request[Any, Any, Any], credentials: LocalCredentials
    ) -> LocalAccountResponse | RateLimited | InvalidCredentials | VerificationUnavailable:
        """Authenticate a password and establish fixation-safe session state."""
        account = await self.password_login.authenticate(
            credentials.identifier, credentials.password, client_key=self.client_key_for(request)
        )
        if not isinstance(account, LocalAccount):
            return account
        session_auth = self.session_auth
        if session_auth is None:
            return VerificationUnavailable()
        established = await session_auth.establish(request, account)
        if not isinstance(established, SessionAuthentication):
            return established
        return LocalAccountResponse(account_id=account.account_id, display_name=account.display_name)

    async def token_login(
        self, request: Request[Any, Any, Any], credentials: LocalCredentials
    ) -> RefreshTokenResponse | RateLimited | InvalidCredentials | VerificationUnavailable:
        """Authenticate a password and issue one access/refresh pair."""
        account = await self.password_login.authenticate(
            credentials.identifier, credentials.password, client_key=self.client_key_for(request)
        )
        if not isinstance(account, LocalAccount):
            return account
        refresh_tokens = self.refresh_tokens
        if refresh_tokens is None:
            return VerificationUnavailable()
        return await refresh_tokens.issue(account)

    async def change_session_password(  # noqa: PLR0911 - preserve explicit sanitized outcomes
        self, request: Request[Any, Any, Any], account_id: str, data: LocalPasswordChangeRequest
    ) -> (
        PasswordChangeResult
        | PasswordPolicyResult
        | InvalidCredentials
        | InvalidLifecycleRequest
        | VerificationUnavailable
    ):
        """Change a password and atomically prepare the current session rebind."""
        session_auth = self.session_auth
        if session_auth is None:
            return VerificationUnavailable()
        proof = await self.password_reauthentication.verify(account_id, data.current_password)
        if not isinstance(proof, PasswordReauthenticationProof):
            return proof
        if data.compromise:
            result = await self.password_change.change(account_id, data.password, proof=proof, compromise=True)
            if isinstance(result, PasswordChangeResult) and result.status is PasswordChangeStatus.CHANGED:
                await session_auth.logout(request)
            return result
        authentication = session_auth.current_authentication(request)
        if authentication is None or authentication.account_id != account_id:
            return InvalidCredentials()
        try:
            account = await self.accounts.get_by_id(account_id)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if account is None or account.security_epoch != proof.security_epoch:
            return InvalidCredentials()
        plan = session_auth.prepare_password_rebind(request, account)
        if isinstance(plan, VerificationUnavailable):
            return plan
        result = await self.password_change.change(
            account_id,
            data.password,
            proof=proof,
            current_session_id=plan.prior_session_id,
            replacement_session=plan.command,
        )
        if (
            isinstance(result, PasswordChangeResult)
            and result.status is PasswordChangeStatus.CHANGED
            and result.security_epoch is not None
        ):
            await session_auth.activate_password_rebind(request, plan, result.security_epoch)
        return result

    async def change_token_password(
        self, account_id: str, data: LocalPasswordChangeRequest
    ) -> (
        PasswordChangeResult
        | PasswordPolicyResult
        | InvalidCredentials
        | InvalidLifecycleRequest
        | VerificationUnavailable
    ):
        """Change a bearer-authenticated password and revoke local transports."""
        proof = await self.password_reauthentication.verify(account_id, data.current_password)
        if not isinstance(proof, PasswordReauthenticationProof):
            return proof
        return await self.password_change.change(account_id, data.password, proof=proof, compromise=data.compromise)


@dataclass(frozen=True, slots=True)
class LocalAuthConfig(Generic[UserT]):
    """Explicit local-authentication transport and capability selection."""

    mode: LocalAuthMode
    accounts: LocalAccountCapabilities[UserT] = field(repr=False)
    secrets: LocalAuthSecrets = field(repr=False)
    registration: RegistrationPolicy
    route_prefix: str
    register_routes: bool = True
    csrf: CSRFConfig | ExternalCSRF | None = field(default=None, repr=False)
    binding: SessionBindingConfig | None = field(default=None, repr=False)
    key_ring: LocalKeyRing | None = field(default=None, repr=False)
    token_audience: str | None = None
    token_client_id: str = _DEFAULT_LOCAL_CLIENT_ID
    access_token_lifetime: timedelta = _DEFAULT_ACCESS_TOKEN_LIFETIME
    password_hasher: PasswordHasher = field(default_factory=Argon2PasswordHasher, repr=False, compare=False)
    session_auth: NativeSessionAuth[UserT] | None = field(default=None, repr=False, compare=False)
    rate_limiter: RateLimiter | None = field(default=None, repr=False, compare=False)
    events: SecurityEventSink = field(default_factory=NoOpSecurityEventSink, repr=False, compare=False)
    client_key: "Callable[[ASGIConnection[Any, Any, Any, Any]], str | None]" = field(
        default=trusted_client_key, repr=False, compare=False
    )
    rate_limits: RateLimitGuard = field(init=False, repr=False, compare=False)
    password_login: PasswordLoginService[UserT] = field(init=False, repr=False, compare=False)
    access_token_issuer: LocalAccessTokenIssuer[UserT] | None = field(
        init=False, default=None, repr=False, compare=False
    )
    bearer_slot: BearerTokenSlot | None = field(init=False, default=None, repr=False, compare=False)
    bearer_resolver: LocalBearerIdentityResolver[UserT] | None = field(
        init=False, default=None, repr=False, compare=False
    )
    services: LocalAuthServices[UserT] = field(init=False, repr=False, compare=False)
    _route_handlers: tuple[Router, ...] | None = field(init=False, default=None, repr=False, compare=False)

    def __post_init__(self) -> None:  # noqa: C901 - explicit transport invariants remain centralized
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
        register_routes_value: object = self.register_routes
        if register_routes_value.__class__ is not bool:
            msg = "Local authentication route registration must be boolean"
            raise ImproperlyConfiguredException(detail=msg)
        password_hasher_value: object = object.__getattribute__(self, "password_hasher")
        if not isinstance(password_hasher_value, PasswordHasher):
            msg = "Local authentication password_hasher must implement PasswordHasher"
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
        if self.mode in {LocalAuthMode.SESSION, LocalAuthMode.HYBRID} and (
            not isinstance(self.csrf, (CSRFConfig, ExternalCSRF)) or not isinstance(self.binding, SessionBindingConfig)
        ):
            msg = "Session local authentication requires explicit CSRF and binding configuration"
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
                NativeSessionAuth[UserT](accounts=cast("NativeSessionStore[UserT]", self.accounts), binding=binding),
            )
        elif id(session_auth.accounts) != id(self.accounts) or session_auth.binding is not binding:
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
        """
        limiter = self.rate_limiter
        if isinstance(limiter, StoreRateLimiter) and limiter.store is None:
            limiter.bind(stores.get(limiter.store_name))

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
            accounts=self.accounts, hasher=self.password_hasher, sessions=session_registry, refresh_tokens=refresh_store
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
        )
        registration = (
            RegistrationService(
                accounts=cast("RegistrationStore[UserT]", self.accounts),
                hasher=self.password_hasher,
                tokens=self.secrets.purpose_tokens,
                registration=self.registration,
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
            "services",
            LocalAuthServices(
                accounts=self.accounts,
                password_login=self.password_login,
                password_reauthentication=password_reauthentication,
                password_change=password_change,
                verification=verification,
                recovery=recovery,
                registration=registration,
                session_auth=self.session_auth,
                refresh_tokens=refresh_tokens,
                client_key=self.client_key,
            ),
        )

    def build_route_handlers(self) -> tuple[Router, ...]:
        """Build and cache the standard end-user route tree."""
        if not self.register_routes:
            return ()
        if self._route_handlers is None:
            from litestar_security.accounts._controllers import build_local_auth_routes  # noqa: PLC0415 - cycle break

            object.__setattr__(self, "_route_handlers", (build_local_auth_routes(self),))
        return cast("tuple[Router, ...]", self._route_handlers)

    def openapi_tags(self) -> "tuple[Tag, ...]":
        """Return the documented tag groups the generated routes are filed under."""
        if not self.register_routes:
            return ()
        from litestar_security.accounts._controllers import LOCAL_AUTH_TAGS  # noqa: PLC0415 - cycle break

        return LOCAL_AUTH_TAGS


class LocalAuth:
    """Construct explicit session, token, or hybrid local-auth profiles."""

    @classmethod
    def session(  # noqa: PLR0913 - explicit configuration surface; every input is named
        cls,
        *,
        accounts: LocalAccountCapabilities[UserT],
        secrets: LocalAuthSecrets,
        csrf: CSRFConfig | ExternalCSRF,
        binding: SessionBindingConfig,
        session_auth: NativeSessionAuth[UserT] | None = None,
        password_hasher: PasswordHasher | None = None,
        registration: RegistrationPolicy = _DISABLED_REGISTRATION,
        route_prefix: str = "/auth",
        register_routes: bool = True,
        rate_limiter: RateLimiter | None = None,
        events: SecurityEventSink | None = None,
        client_key: Callable[[ASGIConnection[Any, Any, Any, Any]], str | None] = trusted_client_key,
    ) -> "LocalAuthConfig[UserT]":
        """Select native-session local authentication."""
        return LocalAuthConfig(
            mode=LocalAuthMode.SESSION,
            accounts=accounts,
            secrets=secrets,
            csrf=csrf,
            binding=binding,
            session_auth=session_auth,
            password_hasher=Argon2PasswordHasher() if password_hasher is None else password_hasher,
            registration=registration,
            route_prefix=route_prefix,
            register_routes=register_routes,
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
        registration: RegistrationPolicy = _DISABLED_REGISTRATION,
        route_prefix: str = "/auth",
        register_routes: bool = True,
        rate_limiter: RateLimiter | None = None,
        events: SecurityEventSink | None = None,
        client_key: Callable[[ASGIConnection[Any, Any, Any, Any]], str | None] = trusted_client_key,
    ) -> "LocalAuthConfig[UserT]":
        """Select bearer access/refresh-token local authentication."""
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
            registration=registration,
            route_prefix=route_prefix,
            register_routes=register_routes,
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
        csrf: CSRFConfig | ExternalCSRF,
        binding: SessionBindingConfig,
        key_ring: LocalKeyRing,
        token_audience: str,
        token_client_id: str = _DEFAULT_LOCAL_CLIENT_ID,
        access_token_lifetime: timedelta = _DEFAULT_ACCESS_TOKEN_LIFETIME,
        session_auth: NativeSessionAuth[UserT] | None = None,
        password_hasher: PasswordHasher | None = None,
        registration: RegistrationPolicy = _DISABLED_REGISTRATION,
        route_prefix: str = "/auth",
        register_routes: bool = True,
        rate_limiter: RateLimiter | None = None,
        events: SecurityEventSink | None = None,
        client_key: Callable[[ASGIConnection[Any, Any, Any, Any]], str | None] = trusted_client_key,
    ) -> "LocalAuthConfig[UserT]":
        """Select distinct native-session and bearer-token local transports."""
        return LocalAuthConfig(
            mode=LocalAuthMode.HYBRID,
            accounts=accounts,
            secrets=secrets,
            csrf=csrf,
            binding=binding,
            key_ring=key_ring,
            token_audience=token_audience,
            token_client_id=token_client_id,
            access_token_lifetime=access_token_lifetime,
            session_auth=session_auth,
            password_hasher=(
                Argon2PasswordHasher(worker_limits=key_ring.worker_limits)
                if password_hasher is None
                else password_hasher
            ),
            registration=registration,
            route_prefix=route_prefix,
            register_routes=register_routes,
            rate_limiter=rate_limiter,
            events=NoOpSecurityEventSink() if events is None else events,
            client_key=client_key,
        )
