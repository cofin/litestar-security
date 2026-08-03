"""Typed authentication contracts and deterministic mechanism registration."""

from collections.abc import Awaitable, Callable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field, replace
from secrets import token_urlsafe
from types import MappingProxyType
from typing import Any, Generic, Literal, Protocol, TypeAlias, TypeVar, cast

from litestar.connection import ASGIConnection
from litestar.enums import ScopeType
from litestar.exceptions import (
    ImproperlyConfiguredException,
    NotAuthorizedException,
    PermissionDeniedException,
    ServiceUnavailableException,
    WebSocketException,
)
from litestar.middleware import DefineMiddleware
from litestar.middleware._internal.exceptions import ExceptionHandlerMiddleware
from litestar.openapi.spec import SecurityScheme
from litestar.routes import HTTPRoute
from litestar.types import ASGIApp, HTTPScope, Message, Receive, Scope, Send
from typing_extensions import Self

from litestar_security.context import (
    AuthenticationEvidence,
    AuthorizationSnapshot,
    CredentialRestrictions,
    LitestarSessionHandle,
    NullSessionHandle,
    Principal,
    ResourcePermission,
    SecurityContext,
    SessionHandle,
    resolve_authorization,
)
from litestar_security.websocket import (
    WebSocketBinding,
    WebSocketCloseCoordinator,
    WebSocketConnectTokenRecord,
    WebSocketConnectTokenService,
    WebSocketConnectTokenUnavailableError,
    WebSocketHandshake,
    WebSocketSecurityConfig,
    close_websocket,
    extract_websocket_handshake,
    supervise_websocket_lifetime,
    websocket_policy_fingerprint,
)

__all__ = (
    "CSRF_REQUIRED_OPT_KEY",
    "Authenticated",
    "AuthenticationMechanism",
    "AuthenticationOutcome",
    "AuthenticationPolicy",
    "AuthenticationRegistry",
    "AuthorizationResolver",
    "CredentialExtraction",
    "CredentialSlot",
    "IdentityResolution",
    "IdentityResolver",
    "InvalidCredentials",
    "MechanismRequirement",
    "NoCredentials",
    "PresentedCredential",
    "RequestAuthenticator",
    "VerificationUnavailable",
    "all_of",
    "any_of",
    "at_least",
    "exclude",
    "mechanism",
    "optional",
    "public",
    "required",
)


CredentialT = TypeVar("CredentialT")


ClaimsT = TypeVar("ClaimsT")


UserT = TypeVar("UserT")


_CredentialT = TypeVar("_CredentialT")


_ClaimsT = TypeVar("_ClaimsT")


_UserT = TypeVar("_UserT")


_RequestCredentialT_contra = TypeVar("_RequestCredentialT_contra", contravariant=True)


_ResolverClaimsT_contra = TypeVar("_ResolverClaimsT_contra", contravariant=True)


_AUTHENTICATION_UNAVAILABLE = "Authentication service unavailable"


_LITESTAR_INTERNAL_ERROR_CLOSE = 4500


RUNTIME_PLAN_OPT_KEY = "litestar_security_plan"


AUTH_POLICY_OPT_KEY = "auth"


CSRF_REQUIRED_OPT_KEY = "csrf_required"


_SECURITY_RESPONSE_HEADERS_SCOPE_KEY = "_litestar_security_response_headers"


_NATIVE_EXCEPTION_HANDLER = ExceptionHandlerMiddleware


def queue_security_response_header(scope: Scope, header: tuple[bytes, bytes]) -> None:
    """Queue one encoded header for the next HTTP response start event."""
    if scope["type"] != ScopeType.HTTP:
        return
    scope_data = cast("dict[str, object]", scope)
    headers = cast("list[tuple[bytes, bytes]]", scope_data.setdefault(_SECURITY_RESPONSE_HEADERS_SCOPE_KEY, []))
    headers.append(header)


def is_generated_options_handler(handler: object) -> bool:
    """Report whether a callable is an OPTIONS handler Litestar generated for a route.

    This is the one predicate every compile-time and runtime bypass shares, so
    the two sites can never drift apart. The handler is matched by the module
    and exact qualname of the closure :meth:`HTTPRoute.create_options_handler`
    produces, both read from that method rather than spelled as string
    literals, so a Litestar reorganization fails here instead of silently
    reclassifying routes. An application handler that merely shares the
    function name is not matched and is authenticated normally.

    Args:
        handler: The route handler function to identify.

    Returns:
        True only when Litestar generated the handler to answer OPTIONS.
    """
    return (
        getattr(handler, "__module__", None) == HTTPRoute.create_options_handler.__module__
        and getattr(handler, "__qualname__", None)
        == f"{HTTPRoute.create_options_handler.__qualname__}.<locals>.options_handler"
    )


class AuthenticationPolicy:
    """Immutable closed request-authentication expression."""

    __slots__ = ()

    def __new__(cls, *_args: object, **_kwargs: object) -> Self:
        """Require construction through the validated public factories."""
        if cls is AuthenticationPolicy:
            message = "Authentication policy must be created by a Litestar Security policy helper"
            raise ImproperlyConfiguredException(detail=message)
        return super().__new__(cls)


@dataclass(frozen=True, slots=True)
class PublicPolicy(AuthenticationPolicy):
    pass


@dataclass(frozen=True, slots=True)
class ExcludePolicy(AuthenticationPolicy):
    pass


@dataclass(frozen=True, slots=True)
class OptionalPolicy(AuthenticationPolicy):
    policy: AuthenticationPolicy


def mechanism(name: str, *scopes: str) -> "MechanismRequirement":
    """Select a named mechanism and its requested OAuth or OIDC scopes.

    Args:
        name: The configured mechanism name.
        *scopes: Provider scopes to request. Only OAuth and OIDC schemes accept these.

    Returns:
        The requirement, for use inside a policy expression.
    """
    return MechanismRequirement(name=name, scopes=tuple(scopes))


def public() -> AuthenticationPolicy:
    """Deliberately skip request credential verification.

    Returns:
        A policy that authenticates nothing, leaving the anonymous principal in place.
    """
    return PublicPolicy()


def exclude() -> AuthenticationPolicy:
    """Bypass request authentication while preserving the default CSRF policy.

    Returns:
        A policy that skips credential extraction and authentication.
    """
    return ExcludePolicy()


def required(*requirements: "str | MechanismRequirement") -> AuthenticationPolicy:
    """Require an explicit OR expression or the implicit default participants.

    Args:
        *requirements: Mechanism names or requirements. Passing none requires any
            mechanism that participates by default.

    Returns:
        A policy that rejects a request presenting no accepted credential.
    """
    if requirements:
        return any_of(*requirements)
    return MechanismPolicy(operator="any_of", requirements=(), implicit=True)


_AUTHENTICATION_REQUIRED = "Authentication required"


def optional(policy: AuthenticationPolicy) -> AuthenticationPolicy:
    """Allow anonymous access only when a positive policy sees no credential.

    A presented-but-invalid credential is still rejected: optional means the
    route tolerates absence, not failure.

    Args:
        policy: The positive policy to apply when a credential is present.

    Returns:
        A policy that admits anonymous callers alongside authenticated ones.

    Raises:
        ImproperlyConfiguredException: If the policy is public or already optional.
    """
    _validate_policy(policy)
    if isinstance(policy, OptionalPolicy):
        message = "Authentication policy cannot contain a nested optional expression"
        raise ImproperlyConfiguredException(detail=message)
    if isinstance(policy, PublicPolicy):
        message = "Optional authentication requires a positive authentication policy"
        raise ImproperlyConfiguredException(detail=message)
    return OptionalPolicy(policy=policy)


@dataclass(frozen=True, slots=True)
class MechanismRequirement:
    """Select one configured mechanism and optional provider scopes."""

    name: str
    scopes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Normalize and validate the mechanism requirement."""
        name = _normalize_name(self.name, "Authentication mechanism name")
        scopes = tuple(_normalize_name(scope, "Authentication scope") for scope in self.scopes)
        if len(frozenset(scopes)) != len(scopes):
            message = f"Duplicate scope in authentication mechanism {name}"
            raise ImproperlyConfiguredException(detail=message)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "scopes", scopes)


def any_of(*requirements: str | MechanismRequirement) -> AuthenticationPolicy:
    """Require at least one named authentication mechanism.

    Args:
        *requirements: Mechanism names or requirements to accept.

    Returns:
        A policy satisfied by any one participant.
    """
    return MechanismPolicy(operator="any_of", requirements=_normalize_requirements(requirements, "any_of"))


def all_of(*requirements: str | MechanismRequirement) -> AuthenticationPolicy:
    """Require every named authentication mechanism.

    Args:
        *requirements: Mechanism names or requirements that must all succeed.

    Returns:
        A policy satisfied only when every participant succeeds.
    """
    return MechanismPolicy(operator="all_of", requirements=_normalize_requirements(requirements, "all_of"))


def at_least(count: int, *requirements: str | MechanismRequirement) -> AuthenticationPolicy:
    """Require a positive threshold of named authentication mechanisms.

    Args:
        count: How many participants must succeed.
        *requirements: Mechanism names or requirements to draw from.

    Returns:
        A policy satisfied by any ``count`` of the participants.

    Raises:
        ImproperlyConfiguredException: If the count is not between one and the
            number of participants.
    """
    normalized = _normalize_requirements(requirements, "at_least")
    if not 1 <= count <= len(normalized):
        message = f"at_least count must be between 1 and {len(normalized)}"
        raise ImproperlyConfiguredException(detail=message)
    return MechanismPolicy(operator="at_least", requirements=normalized, count=count)


_PolicyOperator = Literal["any_of", "all_of", "at_least"]


@dataclass(frozen=True, slots=True)
class MechanismPolicy(AuthenticationPolicy):
    operator: _PolicyOperator
    requirements: tuple[MechanismRequirement, ...]
    count: int | None = None
    implicit: bool = False


@dataclass(frozen=True, slots=True)
class PresentedCredential(Generic[CredentialT]):
    """A credential extracted from one owned request slot."""

    value: CredentialT = field(repr=False)


@dataclass(frozen=True, slots=True)
class NoCredentials:
    """Indicate that an owned slot contains no credential."""


@dataclass(frozen=True, slots=True)
class Authenticated(Generic[ClaimsT]):
    """Carry the typed result of successful credential verification."""

    claims: ClaimsT = field(repr=False)
    evidence: AuthenticationEvidence
    grants: AuthorizationSnapshot = field(default_factory=AuthorizationSnapshot)
    restrictions: CredentialRestrictions = field(default_factory=CredentialRestrictions)


@dataclass(frozen=True, slots=True)
class InvalidCredentials:
    """Indicate that a presented credential cannot authenticate."""

    code: str = "invalid_credentials"


CredentialExtraction: TypeAlias = NoCredentials | PresentedCredential[CredentialT] | InvalidCredentials


@dataclass(frozen=True, slots=True)
class VerificationUnavailable:
    """Indicate that a verifier cannot make a trustworthy decision."""

    code: str = "verification_unavailable"
    retry_after: int | None = None


AuthenticationOutcome: TypeAlias = NoCredentials | Authenticated[ClaimsT] | InvalidCredentials | VerificationUnavailable


IdentityResolution: TypeAlias = Principal[UserT] | InvalidCredentials | VerificationUnavailable


AuthorizationResolution: TypeAlias = AuthorizationSnapshot | InvalidCredentials | VerificationUnavailable


class CredentialSlot(Protocol[_CredentialT]):
    """Synchronous, non-blocking credential extraction boundary."""

    name: str

    def extract(self, connection: ASGIConnection[Any, Any, Any, Any]) -> CredentialExtraction[_CredentialT]:
        """Extract at most one credential from the connection.

        Runs synchronously on every request, so it must not block or perform I/O.

        Args:
            connection: The incoming connection.

        Returns:
            The presented credential, ``NoCredentials`` when this slot is empty,
            or ``InvalidCredentials`` when the slot is malformed.
        """
        ...  # pragma: no cover


class RequestAuthenticator(Protocol[_RequestCredentialT_contra, _ClaimsT]):
    """Async credential verification boundary."""

    name: str
    slot: str
    participates_by_default: bool

    async def authenticate(
        self, credential: _RequestCredentialT_contra, connection: ASGIConnection[Any, Any, Any, Any]
    ) -> AuthenticationOutcome[_ClaimsT]:
        """Verify a credential without resolving application identity.

        Args:
            credential: The value produced by this authenticator's slot.
            connection: The incoming connection.

        Returns:
            The verified claims, or a sanitized outcome describing why
            verification did not succeed.
        """
        ...  # pragma: no cover


class IdentityResolver(Protocol[_ResolverClaimsT_contra, _UserT]):
    """Async mapping from verified claims to one application principal."""

    async def resolve(self, claims: _ResolverClaimsT_contra) -> IdentityResolution[_UserT]:
        """Resolve verified claims into a principal or sanitized resolution outcome.

        Args:
            claims: The claims produced by the paired authenticator.

        Returns:
            The application principal, or a sanitized outcome when the claims
            cannot be mapped to one.
        """
        ...  # pragma: no cover


class AuthorizationResolver(Protocol[_UserT]):
    """Application-owned resolution of authorization for one verified principal."""

    async def resolve(self, principal: Principal[_UserT]) -> AuthorizationResolution:
        """Load one immutable application authorization snapshot.

        Args:
            principal: The same-subject principal established by authentication.

        Returns:
            Application authorization or a sanitized rejection/outage outcome.
        """
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class AuthenticationMechanism(Generic[CredentialT, ClaimsT, UserT]):
    """Pair one slot authenticator with its identity resolver."""

    authenticator: RequestAuthenticator[CredentialT, ClaimsT]
    resolver: IdentityResolver[ClaimsT, UserT]
    scheme_name: str | None = None
    security_scheme: SecurityScheme | None = field(default=None, hash=False)
    session_capable: bool = False

    def __post_init__(self) -> None:
        """Validate the optional native OpenAPI scheme pair."""
        if (self.scheme_name is None) is not (self.security_scheme is None):
            message = "Authentication mechanism OpenAPI scheme name and definition must be configured together"
            raise ImproperlyConfiguredException(detail=message)
        if self.scheme_name is not None:
            object.__setattr__(self, "scheme_name", _normalize_name(self.scheme_name, "OpenAPI security scheme name"))


@dataclass(frozen=True, slots=True)
class AuthenticationRegistry(Generic[UserT]):
    """Validate and compile deterministic credential-slot ownership."""

    slots: Sequence[CredentialSlot[Any]] = ()
    mechanisms: Sequence[AuthenticationMechanism[Any, Any, UserT]] = ()
    authorization_resolver: AuthorizationResolver[UserT] | None = field(default=None, repr=False, compare=False)
    require_default: bool = False
    _slots_by_name: Mapping[str, CredentialSlot[Any]] = field(init=False, repr=False, compare=False)
    _mechanisms_by_name: Mapping[str, AuthenticationMechanism[Any, Any, UserT]] = field(
        init=False, repr=False, compare=False
    )
    _mechanisms_by_slot: Mapping[str, AuthenticationMechanism[Any, Any, UserT]] = field(
        init=False, repr=False, compare=False
    )
    _slot_names: tuple[str, ...] = field(init=False, repr=False)
    _mechanism_names: tuple[str, ...] = field(init=False, repr=False)
    _default_mechanism_names: tuple[str, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Normalize names and reject ambiguous ownership before startup."""
        slots = tuple(self.slots)
        mechanisms = tuple(self.mechanisms)
        _validate_authorization_resolver(self.authorization_resolver)
        slots_by_name: dict[str, CredentialSlot[Any]] = {}
        slot_names: list[str] = []
        for slot in slots:
            name = _normalize_name(slot.name, "Credential slot name")
            if name in slots_by_name:
                message = f"Duplicate credential slot: {name}"
                raise ImproperlyConfiguredException(detail=message)
            slots_by_name[name] = slot
            slot_names.append(name)

        mechanisms_by_name: dict[str, AuthenticationMechanism[Any, Any, UserT]] = {}
        mechanisms_by_slot: dict[str, AuthenticationMechanism[Any, Any, UserT]] = {}
        mechanism_names: list[str] = []
        default_names: list[str] = []
        for mechanism in mechanisms:
            name = _normalize_name(mechanism.authenticator.name, "Authentication mechanism name")
            slot_name = _normalize_name(mechanism.authenticator.slot, "Credential slot reference")
            if name in mechanisms_by_name:
                message = f"Duplicate authentication mechanism: {name}"
                raise ImproperlyConfiguredException(detail=message)
            if slot_name not in slots_by_name:
                message = f"Authentication mechanism {name} references undefined credential slot {slot_name}"
                raise ImproperlyConfiguredException(detail=message)
            if slot_name in mechanisms_by_slot:
                if slot_name == "authorization.bearer":
                    message = "authorization.bearer must have one composite authenticator owner"
                else:
                    message = f"Duplicate owner for credential slot: {slot_name}"
                raise ImproperlyConfiguredException(detail=message)
            mechanisms_by_name[name] = mechanism
            mechanisms_by_slot[slot_name] = mechanism
            mechanism_names.append(name)
            if mechanism.authenticator.participates_by_default:
                default_names.append(name)

        if self.require_default and not default_names:
            message = "A required default authentication plan needs at least one participating mechanism"
            raise ImproperlyConfiguredException(detail=message)

        object.__setattr__(self, "slots", slots)
        object.__setattr__(self, "mechanisms", mechanisms)
        object.__setattr__(self, "_slots_by_name", MappingProxyType(slots_by_name))
        object.__setattr__(self, "_mechanisms_by_name", MappingProxyType(mechanisms_by_name))
        object.__setattr__(self, "_mechanisms_by_slot", MappingProxyType(mechanisms_by_slot))
        object.__setattr__(self, "_slot_names", tuple(slot_names))
        object.__setattr__(self, "_mechanism_names", tuple(mechanism_names))
        object.__setattr__(self, "_default_mechanism_names", tuple(default_names))

    @property
    def slot_names(self) -> tuple[str, ...]:
        """Return normalized slot names in configuration order."""
        return self._slot_names

    @property
    def mechanism_names(self) -> tuple[str, ...]:
        """Return normalized mechanism names in configuration order."""
        return self._mechanism_names

    @property
    def default_mechanism_names(self) -> tuple[str, ...]:
        """Return default-participating mechanism names in configuration order."""
        return self._default_mechanism_names

    def get_slot(self, name: str) -> CredentialSlot[Any]:
        """Look up an owned slot by normalized name.

        Args:
            name: The slot name, normalized before lookup.

        Returns:
            The registered slot.
        """
        return self._slots_by_name[_normalize_name(name, "Credential slot name")]

    def get_mechanism(self, name: str) -> AuthenticationMechanism[Any, Any, UserT]:
        """Look up a mechanism by normalized name.

        Args:
            name: The mechanism name, normalized before lookup.

        Returns:
            The registered mechanism.
        """
        return self._mechanisms_by_name[_normalize_name(name, "Authentication mechanism name")]

    def get_mechanism_for_slot(self, name: str) -> AuthenticationMechanism[Any, Any, UserT] | None:
        """Look up the sole mechanism owning a normalized slot.

        Args:
            name: The slot name, normalized before lookup.

        Returns:
            The owning mechanism, or ``None`` when no mechanism claims the slot.
        """
        return self._mechanisms_by_slot.get(_normalize_name(name, "Credential slot name"))

    def evaluator(self) -> "_AuthenticationEvaluator[UserT]":
        """Create a stateless evaluator bound to this compiled registry.

        Returns:
            An evaluator that may be shared across requests.
        """
        return _AuthenticationEvaluator(self)


@dataclass(frozen=True, slots=True)
class SecurityRuntimePlan:
    """Compiled per-route authentication work for the runtime middleware."""

    authenticate: bool = True
    bypass_authentication: bool = False
    required: bool = False
    participant_names: frozenset[str] | None = None
    alternatives: tuple[tuple[MechanismRequirement, ...], ...] = ()
    allow_anonymous: bool = False
    csrf_required: bool | None = None
    csrf_enforcement: str | None = None

    def __post_init__(self) -> None:
        """Freeze explicit participant names."""
        alternatives = tuple(tuple(alternative) for alternative in self.alternatives)
        object.__setattr__(self, "alternatives", alternatives)
        if alternatives and self.participant_names is None:
            object.__setattr__(
                self,
                "participant_names",
                frozenset(requirement.name for alternative in alternatives for requirement in alternative),
            )
        if self.participant_names is not None:
            object.__setattr__(
                self,
                "participant_names",
                frozenset(_normalize_name(name, "Authentication participant") for name in self.participant_names),
            )


@dataclass(frozen=True, slots=True)
class OwnedSessionBackend:
    """Native Litestar session middleware and its configured backend."""

    middleware: DefineMiddleware
    backend: object


@dataclass(frozen=True, slots=True)
class SecurityRuntimeConfig(Generic[UserT]):
    """Per-application runtime state consumed by security middleware."""

    registry: AuthenticationRegistry[UserT]
    owned_session_backend: OwnedSessionBackend | None = None
    websocket: WebSocketSecurityConfig = field(default_factory=WebSocketSecurityConfig)
    plan_lookup: Callable[[Scope], SecurityRuntimePlan] | None = field(default=None, repr=False)
    _default_plan: SecurityRuntimePlan = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Compile the implicit route plan once."""
        participants = frozenset(self.registry.default_mechanism_names)
        object.__setattr__(
            self,
            "_default_plan",
            SecurityRuntimePlan(
                authenticate=bool(participants), required=bool(participants), participant_names=participants or None
            ),
        )

    def resolve_plan(self, scope: Scope) -> SecurityRuntimePlan:
        """Resolve generated OPTIONS, custom lookup, route opt, then default."""
        if _is_generated_options(scope):
            return SecurityRuntimePlan(authenticate=False)
        if self.plan_lookup is not None:
            return self.plan_lookup(scope)
        route_handler = cast("Mapping[str, object]", scope).get("route_handler")
        opt = cast("Mapping[str, object] | None", getattr(route_handler, "opt", None))
        if isinstance(opt, Mapping) and isinstance(plan := opt.get(RUNTIME_PLAN_OPT_KEY), SecurityRuntimePlan):
            return plan
        return self._default_plan


class SecurityMiddleware(Generic[UserT]):
    """Initialize typed anonymous state, then evaluate the compiled route plan."""

    __slots__ = ("app", "config", "evaluator")

    def __init__(self, app: ASGIApp, config: SecurityRuntimeConfig[UserT]) -> None:
        """Initialize security evaluation for the next ASGI app."""
        self.app = app
        self.config = config
        self.evaluator = config.registry.evaluator()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Populate connection identity/context before every bypass or failure."""
        session = cast("SessionHandle", LitestarSessionHandle(scope) if "session" in scope else NullSessionHandle())
        scope["user"] = Principal[UserT].anonymous()
        scope["auth"] = SecurityContext(session=session)
        plan = self.config.resolve_plan(scope)
        if scope["type"] == ScopeType.WEBSOCKET:
            await self._handle_websocket(scope, receive, send, session=session, plan=plan)
            return
        if plan.authenticate:
            connection = ASGIConnection[Any, Principal[UserT], SecurityContext, Any](
                scope=scope, receive=receive, send=send
            )
            principal, context = await self.evaluator.evaluate(connection, session, plan=plan)
            scope["user"] = principal
            scope["auth"] = context
        await self.app(scope, receive, send)

    async def _handle_websocket(  # noqa: C901, PLR0915 - handshake, hook, and close phases remain explicit
        self, scope: Scope, receive: Receive, send: Send, *, session: SessionHandle, plan: SecurityRuntimePlan
    ) -> None:
        if plan.bypass_authentication:
            await self.app(scope, receive, send)
            return
        connection = ASGIConnection[Any, Principal[UserT], SecurityContext, Any](
            scope=scope, receive=receive, send=send
        )
        extracted = self.evaluator.extract(connection)
        uses_cookie_credentials = any(
            isinstance(extraction, PresentedCredential)
            and (mechanism := self.config.registry.get_mechanism_for_slot(slot_name)) is not None
            and mechanism.session_capable
            for slot_name, extraction in extracted
        )
        try:
            handshake = extract_websocket_handshake(
                connection, config=self.config.websocket, uses_cookie_credentials=uses_cookie_credentials
            )
            if handshake.connect_token is not None:
                principal, context = await self._authenticate_connect_token(
                    scope=scope,
                    connection=connection,
                    handshake=handshake,
                    session=session,
                    plan=plan,
                    extracted=extracted,
                )
                scope["user"] = principal
                scope["auth"] = context
            elif plan.authenticate:
                principal, context = await self.evaluator.evaluate(connection, session, plan=plan, extracted=extracted)
                scope["user"] = principal
                scope["auth"] = context
        except WebSocketException as exc:
            reason = (
                "origin_denied"
                if exc.code == self.config.websocket.close_codes.unauthorized
                else "authentication_required"
            )
            await close_websocket(send, code=exc.code, reason=reason)
            return
        except NotAuthorizedException:
            await close_websocket(
                send, code=self.config.websocket.close_codes.unauthenticated, reason="authentication_required"
            )
            return
        except (ServiceUnavailableException, WebSocketConnectTokenUnavailableError):
            await close_websocket(
                send, code=self.config.websocket.close_codes.verification_unavailable, reason="verification_unavailable"
            )
            return
        coordinator = WebSocketCloseCoordinator(send)
        current_context = cast("SecurityContext", scope["auth"])
        route_name = _websocket_route_name(scope)
        revocation_hook: Callable[[], Awaitable[None]] | None = None
        refresh_hook: Callable[[], Awaitable[None]] | None = None
        if (
            self.config.websocket.revocation_source is not None
            and cast("Principal[Any]", scope["user"]).is_authenticated
        ):
            source = self.config.websocket.revocation_source
            binding = _websocket_binding(
                principal=cast("Principal[Any]", scope["user"]), context=current_context, route_name=route_name
            )

            async def wait_for_revocation() -> None:
                await source.wait(binding)

            revocation_hook = wait_for_revocation

        if self.config.websocket.snapshot_refresher is not None:
            refresher = self.config.websocket.snapshot_refresher

            async def refresh_authorization() -> None:
                nonlocal current_context
                principal = cast("Principal[UserT]", scope["user"])
                snapshot = await refresher.refresh(
                    principal=principal, previous=current_context.authorization, route_name=route_name
                )
                if snapshot.__class__ is not AuthorizationSnapshot:
                    raise ServiceUnavailableException(detail=_AUTHENTICATION_UNAVAILABLE)
                current_context = replace(
                    current_context, authorization=resolve_authorization(snapshot, current_context.restrictions)
                )
                scope["auth"] = current_context
                route_handler = cast("Any", cast("Mapping[str, object]", scope).get("route_handler"))
                if route_handler.resolve_guards():
                    await route_handler.authorize_connection(connection=connection)

            refresh_hook = refresh_authorization

        async def send_with_guard_mapping(message: Message) -> None:
            if (
                message["type"] == "websocket.close"
                and coordinator.state == "pending"
                and message.get("code") == _LITESTAR_INTERNAL_ERROR_CLOSE
                and message.get("reason") in {"Authentication required", "Permission denied"}
            ):
                message = {
                    "type": "websocket.close",
                    "code": self.config.websocket.close_codes.unauthorized,
                    "reason": "authorization_denied",
                }
            await coordinator.send(message)

        try:

            async def handle() -> None:
                await self.app(scope, receive, send_with_guard_mapping)

            await supervise_websocket_lifetime(
                handle,
                expires_at=current_context.expires_at,
                coordinator=coordinator,
                unauthenticated_close_code=self.config.websocket.close_codes.unauthenticated,
                unauthorized_close_code=self.config.websocket.close_codes.unauthorized,
                unavailable_close_code=self.config.websocket.close_codes.verification_unavailable,
                revocation_wait=revocation_hook,
                refresh=refresh_hook,
                refresh_interval=self.config.websocket.refresh_interval,
                clock=self.config.websocket.clock,
                sleeper=self.config.websocket.sleeper,
            )
        except (NotAuthorizedException, PermissionDeniedException):
            await coordinator.close(code=self.config.websocket.close_codes.unauthorized, reason="authorization_denied")

    async def _authenticate_connect_token(  # noqa: PLR0913 - explicit routed inputs prevent reparsing and hidden state
        self,
        *,
        scope: Scope,
        connection: ASGIConnection[Any, Any, Any, Any],
        handshake: WebSocketHandshake,
        session: SessionHandle,
        plan: SecurityRuntimePlan,
        extracted: Sequence[tuple[str, CredentialExtraction[Any]]],
    ) -> tuple[Principal[UserT], SecurityContext]:
        connect_token_store = self.config.websocket.connect_token_store
        route_handler = cast("Mapping[str, object]", scope).get("route_handler")
        route_name = cast("str | None", getattr(route_handler, "name", None)) or cast(
            "str", getattr(route_handler, "handler_name", "")
        )
        if connect_token_store is None or handshake.origin is None or not route_name or handshake.connect_token is None:
            raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)
        connect_token = await WebSocketConnectTokenService(
            store=connect_token_store, ttl=self.config.websocket.connect_token_ttl, clock=self.config.websocket.clock
        ).consume(
            handshake.connect_token,
            route_name=route_name,
            origin=handshake.origin,
            policy_fingerprint=websocket_policy_fingerprint(plan),
        )
        if connect_token is None:
            raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)
        non_connect_token_plan = replace(plan, required=False, alternatives=(), allow_anonymous=True)
        principal, context = await self.evaluator.evaluate(
            connection, session, plan=non_connect_token_plan, extracted=extracted
        )
        return await self._merge_connect_token(connect_token, principal=principal, context=context, session=session)

    async def _merge_connect_token(
        self,
        connect_token: WebSocketConnectTokenRecord,
        *,
        principal: Principal[UserT],
        context: SecurityContext,
        session: SessionHandle,
    ) -> tuple[Principal[UserT], SecurityContext]:
        if principal.is_authenticated:
            if principal.id != connect_token.subject_id:
                raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)
            authorization = resolve_authorization(context.authorization, (connect_token.restrictions,))
        else:
            principal = Principal(id=connect_token.subject_id)
            resolver = self.config.registry.authorization_resolver
            if resolver is None:
                authorization = AuthorizationSnapshot()
            else:
                try:
                    resolution = await resolver.resolve(principal)
                except Exception:  # noqa: BLE001 - a raising authorization resolver fails closed as one 503
                    raise ServiceUnavailableException(detail=_AUTHENTICATION_UNAVAILABLE) from None
                if isinstance(resolution, VerificationUnavailable):
                    raise ServiceUnavailableException(detail=_AUTHENTICATION_UNAVAILABLE)
                if isinstance(resolution, InvalidCredentials):
                    raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)
                authorization = resolution
            authorization = resolve_authorization(authorization, (connect_token.restrictions,))
        evidence = AuthenticationEvidence(
            mechanism="websocket-connect-token",
            slot=self.config.websocket.connect_token_query_parameter,
            authenticated_at=connect_token.issued_at,
            expires_at=connect_token.expires_at,
            methods=frozenset({"websocket-connect-token"}),
        )
        return principal, SecurityContext(
            session=session,
            evidence=(*context.evidence, evidence),
            authorization=authorization,
            restrictions=(*context.restrictions, connect_token.restrictions),
        )


class SecurityMiddlewareWrapper(Generic[UserT]):
    """Lazily build session -> native exception -> security."""

    __slots__ = ("_wrapped", "app", "config")

    def __init__(self, app: ASGIApp, config: SecurityRuntimeConfig[UserT]) -> None:
        """Initialize the lazy first-party middleware composition."""
        self.app = app
        self.config = config
        self._wrapped: ASGIApp | None = None

    def _build_stack(self) -> ASGIApp:
        security = SecurityMiddleware(app=self.app, config=self.config)
        wrapped: ASGIApp = ExceptionHandlerMiddleware(app=security, debug=None)
        if self.config.owned_session_backend is not None:
            session = self.config.owned_session_backend
            wrapped = session.middleware.middleware(app=wrapped, backend=session.backend)
        return wrapped

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Build the wrapper once and dispatch the connection."""
        if self._wrapped is None:
            self._wrapped = self._build_stack()

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                scope_data = cast("dict[str, object]", scope)
                queued = cast("list[tuple[bytes, bytes]]", scope_data.pop(_SECURITY_RESPONSE_HEADERS_SCOPE_KEY, []))
                message["headers"] = [*message.get("headers", []), *queued]
            await send(message)

        await self._wrapped(scope, receive, send_with_security_headers)


def _normalize_name(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized:
        message = f"{label} must not be blank"
        raise ImproperlyConfiguredException(detail=message)
    return normalized


def _validate_policy(policy: object) -> None:
    if not isinstance(policy, (PublicPolicy, ExcludePolicy, MechanismPolicy, OptionalPolicy)):
        message = "Authentication policy must be created by a Litestar Security policy helper"
        raise ImproperlyConfiguredException(detail=message)


def _normalize_requirements(
    requirements: Sequence[str | MechanismRequirement], expression: str
) -> tuple[MechanismRequirement, ...]:
    if not requirements:
        message = f"{expression} authentication policy requires at least one mechanism"
        raise ImproperlyConfiguredException(detail=message)
    normalized: list[MechanismRequirement] = []
    names: set[str] = set()
    for requirement in requirements:
        item = mechanism(requirement) if isinstance(requirement, str) else requirement
        if item.name in names:
            message = f"Duplicate mechanism requirement: {item.name}"
            raise ImproperlyConfiguredException(detail=message)
        names.add(item.name)
        normalized.append(item)
    return tuple(normalized)


@dataclass(frozen=True, slots=True)
class _ResolvedAuthentication(Generic[UserT]):
    name: str
    outcome: Authenticated[Any]
    principal: Principal[UserT]


class _AuthenticationEvaluator(Generic[UserT]):
    """Evaluate every presented configured credential in deterministic phases."""

    __slots__ = ("registry",)

    def __init__(self, registry: AuthenticationRegistry[UserT]) -> None:
        self.registry = registry

    async def evaluate(  # noqa: PLR0913 - direct controls and pre-extracted input avoid duplicate credential parsing
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        session: SessionHandle,
        *,
        required: bool = False,
        participant_names: AbstractSet[str] | None = None,
        plan: SecurityRuntimePlan | None = None,
        extracted: Sequence[tuple[str, CredentialExtraction[Any]]] | None = None,
    ) -> tuple[Principal[UserT], SecurityContext]:
        """Evaluate one authenticating request without leaking credential details."""
        if plan is not None:
            if not plan.authenticate:
                return Principal[UserT].anonymous(), SecurityContext(session=session)
            required = plan.required
            participant_names = plan.participant_names
        participants = self._participant_names(participant_names)
        extracted = tuple(extracted) if extracted is not None else self.extract(connection)
        outcomes, invalid = await self._authenticate(extracted, connection)
        self._raise_terminal(outcomes, invalid=invalid)
        resolved = await self._resolve(outcomes)

        principal = resolved[0].principal if resolved else Principal[UserT].anonymous()
        if resolved and any(result.principal.id != principal.id for result in resolved[1:]):
            raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)
        if plan is not None and plan.alternatives:
            successful = frozenset(result.name for result in resolved)
            satisfied = any(
                all(requirement.name in successful for requirement in alternative) for alternative in plan.alternatives
            )
            if not satisfied:
                if plan.allow_anonymous and not resolved:
                    return principal, SecurityContext(session=session)
                raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)
        elif required and not any(result.name in participants for result in resolved):
            raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)
        if not resolved:
            return principal, SecurityContext(session=session)

        authenticated = tuple(result.outcome for result in resolved)
        authorization = await self._resolve_authorization(principal, authenticated)
        return principal, SecurityContext(
            session=session,
            evidence=tuple(outcome.evidence for outcome in authenticated),
            authorization=authorization,
            restrictions=tuple(outcome.restrictions for outcome in authenticated),
        )

    async def _resolve_authorization(
        self, principal: Principal[UserT], outcomes: Sequence[Authenticated[Any]]
    ) -> AuthorizationSnapshot:
        resolver = self.registry.authorization_resolver
        if resolver is None:
            snapshot = _merge_authorization(outcomes)
        else:
            try:
                resolution = await resolver.resolve(principal)
            except Exception:  # noqa: BLE001 - a raising authorization resolver fails closed as one 503
                raise ServiceUnavailableException(detail=_AUTHENTICATION_UNAVAILABLE) from None
            if isinstance(resolution, VerificationUnavailable):
                raise ServiceUnavailableException(detail=_AUTHENTICATION_UNAVAILABLE)
            if isinstance(resolution, InvalidCredentials):
                raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)
            snapshot = resolution
        return resolve_authorization(snapshot, tuple(outcome.restrictions for outcome in outcomes))

    def _participant_names(self, participant_names: AbstractSet[str] | None) -> frozenset[str]:
        if participant_names is None:
            return frozenset(self.registry.default_mechanism_names)
        return frozenset(_normalize_name(name, "Authentication participant") for name in participant_names)

    def extract(
        self, connection: ASGIConnection[Any, Any, Any, Any]
    ) -> tuple[tuple[str, CredentialExtraction[Any]], ...]:
        """Extract every configured credential slot exactly once."""
        extracted: list[tuple[str, CredentialExtraction[Any]]] = []
        for slot_name in self.registry.slot_names:
            try:
                extraction = self.registry.get_slot(slot_name).extract(connection)
            except Exception:  # noqa: BLE001 - a raising credential slot fails closed as one 503
                raise ServiceUnavailableException(detail=_AUTHENTICATION_UNAVAILABLE) from None
            extracted.append((slot_name, extraction))
        return tuple(extracted)

    async def _authenticate(
        self, extracted: Sequence[tuple[str, CredentialExtraction[Any]]], connection: ASGIConnection[Any, Any, Any, Any]
    ) -> tuple[list[tuple[str, AuthenticationOutcome[Any]]], bool]:
        invalid = any(isinstance(extraction, InvalidCredentials) for _, extraction in extracted)
        outcomes: list[tuple[str, AuthenticationOutcome[Any]]] = []
        for slot_name, extraction in extracted:
            if not isinstance(extraction, PresentedCredential):
                continue
            mechanism = self.registry.get_mechanism_for_slot(slot_name)
            if mechanism is None:
                invalid = True
                continue
            try:
                outcome = await mechanism.authenticator.authenticate(extraction.value, connection)
            except Exception:  # noqa: BLE001 - a raising authenticator fails closed as one 503
                raise ServiceUnavailableException(detail=_AUTHENTICATION_UNAVAILABLE) from None
            name = _normalize_name(mechanism.authenticator.name, "Authentication mechanism name")
            if isinstance(outcome, NoCredentials):
                invalid = True
            else:
                outcomes.append((name, outcome))
        return outcomes, invalid

    @staticmethod
    def _raise_terminal(outcomes: Sequence[tuple[str, AuthenticationOutcome[Any]]], *, invalid: bool) -> None:
        if any(isinstance(outcome, VerificationUnavailable) for _, outcome in outcomes):
            raise ServiceUnavailableException(detail=_AUTHENTICATION_UNAVAILABLE)
        if invalid or any(isinstance(outcome, InvalidCredentials) for _, outcome in outcomes):
            raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)

    async def _resolve(
        self, outcomes: Sequence[tuple[str, AuthenticationOutcome[Any]]]
    ) -> list[_ResolvedAuthentication[UserT]]:
        resolutions: list[tuple[str, Authenticated[Any], IdentityResolution[UserT]]] = []
        for name, outcome in outcomes:
            authenticated = cast("Authenticated[Any]", outcome)
            mechanism = self.registry.get_mechanism(name)
            try:
                resolution = await mechanism.resolver.resolve(authenticated.claims)
            except Exception:  # noqa: BLE001 - a raising identity resolver fails closed as one 503
                raise ServiceUnavailableException(detail=_AUTHENTICATION_UNAVAILABLE) from None
            resolutions.append((name, authenticated, resolution))
        if any(isinstance(resolution, VerificationUnavailable) for _, _, resolution in resolutions):
            raise ServiceUnavailableException(detail=_AUTHENTICATION_UNAVAILABLE)
        if any(isinstance(resolution, InvalidCredentials) for _, _, resolution in resolutions):
            raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)
        resolved: list[_ResolvedAuthentication[UserT]] = []
        for name, authenticated, resolution in resolutions:
            principal = cast("Principal[UserT]", resolution)
            if not principal.is_authenticated:
                raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)
            resolved.append(_ResolvedAuthentication(name=name, outcome=authenticated, principal=principal))
        return resolved


def _validate_authorization_resolver(resolver: object | None) -> None:
    if resolver is not None and not callable(getattr(resolver, "resolve", None)):
        message = "Authorization resolver must define resolve"
        raise ImproperlyConfiguredException(detail=message)


def _merge_authorization(outcomes: Sequence[Authenticated[Any]]) -> AuthorizationSnapshot:
    scopes: set[str] = set()
    roles: set[str] = set()
    capabilities: set[str] = set()
    team_roles: dict[str, set[str]] = {}
    tenant_ids: set[str] = set()
    resources: set[ResourcePermission] = set()
    attributes: dict[str, object] = {}
    for outcome in outcomes:
        scopes.update(outcome.grants.scopes)
        roles.update(outcome.grants.roles)
        capabilities.update(outcome.grants.capabilities)
        for team_id, grants in outcome.grants.team_roles.items():
            team_roles.setdefault(team_id, set()).update(grants)
        tenant_ids.update(outcome.grants.tenant_ids)
        resources.update(outcome.grants.resources)
        attributes.update(outcome.grants.attributes)
    return AuthorizationSnapshot(
        scopes=frozenset(scopes),
        roles=frozenset(roles),
        capabilities=frozenset(capabilities),
        team_roles={team_id: frozenset(grants) for team_id, grants in team_roles.items()},
        tenant_ids=frozenset(tenant_ids),
        resources=frozenset(resources),
        attributes=attributes,
    )


def _is_generated_options(scope: Scope) -> bool:
    if scope["type"] != ScopeType.HTTP:
        return False
    http_scope: HTTPScope = scope
    if http_scope["method"] != "OPTIONS":
        return False
    route_handler = cast("Mapping[str, object]", scope).get("route_handler")
    return is_generated_options_handler(getattr(route_handler, "fn", None))


def _websocket_route_name(scope: Scope) -> str:
    route_handler = cast("Mapping[str, object]", scope).get("route_handler")
    return cast("str | None", getattr(route_handler, "name", None)) or cast(
        "str", getattr(route_handler, "handler_name", "")
    )


def _websocket_binding(*, principal: Principal[Any], context: SecurityContext, route_name: str) -> WebSocketBinding:
    session_value = context.session.get("_litestar_security")
    session_mapping = cast("Mapping[str, object]", session_value) if isinstance(session_value, Mapping) else None
    session_id = cast("str | None", session_mapping.get("session_id")) if session_mapping is not None else None
    return WebSocketBinding(
        connection_id=token_urlsafe(16),
        subject_id=cast("str", principal.id),
        credential_ids=frozenset(f"{evidence.mechanism}:{evidence.slot}" for evidence in context.evidence),
        session_id=session_id,
        route_name=route_name,
    )
