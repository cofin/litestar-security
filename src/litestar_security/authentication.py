"""Typed authentication contracts and deterministic mechanism registration."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Generic, Protocol, TypeAlias, TypeVar, cast

from litestar.connection import ASGIConnection
from litestar.enums import ScopeType
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException, ServiceUnavailableException
from litestar.middleware._internal.exceptions import ExceptionHandlerMiddleware

from litestar_security.context import (
    AuthenticationEvidence,
    AuthorizationSnapshot,
    CredentialRestrictions,
    LitestarSessionHandle,
    NullSessionHandle,
    Principal,
    SecurityContext,
    SessionHandle,
)

if TYPE_CHECKING:
    from litestar.middleware import DefineMiddleware
    from litestar.types import ASGIApp, HTTPScope, Receive, Scope, Send

__all__ = (
    "Authenticated",
    "AuthenticationMechanism",
    "AuthenticationOutcome",
    "AuthenticationRegistry",
    "CredentialExtraction",
    "CredentialSlot",
    "IdentityResolver",
    "InvalidCredentials",
    "NoCredentials",
    "OwnedSessionBackend",
    "PresentedCredential",
    "RequestAuthenticator",
    "SecurityMiddleware",
    "SecurityMiddlewareWrapper",
    "SecurityRuntimeConfig",
    "SecurityRuntimePlan",
    "VerificationUnavailable",
)

CredentialT = TypeVar("CredentialT")
ClaimsT = TypeVar("ClaimsT")
UserT = TypeVar("UserT")
_CredentialT = TypeVar("_CredentialT")
_ClaimsT = TypeVar("_ClaimsT")
_UserT = TypeVar("_UserT")
_RequestCredentialT_contra = TypeVar("_RequestCredentialT_contra", contravariant=True)
_ResolverClaimsT_contra = TypeVar("_ResolverClaimsT_contra", contravariant=True)

_AUTHENTICATION_REQUIRED = "Authentication required"
_AUTHENTICATION_UNAVAILABLE = "Authentication service unavailable"
_RUNTIME_PLAN_OPT_KEY = "litestar_security_plan"
_NATIVE_EXCEPTION_HANDLER = ExceptionHandlerMiddleware


def _normalize_name(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized:
        message = f"{label} must not be blank"
        raise ImproperlyConfiguredException(detail=message)
    return normalized


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


@dataclass(frozen=True, slots=True)
class VerificationUnavailable:
    """Indicate that a verifier cannot make a trustworthy decision."""

    code: str = "verification_unavailable"
    retry_after: int | None = None


CredentialExtraction: TypeAlias = NoCredentials | PresentedCredential[CredentialT] | InvalidCredentials
AuthenticationOutcome: TypeAlias = NoCredentials | Authenticated[ClaimsT] | InvalidCredentials | VerificationUnavailable


class CredentialSlot(Protocol[_CredentialT]):
    """Synchronous, non-blocking credential extraction boundary."""

    name: str

    def extract(self, connection: ASGIConnection[Any, Any, Any, Any]) -> CredentialExtraction[_CredentialT]:
        """Extract at most one credential from the connection."""
        ...  # pragma: no cover


class RequestAuthenticator(Protocol[_RequestCredentialT_contra, _ClaimsT]):
    """Async credential verification boundary."""

    name: str
    slot: str
    participates_by_default: bool

    async def authenticate(
        self, credential: _RequestCredentialT_contra, connection: ASGIConnection[Any, Any, Any, Any]
    ) -> AuthenticationOutcome[_ClaimsT]:
        """Verify a credential without resolving application identity."""
        ...  # pragma: no cover


class IdentityResolver(Protocol[_ResolverClaimsT_contra, _UserT]):
    """Async mapping from verified claims to one application principal."""

    async def resolve(self, claims: _ResolverClaimsT_contra) -> Principal[_UserT]:
        """Resolve verified claims into a stable principal."""
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class AuthenticationMechanism(Generic[CredentialT, ClaimsT, UserT]):
    """Pair one slot authenticator with its identity resolver."""

    authenticator: RequestAuthenticator[CredentialT, ClaimsT]
    resolver: IdentityResolver[ClaimsT, UserT]


@dataclass(frozen=True, slots=True)
class AuthenticationRegistry(Generic[UserT]):
    """Validate and compile deterministic credential-slot ownership."""

    slots: Sequence[CredentialSlot[Any]] = ()
    mechanisms: Sequence[AuthenticationMechanism[Any, Any, UserT]] = ()
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
        """Look up an owned slot by normalized name."""
        return self._slots_by_name[_normalize_name(name, "Credential slot name")]

    def get_mechanism(self, name: str) -> AuthenticationMechanism[Any, Any, UserT]:
        """Look up a mechanism by normalized name."""
        return self._mechanisms_by_name[_normalize_name(name, "Authentication mechanism name")]

    def get_mechanism_for_slot(self, name: str) -> AuthenticationMechanism[Any, Any, UserT] | None:
        """Look up the sole mechanism owning a normalized slot."""
        return self._mechanisms_by_slot.get(_normalize_name(name, "Credential slot name"))

    def evaluator(self) -> _AuthenticationEvaluator[UserT]:
        """Create a stateless evaluator bound to this compiled registry."""
        return _AuthenticationEvaluator(self)


@dataclass(frozen=True, slots=True)
class SecurityRuntimePlan:
    """Compiled per-route authentication work for the runtime middleware."""

    authenticate: bool = True
    required: bool = False
    participant_names: frozenset[str] | None = None

    def __post_init__(self) -> None:
        """Freeze explicit participant names."""
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
        if isinstance(opt, Mapping) and isinstance(plan := opt.get(_RUNTIME_PLAN_OPT_KEY), SecurityRuntimePlan):
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
        if plan.authenticate:
            connection = ASGIConnection[Any, Principal[UserT], SecurityContext, Any](
                scope=scope, receive=receive, send=send
            )
            principal, context = await self.evaluator.evaluate(
                connection, session, required=plan.required, participant_names=plan.participant_names
            )
            scope["user"] = principal
            scope["auth"] = context
        await self.app(scope, receive, send)


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
        await self._wrapped(scope, receive, send)


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

    async def evaluate(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        session: SessionHandle,
        *,
        required: bool,
        participant_names: AbstractSet[str] | None = None,
    ) -> tuple[Principal[UserT], SecurityContext]:
        """Evaluate one authenticating request without leaking credential details."""
        participants = self._participant_names(participant_names)
        extracted = self._extract(connection)
        outcomes, invalid = await self._authenticate(extracted, connection)
        self._raise_terminal(outcomes, invalid=invalid)
        resolved = await self._resolve(outcomes)

        if required and not any(result.name in participants for result in resolved):
            raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)
        if not resolved:
            return Principal[UserT].anonymous(), SecurityContext(session=session)

        principal = resolved[0].principal
        if any(result.principal.id != principal.id for result in resolved[1:]):
            raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)

        authenticated = tuple(result.outcome for result in resolved)
        authorization = _apply_restrictions(_merge_authorization(authenticated), _intersect_restrictions(authenticated))
        return principal, SecurityContext(
            session=session, evidence=tuple(outcome.evidence for outcome in authenticated), authorization=authorization
        )

    def _participant_names(self, participant_names: AbstractSet[str] | None) -> frozenset[str]:
        if participant_names is None:
            return frozenset(self.registry.default_mechanism_names)
        return frozenset(_normalize_name(name, "Authentication participant") for name in participant_names)

    def _extract(
        self, connection: ASGIConnection[Any, Any, Any, Any]
    ) -> tuple[tuple[str, CredentialExtraction[Any]], ...]:
        return tuple(
            (slot_name, self.registry.get_slot(slot_name).extract(connection)) for slot_name in self.registry.slot_names
        )

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
            outcome = await mechanism.authenticator.authenticate(extraction.value, connection)
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
        resolved: list[_ResolvedAuthentication[UserT]] = []
        for name, outcome in outcomes:
            authenticated = cast("Authenticated[Any]", outcome)
            mechanism = self.registry.get_mechanism(name)
            principal = await mechanism.resolver.resolve(authenticated.claims)
            if not principal.is_authenticated:
                raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)
            resolved.append(_ResolvedAuthentication(name=name, outcome=authenticated, principal=principal))
        return resolved


def _merge_authorization(outcomes: Sequence[Authenticated[Any]]) -> AuthorizationSnapshot:
    scopes: set[str] = set()
    roles: set[str] = set()
    capabilities: set[str] = set()
    team_roles: dict[str, set[str]] = {}
    tenant_ids: set[str] = set()
    attributes: dict[str, object] = {}
    for outcome in outcomes:
        scopes.update(outcome.grants.scopes)
        roles.update(outcome.grants.roles)
        capabilities.update(outcome.grants.capabilities)
        for team_id, grants in outcome.grants.team_roles.items():
            team_roles.setdefault(team_id, set()).update(grants)
        tenant_ids.update(outcome.grants.tenant_ids)
        attributes.update(outcome.grants.attributes)
    return AuthorizationSnapshot(
        scopes=frozenset(scopes),
        roles=frozenset(roles),
        capabilities=frozenset(capabilities),
        team_roles={team_id: frozenset(grants) for team_id, grants in team_roles.items()},
        tenant_ids=frozenset(tenant_ids),
        attributes=attributes,
    )


def _intersect_restrictions(outcomes: Sequence[Authenticated[Any]]) -> CredentialRestrictions:
    return CredentialRestrictions(
        scopes=_intersect_dimension(outcomes, "scopes"),
        roles=_intersect_dimension(outcomes, "roles"),
        capabilities=_intersect_dimension(outcomes, "capabilities"),
        team_ids=_intersect_dimension(outcomes, "team_ids"),
        tenant_ids=_intersect_dimension(outcomes, "tenant_ids"),
    )


def _intersect_dimension(outcomes: Sequence[Authenticated[Any]], name: str) -> frozenset[str] | None:
    bounds = tuple(value for outcome in outcomes if (value := getattr(outcome.restrictions, name)) is not None)
    if not bounds:
        return None
    intersection = set(bounds[0])
    for bound in bounds[1:]:
        intersection.intersection_update(bound)
    return frozenset(intersection)


def _apply_restrictions(grants: AuthorizationSnapshot, restrictions: CredentialRestrictions) -> AuthorizationSnapshot:
    return AuthorizationSnapshot(
        scopes=grants.scopes if restrictions.scopes is None else grants.scopes & restrictions.scopes,
        roles=grants.roles if restrictions.roles is None else grants.roles & restrictions.roles,
        capabilities=(
            grants.capabilities
            if restrictions.capabilities is None
            else grants.capabilities & restrictions.capabilities
        ),
        team_roles=(
            grants.team_roles
            if restrictions.team_ids is None
            else {team_id: roles for team_id, roles in grants.team_roles.items() if team_id in restrictions.team_ids}
        ),
        tenant_ids=(
            grants.tenant_ids if restrictions.tenant_ids is None else grants.tenant_ids & restrictions.tenant_ids
        ),
        attributes=grants.attributes,
    )


def _is_generated_options(scope: Scope) -> bool:
    if scope["type"] != ScopeType.HTTP:
        return False
    http_scope: HTTPScope = scope
    if http_scope["method"] != "OPTIONS":
        return False
    route_handler = cast("Mapping[str, object]", scope).get("route_handler")
    handler = getattr(route_handler, "fn", None)
    return (
        getattr(handler, "__module__", None) == "litestar.routes.http"
        and getattr(handler, "__name__", None) == "options_handler"
    )
