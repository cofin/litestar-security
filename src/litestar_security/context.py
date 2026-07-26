"""Immutable request security context contracts."""

from collections.abc import Mapping
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Generic, Protocol, TypeVar, runtime_checkable

from litestar.exceptions import NotAuthorizedException

__all__ = (
    "AuthenticationEvidence",
    "AuthorizationSnapshot",
    "CredentialRestrictions",
    "Principal",
    "SecurityContext",
    "SessionHandle",
)

UserT = TypeVar("UserT")


def _normalize_text(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized:
        msg = f"{label} must not be blank"
        raise ValueError(msg)
    return normalized


def _normalize_values(values: AbstractSet[str], label: str) -> frozenset[str]:
    return frozenset(_normalize_text(value, label) for value in values)


def _normalize_optional_values(values: AbstractSet[str] | None, label: str) -> frozenset[str] | None:
    return None if values is None else _normalize_values(values, label)


def _normalize_datetime(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        msg = f"{label} must be timezone-aware"
        raise ValueError(msg)
    return value.astimezone(timezone.utc)


def _empty_team_roles() -> Mapping[str, frozenset[str]]:
    return MappingProxyType({})


def _empty_attributes() -> Mapping[str, object]:
    return MappingProxyType({})


@runtime_checkable
class SessionHandle(Protocol):
    """Uniform access to an optional native Litestar session."""

    @property
    def is_available(self) -> bool:
        """Return whether a session is attached."""
        ...  # pragma: no cover

    @property
    def can_persist(self) -> bool:
        """Return whether session mutations can persist."""
        ...  # pragma: no cover

    def get(self, key: str, default: object = None) -> object:
        """Read a session value."""
        ...  # pragma: no cover

    def set(self, key: str, value: object) -> None:
        """Store a session value."""
        ...  # pragma: no cover

    def pop(self, key: str, default: object = None) -> object:
        """Remove and return a session value."""
        ...  # pragma: no cover

    def clear(self) -> None:
        """Remove all session values."""
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class Principal(Generic[UserT]):
    """Stable identity envelope for anonymous, user, and service actors."""

    id: str | None
    display_name: str | None = None
    user: UserT | None = None

    def __post_init__(self) -> None:
        """Normalize and validate the identity envelope."""
        if self.id is None:
            if self.user is not None:
                msg = "Anonymous principals cannot contain an application user"
                raise ValueError(msg)
        else:
            object.__setattr__(self, "id", _normalize_text(self.id, "Principal id"))
        if self.display_name is not None:
            object.__setattr__(self, "display_name", _normalize_text(self.display_name, "Display name"))

    @classmethod
    def anonymous(cls) -> "Principal[UserT]":
        """Create an anonymous principal."""
        return cls(id=None)

    @property
    def is_authenticated(self) -> bool:
        """Return whether this principal has an authenticated identity."""
        return self.id is not None

    @property
    def has_user(self) -> bool:
        """Return whether an application user is attached."""
        return self.user is not None

    def require_user(self) -> UserT:
        """Return the application user or fail without revealing actor state."""
        if self.user is None:
            raise NotAuthorizedException(detail="Authentication required")
        return self.user


@dataclass(frozen=True, slots=True)
class AuthenticationEvidence:
    """Normalized evidence emitted by one successful authenticator."""

    mechanism: str
    slot: str
    authenticated_at: datetime
    expires_at: datetime | None = None
    methods: frozenset[str] = frozenset()
    traits: frozenset[str] = frozenset()
    acr: str | None = None
    amr: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Normalize evidence while retaining provider assurance details."""
        object.__setattr__(self, "mechanism", _normalize_text(self.mechanism, "Mechanism"))
        object.__setattr__(self, "slot", _normalize_text(self.slot, "Slot"))
        object.__setattr__(
            self, "authenticated_at", _normalize_datetime(self.authenticated_at, "Authenticated timestamp")
        )
        if self.expires_at is not None:
            object.__setattr__(self, "expires_at", _normalize_datetime(self.expires_at, "Expiry timestamp"))
        object.__setattr__(self, "methods", _normalize_values(self.methods, "Authentication method"))
        object.__setattr__(self, "traits", _normalize_values(self.traits, "Authentication trait"))
        if self.acr is not None:
            object.__setattr__(self, "acr", _normalize_text(self.acr, "ACR"))
        object.__setattr__(
            self, "amr", tuple(_normalize_text(method, "AMR method") for method in self.amr)
        )


@dataclass(frozen=True, slots=True)
class AuthorizationSnapshot:
    """Immutable application authorization data."""

    scopes: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset()
    capabilities: frozenset[str] = frozenset()
    team_roles: Mapping[str, frozenset[str]] = field(default_factory=_empty_team_roles)
    tenant_ids: frozenset[str] = frozenset()
    attributes: Mapping[str, object] = field(default_factory=_empty_attributes)

    def __post_init__(self) -> None:
        """Defensively normalize and freeze authorization inputs."""
        object.__setattr__(self, "scopes", _normalize_values(self.scopes, "Scope"))
        object.__setattr__(self, "roles", _normalize_values(self.roles, "Role"))
        object.__setattr__(self, "capabilities", _normalize_values(self.capabilities, "Capability"))
        object.__setattr__(
            self,
            "team_roles",
            MappingProxyType(
                {
                    _normalize_text(team_id, "Team id"): _normalize_values(roles, "Team role")
                    for team_id, roles in self.team_roles.items()
                }
            ),
        )
        object.__setattr__(self, "tenant_ids", _normalize_values(self.tenant_ids, "Tenant id"))
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class CredentialRestrictions:
    """Authorization bounds imposed by one credential."""

    scopes: frozenset[str] | None = None
    roles: frozenset[str] | None = None
    capabilities: frozenset[str] | None = None
    team_ids: frozenset[str] | None = None
    tenant_ids: frozenset[str] | None = None

    def __post_init__(self) -> None:
        """Normalize bounds while preserving unbounded versus empty."""
        object.__setattr__(self, "scopes", _normalize_optional_values(self.scopes, "Scope"))
        object.__setattr__(self, "roles", _normalize_optional_values(self.roles, "Role"))
        object.__setattr__(
            self, "capabilities", _normalize_optional_values(self.capabilities, "Capability")
        )
        object.__setattr__(self, "team_ids", _normalize_optional_values(self.team_ids, "Team id"))
        object.__setattr__(self, "tenant_ids", _normalize_optional_values(self.tenant_ids, "Tenant id"))


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Authentication evidence, authorization, and optional session capability."""

    session: SessionHandle
    evidence: tuple[AuthenticationEvidence, ...] = ()
    authorization: AuthorizationSnapshot = field(default_factory=AuthorizationSnapshot)

    def __post_init__(self) -> None:
        """Freeze caller-supplied evidence iterables."""
        object.__setattr__(self, "evidence", tuple(self.evidence))

    @property
    def expires_at(self) -> datetime | None:
        """Return the earliest bounded evidence expiry."""
        expirations = tuple(evidence.expires_at for evidence in self.evidence if evidence.expires_at is not None)
        return min(expirations) if expirations else None
