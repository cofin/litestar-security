"""Bearer token slots, selectors, and composite bearer authentication.

Slot selection resolves which configured issuer should verify a presented token.
It depends on verification but never on the key ring, so applications can compose
remote and local issuers through the same slot contract.
"""

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Generic, TypeVar

from litestar.connection import ASGIConnection
from litestar.openapi.spec import SecurityScheme

from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationOutcome,
    CredentialExtraction,
    CredentialSlot,
    IdentityResolution,
    IdentityResolver,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
)
from litestar_security.providers._internal import raise_config
from litestar_security.providers.jwt._claims import JWTClaims, JWTValidationConfig, normalize_audiences
from litestar_security.providers.jwt._internal import is_strict_identifier, strict_identifier
from litestar_security.providers.jwt._verification import JWTVerifier, UnverifiedJWTRoute, parse_unverified_jwt_route

__all__ = ("BearerSlotSelector", "BearerTokenSlot", "CompositeBearerConfig", "extend_composite_bearer")


UserT = TypeVar("UserT")


_ACCESS_TOKEN_TYPES = frozenset({"at+jwt", "application/at+jwt"})


_ASCII_CONTROL_LIMIT = 32


_ASCII_DELETE = 127


_BEARER_PREFIX_LENGTH = len(b"Bearer ")


@dataclass(frozen=True, slots=True)
class BearerSlotSelector:
    """Route unverified bearer metadata only to a configured trust domain."""

    issuers: frozenset[str]
    audiences: frozenset[str] = frozenset()
    token_types: frozenset[str] = _ACCESS_TOKEN_TYPES

    def __post_init__(self) -> None:
        """Normalize immutable selector values without broadening trust."""
        issuers = frozenset(strict_identifier(issuer) for issuer in self.issuers)
        audiences = frozenset(strict_identifier(audience) for audience in self.audiences)
        token_types = frozenset(strict_identifier(token_type).lower() for token_type in self.token_types)
        if not issuers:
            raise_config("Bearer selector issuers must not be empty")
        if not token_types:
            raise_config("Bearer selector token types must not be empty")
        object.__setattr__(self, "issuers", issuers)
        object.__setattr__(self, "audiences", audiences)
        object.__setattr__(self, "token_types", token_types)


@dataclass(frozen=True, slots=True)
class BearerTokenSlot:
    """Bind one logical bearer routing selector to one verifier."""

    name: str
    selector: BearerSlotSelector
    verifier: JWTVerifier[JWTClaims] = field(repr=False)

    def __post_init__(self) -> None:
        """Validate logical naming and verifier trust compatibility."""
        name = strict_identifier(self.name)
        verifier_config = getattr(self.verifier, "config", None)
        if not isinstance(verifier_config, JWTValidationConfig):
            raise_config(f"Bearer slot {name} verifier must expose JWTValidationConfig")
        selector = self.selector
        if (
            selector.issuers != frozenset({verifier_config.issuer})
            or (selector.audiences and not selector.audiences.issubset(verifier_config.audiences))
            or not selector.token_types.issubset(verifier_config.token_types)
        ):
            raise_config(f"Bearer slot {name} selector does not match verifier validation config")
        object.__setattr__(self, "name", name)


def extend_composite_bearer(
    mechanism: AuthenticationMechanism[str, JWTClaims, UserT],
    slot: BearerTokenSlot,
    resolver: IdentityResolver[JWTClaims, UserT],
) -> AuthenticationMechanism[str, JWTClaims, UserT]:
    """Extend one library-built composite while preserving one physical bearer owner.

    Only one mechanism may own the physical bearer slot, so an additional issuer
    extends the existing composite rather than registering a second reader.

    Args:
        mechanism: The mechanism built by :class:`CompositeBearerConfig`.
        slot: The additional trust slot to accept.
        resolver: The identity resolver for that slot's claims.

    Returns:
        The extended mechanism, still owning exactly one bearer slot.
    """
    authenticator = mechanism.authenticator
    if not isinstance(authenticator, _CompositeBearerAuthenticator):
        raise_config("Existing bearer mechanism was not built by CompositeBearerConfig")
    config = CompositeBearerConfig(
        mechanism_name=authenticator.config.mechanism_name,
        slots=(*authenticator.config.slots, slot),
        maximum_token_bytes=authenticator.config.maximum_token_bytes,
    )
    return AuthenticationMechanism(
        authenticator=_CompositeBearerAuthenticator(
            config=config, clock=authenticator.clock, participates_by_default=authenticator.participates_by_default
        ),
        resolver=_SelectedBearerResolver(selected_slot=slot.name, selected=resolver, fallback=mechanism.resolver),
        scheme_name=mechanism.scheme_name,
        security_scheme=mechanism.security_scheme,
        session_capable=mechanism.session_capable,
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class CompositeBearerConfig:
    """Own one bearer namespace and dispatch it to exactly one JWT verifier."""

    mechanism_name: str
    slots: tuple[BearerTokenSlot, ...]
    maximum_token_bytes: int = 16_384

    def __post_init__(self) -> None:
        """Freeze slots and reject deterministic startup ambiguity."""
        mechanism_name = strict_identifier(self.mechanism_name)
        slots = tuple(self.slots)
        if not slots:
            raise_config("Composite bearer authentication requires at least one slot")
        if self.maximum_token_bytes < 1:
            raise_config("Composite bearer maximum token bytes must be positive")
        names: set[str] = set()
        selectors: set[tuple[frozenset[str], frozenset[str], frozenset[str]]] = set()
        for slot in slots:
            if slot.name in names:
                raise_config(f"Duplicate bearer slot: {slot.name}")
            names.add(slot.name)
            selector = (slot.selector.issuers, slot.selector.audiences, slot.selector.token_types)
            if selector in selectors:
                raise_config(f"Bearer slot {slot.name} has an identical selector")
            selectors.add(selector)
        object.__setattr__(self, "mechanism_name", mechanism_name)
        object.__setattr__(self, "slots", slots)

    def build(
        self,
        resolver: IdentityResolver[JWTClaims, UserT],
        *,
        clock: Callable[[], datetime] = _utc_now,
        participates_by_default: bool = True,
        scheme_name: str | None = None,
    ) -> tuple[CredentialSlot[str], AuthenticationMechanism[str, JWTClaims, UserT]]:
        """Build one physical slot and one native bearer mechanism.

        Args:
            resolver: The identity resolver for verified claims.
            clock: The clock used for expiry decisions.
            participates_by_default: Include this mechanism in implicit ``required()``.
            scheme_name: The OpenAPI security scheme name to publish under.

        Returns:
            The credential slot paired with its mechanism.
        """
        if not callable(clock):
            raise_config("Composite bearer clock must be callable")
        credential_slot = _BearerCredentialSlot(maximum_token_bytes=self.maximum_token_bytes)
        authenticator = _CompositeBearerAuthenticator(
            config=self, clock=clock, participates_by_default=participates_by_default
        )
        mechanism: AuthenticationMechanism[str, JWTClaims, UserT] = AuthenticationMechanism(
            authenticator=authenticator,
            resolver=resolver,
            scheme_name=self.mechanism_name if scheme_name is None else scheme_name,
            security_scheme=SecurityScheme(type="http", scheme="bearer", bearer_format="JWT"),
        )
        return credential_slot, mechanism


@dataclass(frozen=True, slots=True)
class _SelectedBearerResolver(Generic[UserT]):
    selected_slot: str
    selected: IdentityResolver[JWTClaims, UserT] = field(repr=False)
    fallback: IdentityResolver[JWTClaims, UserT] = field(repr=False)

    async def resolve(self, claims: JWTClaims) -> IdentityResolution[UserT]:
        resolver = self.selected if claims.bearer_slot == self.selected_slot else self.fallback
        return await resolver.resolve(claims)


def _selector_matches(selector: BearerSlotSelector, route: UnverifiedJWTRoute) -> bool:
    issuer = route.payload.get("iss")
    token_type = route.header.get("typ")
    audiences = normalize_audiences(route.payload.get("aud"))
    return (
        isinstance(issuer, str)
        and is_strict_identifier(issuer)
        and issuer in selector.issuers
        and isinstance(token_type, str)
        and is_strict_identifier(token_type)
        and token_type.lower() in selector.token_types
        and audiences is not None
        and (not selector.audiences or bool(audiences.intersection(selector.audiences)))
    )


@dataclass(slots=True)
class _BearerCredentialSlot:
    maximum_token_bytes: int
    name: str = field(default="authorization.bearer", init=False)

    def extract(  # noqa: PLR0911 - preserve explicit sanitized outcomes at each security boundary
        self, connection: ASGIConnection[Any, Any, Any, Any]
    ) -> CredentialExtraction[str]:
        """Extract one exact bearer credential from raw ASGI headers."""
        authorization_values = tuple(
            value for name, value in connection.scope["headers"] if name.lower() == b"authorization"
        )
        if not authorization_values:
            return NoCredentials()
        if len(authorization_values) != 1:
            return InvalidCredentials()
        raw_value = authorization_values[0]
        if len(raw_value) > _BEARER_PREFIX_LENGTH + self.maximum_token_bytes:
            return InvalidCredentials()
        try:
            value = raw_value.decode("ascii")
        except (AttributeError, UnicodeDecodeError):
            return InvalidCredentials()
        if any(ord(character) < _ASCII_CONTROL_LIMIT or ord(character) == _ASCII_DELETE for character in value):
            return InvalidCredentials()
        scheme, separator, token = value.partition(" ")
        if (
            separator != " "
            or scheme.lower() != "bearer"
            or not token
            or " " in token
            or len(token.encode("ascii")) > self.maximum_token_bytes
        ):
            return InvalidCredentials()
        return PresentedCredential(token)


@dataclass(slots=True)
class _CompositeBearerAuthenticator:
    config: CompositeBearerConfig
    clock: Callable[[], datetime] = field(repr=False, compare=False)
    participates_by_default: bool = True
    slot: str = field(default="authorization.bearer", init=False)
    name: str = field(init=False)

    def __post_init__(self) -> None:
        """Copy the compiled mechanism name onto the protocol surface."""
        self.name = self.config.mechanism_name

    async def authenticate(
        self, credential: str, connection: ASGIConnection[Any, Any, Any, Any]
    ) -> AuthenticationOutcome[JWTClaims]:
        """Select one trust slot, verify once, and preserve structured failure."""
        del connection
        route = parse_unverified_jwt_route(credential, maximum_token_bytes=self.config.maximum_token_bytes)
        if isinstance(route, InvalidCredentials):
            return route
        matches = tuple(slot for slot in self.config.slots if _selector_matches(slot.selector, route))
        if len(matches) != 1:
            return InvalidCredentials(code="unknown_or_ambiguous_bearer_slot")
        selected = matches[0]
        outcome = await selected.verifier.verify(credential, now=self.clock())
        if isinstance(outcome, NoCredentials):
            return InvalidCredentials()
        if not isinstance(outcome, Authenticated):
            return outcome
        claims = replace(outcome.claims, bearer_slot=selected.name)
        return replace(
            outcome, claims=claims, evidence=replace(outcome.evidence, mechanism=self.name, slot=selected.name)
        )
