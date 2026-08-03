"""External service JWT verification and userless principal resolution."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import cast

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationOutcome,
    CredentialSlot,
    IdentityResolution,
    InvalidCredentials,
    VerificationUnavailable,
)
from litestar_security.context import AuthenticationEvidence, CredentialRestrictions, Principal
from litestar_security.providers.jwks import JWKSProvider
from litestar_security.providers.jwt import (
    BearerSlotSelector,
    BearerTokenSlot,
    CompositeBearerConfig,
    JSONValue,
    JWTClaims,
    JWTValidationConfig,
    PyJWTVerifier,
    VerificationKey,
    parse_unverified_jwt_route,
)

__all__ = ("ServiceTokenConfig",)


_MAXIMUM_TOKEN_BYTES = 16_384


@dataclass(frozen=True, slots=True)
class ServiceTokenConfig:
    """Pinned external workload-token trust and claim profile."""

    issuer: str
    audiences: frozenset[str]
    allowed_algorithms: frozenset[str]
    jwks: JWKSProvider
    jwks_uri: str
    scopes_claim: str = "scope"
    actor_id_claim: str = "sub"
    clock_skew: timedelta = timedelta(seconds=30)
    _validation: JWTValidationConfig = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate the remote trust boundary and required claim names."""
        jwks = cast("object", self.jwks)
        if (
            not isinstance(jwks, JWKSProvider)
            or not self.jwks_uri.startswith("https://")
            or not _claim_name(self.scopes_claim)
            or not _claim_name(self.actor_id_claim)
        ):
            raise ImproperlyConfiguredException(detail="Service token configuration is invalid")
        validation = JWTValidationConfig(
            issuer=self.issuer,
            audiences=self.audiences,
            algorithms=self.allowed_algorithms,
            required_claims=frozenset({"iss", "sub", "aud", "iat", "exp", self.actor_id_claim}),
            access_token_profile=True,
            subject_required=True,
            clock_skew=self.clock_skew,
        )
        object.__setattr__(self, "_validation", validation)

    def build(
        self, *, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    ) -> "tuple[CredentialSlot[str], AuthenticationMechanism[str, JWTClaims, object]]":
        """Build one native bearer slot and external service mechanism.

        Args:
            clock: Time source used by the composite bearer verifier.

        Returns:
            The physical bearer slot and service authentication mechanism.
        """
        verifier = _ServiceJWTVerifier(owner=self, config=self._validation)
        logical_slot = BearerTokenSlot(
            name="service-jwt",
            selector=BearerSlotSelector(issuers=frozenset({self.issuer}), audiences=self.audiences),
            verifier=verifier,
        )
        return CompositeBearerConfig(mechanism_name="service-jwt", slots=(logical_slot,)).build(
            _ServiceIdentityResolver(actor_id_claim=self.actor_id_claim), clock=clock
        )


@dataclass(frozen=True, slots=True)
class _ServiceJWTVerifier:
    owner: ServiceTokenConfig
    config: JWTValidationConfig

    async def verify(  # noqa: PLR0911 - preserve structured trust outcomes at every verifier boundary
        self, token: str, *, now: datetime
    ) -> AuthenticationOutcome[JWTClaims]:
        route = parse_unverified_jwt_route(token, maximum_token_bytes=_MAXIMUM_TOKEN_BYTES)
        if isinstance(route, InvalidCredentials):  # pragma: no cover - composite bearer already parsed this token
            return route
        algorithm = route.header.get("alg")
        key_id = route.header.get("kid")
        if not isinstance(algorithm, str) or algorithm not in self.config.algorithms:
            return InvalidCredentials()
        if not isinstance(key_id, str) or not key_id:
            return InvalidCredentials()
        selection = cast(
            "object",
            await self.owner.jwks.select_key(self.config.issuer, self.owner.jwks_uri, key_id, algorithm, now=now),
        )
        if isinstance(selection, (InvalidCredentials, VerificationUnavailable)):
            return selection
        if not isinstance(selection, VerificationKey):
            return VerificationUnavailable()
        key_config = replace(self.config, algorithms=frozenset({algorithm}))
        outcome = await PyJWTVerifier(
            config=key_config,
            key=selection.key,
            mechanism_name="service-jwt",
            slot_name="authorization.bearer",
            maximum_token_bytes=_MAXIMUM_TOKEN_BYTES,
        ).verify(token, now=now)
        if not isinstance(outcome, Authenticated):
            return outcome
        claims = outcome.claims
        scopes = _scopes(claims.raw.get(self.owner.scopes_claim))
        acr = _optional_text(claims.raw.get("acr"))
        amr = _methods(claims.raw.get("amr"))
        if scopes is None or acr is False or amr is None:
            return InvalidCredentials()
        return Authenticated(
            claims=claims,
            evidence=AuthenticationEvidence(
                mechanism="service-jwt",
                slot="authorization.bearer",
                authenticated_at=claims.issued_at,
                expires_at=claims.expires_at,
                methods=frozenset({"jwt"}),
                traits=frozenset({"service"}),
                acr=cast("str | None", acr),
                amr=amr,
            ),
            restrictions=CredentialRestrictions(scopes=scopes),
        )


@dataclass(frozen=True, slots=True)
class _ServiceIdentityResolver:
    actor_id_claim: str

    async def resolve(self, claims: JWTClaims) -> IdentityResolution[object]:
        actor_id = claims.raw.get(self.actor_id_claim)
        if not isinstance(actor_id, str) or not actor_id:
            return InvalidCredentials()
        return Principal(id=actor_id, display_name=claims.client_id or actor_id, user=None)


def _scopes(value: JSONValue | None) -> frozenset[str] | None:
    if isinstance(value, str):
        return frozenset(value.split())
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return None
    if any(not isinstance(item, str) or not item for item in value):
        return None
    return frozenset(cast("Sequence[str]", value))


def _optional_text(value: JSONValue | None) -> str | bool | None:
    if value is None:
        return None
    return value if isinstance(value, str) and value else False


def _methods(value: JSONValue | None) -> tuple[str, ...] | None:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return None
    if any(not isinstance(item, str) or not item for item in value):
        return None
    return tuple(cast("Sequence[str]", value))


def _claim_name(value: object) -> bool:
    return (
        isinstance(value, str) and bool(value) and all(character.isalnum() or character == "_" for character in value)
    )
