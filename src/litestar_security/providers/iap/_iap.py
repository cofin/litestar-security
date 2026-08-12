"""Authoritative verification of Google IAP signed assertions."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Generic, Literal, TypeVar, cast

from litestar.connection import ASGIConnection
from litestar.exceptions import ImproperlyConfiguredException
from litestar.openapi.spec import SecurityScheme

from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationOutcome,
    CredentialExtraction,
    CredentialSlot,
    IdentityResolver,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
    VerificationUnavailable,
)
from litestar_security.config import WorkerLimits
from litestar_security.context import AuthenticationEvidence
from litestar_security.providers._internal import DynamicVerifierCache
from litestar_security.providers.jwks import JWKSProvider
from litestar_security.providers.jwt import (
    JWTClaims,
    JWTValidationConfig,
    PyJWTVerifier,
    VerificationKey,
    parse_unverified_jwt_route,
)

__all__ = ("GoogleIAPClaims", "GoogleIAPConfig", "GoogleIAPExternalIdentity")


UserT = TypeVar("UserT")

_IAP_ISSUER = "https://cloud.google.com/iap"
_IAP_JWKS_URI = "https://www.gstatic.com/iap/verify/public_key-jwk"
_IAP_HEADER = "X-Goog-IAP-JWT-Assertion"
_MAXIMUM_ASSERTION_BYTES = 16_384
_MAXIMUM_ASSERTION_LIFETIME = timedelta(minutes=10)
_MAXIMUM_SIGN_IN_ATTRIBUTES = 32
_MAXIMUM_SIGN_IN_ATTRIBUTE_LENGTH = 1_024
_MAXIMUM_ACCESS_LEVELS = 64


@dataclass(frozen=True, slots=True)
class GoogleIAPExternalIdentity:
    """Validated external Identity Platform identity nested in an IAP assertion."""

    subject: str
    email: str | None = None
    email_verified: bool | None = None
    sign_in_provider: str | None = None
    tenant: str | None = None
    sign_in_attributes: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))


@dataclass(frozen=True, slots=True)
class GoogleIAPClaims:
    """Verified IAP identity fields offered to the application resolver."""

    subject: str
    email: str | None = None
    authorized_party: str | None = None
    hosted_domain: str | None = None
    access_levels: tuple[str, ...] = ()
    device_id: str | None = None
    external_identity: GoogleIAPExternalIdentity | None = None


@dataclass(frozen=True, slots=True)
class GoogleIAPConfig(Generic[UserT]):
    """Pinned trust configuration for Google IAP signed assertions."""

    audience: str | frozenset[str]
    identity_resolver: IdentityResolver[GoogleIAPClaims, UserT]
    jwks: JWKSProvider
    issuer: str = _IAP_ISSUER
    header_name: str = _IAP_HEADER
    clock_skew: timedelta = timedelta(seconds=30)
    worker_limits: WorkerLimits = field(default_factory=WorkerLimits, repr=False, compare=False)
    _validation: JWTValidationConfig = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Normalize the audience and reject configurable trust downgrades."""
        audiences = frozenset({self.audience}) if isinstance(self.audience, str) else frozenset(self.audience)
        resolver = cast("object", self.identity_resolver)
        jwks = cast("object", self.jwks)
        if (
            not audiences
            or any(not value.strip() for value in audiences)
            or self.issuer != _IAP_ISSUER
            or not _valid_header_name(self.header_name)
            or self.clock_skew.__class__ is not timedelta
            or self.clock_skew < timedelta(0)
            or not isinstance(cast("object", self.worker_limits), WorkerLimits)
            or not callable(getattr(resolver, "resolve", None))
            or not isinstance(jwks, JWKSProvider)
        ):
            raise ImproperlyConfiguredException(detail="Google IAP configuration is invalid")
        validation = JWTValidationConfig(
            issuer=self.issuer,
            audiences=audiences,
            algorithms=frozenset({"ES256"}),
            required_claims=frozenset({"iss", "sub", "aud", "iat", "exp"}),
            access_token_profile=False,
            subject_required=True,
            clock_skew=self.clock_skew,
            token_types=frozenset({"JWT"}),
        )
        object.__setattr__(self, "audience", audiences)
        object.__setattr__(self, "_validation", validation)

    def build(
        self, *, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    ) -> "tuple[CredentialSlot[str], AuthenticationMechanism[str, GoogleIAPClaims, UserT]]":
        """Build the sole IAP assertion slot and authoritative mechanism.

        Args:
            clock: Time source used for key freshness and claim validation.

        Returns:
            The signed-header slot and paired IAP mechanism.
        """
        if not callable(clock):
            raise ImproperlyConfiguredException(detail="Google IAP clock must be callable")
        slot = _GoogleIAPSlot(header_name=self.header_name)
        authenticator = _GoogleIAPAuthenticator(config=self, validation=self._validation, clock=clock)
        return slot, AuthenticationMechanism(
            authenticator=authenticator,
            resolver=self.identity_resolver,
            scheme_name="GoogleIAP",
            security_scheme=SecurityScheme(
                type="apiKey",
                name=self.header_name,
                security_scheme_in="header",
                description=(
                    "Assertion header injected by Google IAP; normal API clients must not supply this value manually."
                ),
            ),
        )


@dataclass(slots=True)
class _GoogleIAPSlot:
    header_name: str
    name: str = field(default="google-iap", init=False)

    def extract(self, connection: ASGIConnection[Any, Any, Any, Any]) -> CredentialExtraction[str]:
        expected = self.header_name.lower().encode("ascii")
        values = tuple(value for name, value in connection.scope["headers"] if name.lower() == expected)
        if not values:
            return NoCredentials()
        if len(values) != 1 or not values[0] or len(values[0]) > _MAXIMUM_ASSERTION_BYTES:
            return InvalidCredentials()
        try:
            return PresentedCredential(values[0].decode("ascii"))
        except (AttributeError, UnicodeDecodeError):
            return InvalidCredentials()


@dataclass(slots=True)
class _GoogleIAPAuthenticator(Generic[UserT]):
    config: GoogleIAPConfig[UserT]
    validation: JWTValidationConfig
    clock: Callable[[], datetime] = field(repr=False)
    name: str = field(default="google-iap", init=False)
    slot: str = field(default="google-iap", init=False)
    participates_by_default: bool = True
    _verifiers: DynamicVerifierCache[PyJWTVerifier] = field(
        default_factory=DynamicVerifierCache[PyJWTVerifier], init=False, repr=False, compare=False
    )

    async def authenticate(  # noqa: PLR0911 - every trust failure retains its structured security outcome
        self, credential: str, connection: ASGIConnection[Any, Any, Any, Any]
    ) -> AuthenticationOutcome[GoogleIAPClaims]:
        del connection
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            return InvalidCredentials()
        now = now.astimezone(timezone.utc)
        route = parse_unverified_jwt_route(credential, maximum_token_bytes=_MAXIMUM_ASSERTION_BYTES)
        if isinstance(route, InvalidCredentials):
            return route
        algorithm = route.header.get("alg")
        key_id = route.header.get("kid")
        if algorithm != "ES256" or not isinstance(key_id, str) or not key_id:
            return InvalidCredentials()
        selection = cast(
            "object",
            await self.config.jwks.select_key(
                self.config.issuer,
                _IAP_JWKS_URI,
                key_id,
                algorithm,  # pyright: ignore[reportArgumentType] - exact ES256 check narrows this value
                now=now,
            ),
        )
        if isinstance(selection, (InvalidCredentials, VerificationUnavailable)):
            return selection
        if not isinstance(selection, VerificationKey):
            return VerificationUnavailable()
        verifier = self._verifiers.get_or_create(
            (key_id, "ES256"),
            selection.key,
            lambda: PyJWTVerifier(
                config=self.validation,
                key=selection.key,
                mechanism_name=self.name,
                slot_name=self.slot,
                maximum_token_bytes=_MAXIMUM_ASSERTION_BYTES,
                limiter=self.config.worker_limits.crypto_limiter,
                worker_timeout=self.config.worker_limits.timeout,
            ),
        )
        outcome = await verifier.verify(credential, now=now)
        if not isinstance(outcome, Authenticated):
            return outcome
        claims = outcome.claims
        if claims.expires_at - claims.issued_at > _MAXIMUM_ASSERTION_LIFETIME + (self.config.clock_skew * 2):
            return InvalidCredentials()
        subject = claims.subject
        email = _optional_claim(claims, "email")
        authorized_party = _optional_claim(claims, "azp")
        hosted_domain = _optional_claim(claims, "hd")
        google = _google_claims(claims.raw.get("google"))
        external_identity = _external_identity(claims.raw.get("gcip"))
        if (
            subject is None
            or email is False
            or authorized_party is False
            or hosted_domain is False
            or google is None
            or external_identity is False
        ):
            return InvalidCredentials()
        access_levels, device_id = google
        return Authenticated(
            claims=GoogleIAPClaims(
                subject=subject,
                email=cast("str | None", email),
                authorized_party=cast("str | None", authorized_party),
                hosted_domain=cast("str | None", hosted_domain),
                access_levels=access_levels,
                device_id=device_id,
                external_identity=external_identity,
            ),
            evidence=AuthenticationEvidence(
                mechanism=self.name,
                slot=self.slot,
                authenticated_at=claims.issued_at,
                expires_at=claims.expires_at,
                methods=frozenset({"iap"}),
                traits=frozenset({"federated"}),
            ),
        )


def _google_claims(value: object) -> tuple[tuple[str, ...], str | None] | None:
    if value is None:
        return (), None
    if not isinstance(value, Mapping):
        return None
    claims = cast("Mapping[str, object]", value)
    access_levels = claims.get("access_levels", [])
    device_id = claims.get("device_id")
    typed_access_levels = cast("Sequence[object]", access_levels)
    if (
        not isinstance(access_levels, Sequence)
        or isinstance(access_levels, (str, bytes))
        or len(typed_access_levels) > _MAXIMUM_ACCESS_LEVELS
        or any(
            not isinstance(item, str) or not item or len(item) > _MAXIMUM_SIGN_IN_ATTRIBUTE_LENGTH
            for item in typed_access_levels
        )
        or (
            device_id is not None
            and (not isinstance(device_id, str) or not device_id or len(device_id) > _MAXIMUM_SIGN_IN_ATTRIBUTE_LENGTH)
        )
    ):
        return None
    return tuple(cast("Sequence[str]", access_levels)), device_id


def _external_identity(value: object) -> GoogleIAPExternalIdentity | Literal[False] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        return False
    claims = cast("Mapping[str, object]", value)
    subject = claims.get("sub")
    email = claims.get("email")
    email_verified = claims.get("email_verified")
    provider = claims.get("sign_in_provider")
    tenant = claims.get("tenant")
    attributes = claims.get("sign_in_attributes", {})
    typed_attributes = cast("Mapping[object, object]", attributes)
    optional_text = (email, provider, tenant)
    if (
        not isinstance(subject, str)
        or not subject
        or len(subject) > _MAXIMUM_SIGN_IN_ATTRIBUTE_LENGTH
        or any(
            item is not None
            and (not isinstance(item, str) or not item or len(item) > _MAXIMUM_SIGN_IN_ATTRIBUTE_LENGTH)
            for item in optional_text
        )
        or (email_verified is not None and email_verified.__class__ is not bool)
        or not isinstance(attributes, Mapping)
        or len(typed_attributes) > _MAXIMUM_SIGN_IN_ATTRIBUTES
        or any(
            not isinstance(key, str)
            or not key
            or not isinstance(item, str)
            or len(key) > _MAXIMUM_SIGN_IN_ATTRIBUTE_LENGTH
            or len(item) > _MAXIMUM_SIGN_IN_ATTRIBUTE_LENGTH
            for key, item in typed_attributes.items()
        )
    ):
        return False
    typed_email_verified = email_verified if isinstance(email_verified, bool) else None
    return GoogleIAPExternalIdentity(
        subject=subject,
        email=cast("str | None", email),
        email_verified=typed_email_verified,
        sign_in_provider=cast("str | None", provider),
        tenant=cast("str | None", tenant),
        sign_in_attributes=MappingProxyType(dict(cast("Mapping[str, str]", attributes))),
    )


def _optional_claim(claims: JWTClaims, name: str) -> str | bool | None:
    value = claims.raw.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        return False
    return value


def _valid_header_name(value: object) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    return all(character.isascii() and (character.isalnum() or character in "!#$%&'*+-.^_`|~") for character in value)
