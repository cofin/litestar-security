"""JWT parsing, verification profiles, signing, and bearer composition."""

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from functools import partial
from secrets import token_urlsafe
from types import MappingProxyType
from typing import Any, Generic, Literal, NoReturn, Protocol, TypeAlias, TypedDict, TypeVar, cast, runtime_checkable

import jwt
from anyio import CapacityLimiter, to_thread
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jwt import PyJWK
from jwt.exceptions import PyJWTError
from litestar.connection import ASGIConnection
from litestar.connection.request import Request
from litestar.datastructures import ResponseHeader
from litestar.exceptions import ImproperlyConfiguredException
from litestar.handlers.http_handlers import HTTPRouteHandler, get
from litestar.openapi.datastructures import ResponseSpec
from litestar.openapi.spec import SecurityScheme
from litestar.response import Response
from litestar.status_codes import HTTP_200_OK, HTTP_304_NOT_MODIFIED

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
    public,
    security,
)
from litestar_security.context import AuthenticationEvidence

__all__ = (
    "BearerSlotSelector",
    "BearerTokenSlot",
    "CompositeBearerConfig",
    "JSONValue",
    "JWTClaims",
    "JWTValidationConfig",
    "JWTVerifier",
    "LocalJWKSConfig",
    "LocalKeyRing",
    "SigningKey",
    "TokenSigner",
    "VerificationKey",
    "VerificationKeySet",
    "build_access_token_claims",
    "build_local_jwks_handler",
)

JSONValue: TypeAlias = bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"] | None
JWTAlgorithm: TypeAlias = Literal["EdDSA", "ES256", "RS256", "HS256"]
VerificationKeyInput: TypeAlias = bytes | str | PyJWK | Mapping[str, JSONValue]
PreparedVerificationKey: TypeAlias = (
    bytes | str | PyJWK | rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey
)
PreparedSigningKey: TypeAlias = bytes | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
ClaimsT = TypeVar("ClaimsT")
UserT = TypeVar("UserT")

_SUPPORTED_ALGORITHMS = frozenset({"EdDSA", "ES256", "RS256", "HS256"})
_ACCESS_TOKEN_TYPES = frozenset({"at+jwt", "application/at+jwt"})
_BASE_REQUIRED_CLAIMS = frozenset({"iss", "sub", "aud", "exp", "iat"})
_ACCESS_REQUIRED_CLAIMS = frozenset({"client_id", "jti"})
_FORBIDDEN_JOSE_HEADERS = frozenset({"b64", "crit", "jku", "jwk", "x5c", "x5t", "x5t#S256", "x5u"})
_PRIVATE_JWK_MEMBERS = frozenset({"d", "dp", "dq", "k", "oth", "p", "q", "qi"})
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_COMPACT_SEGMENT_COUNT = 3
_MINIMUM_HMAC_BYTES = 32
_MINIMUM_RSA_BITS = 2048
_ASCII_CONTROL_LIMIT = 32
_ASCII_DELETE = 127
_BEARER_PREFIX_LENGTH = len(b"Bearer ")
_LOCAL_ACCESS_REQUIRED_CLAIMS = frozenset({"iss", "sub", "aud", "exp", "iat", "client_id", "jti", "se"})
_LOCAL_ACCESS_ALLOWED_CLAIMS = _LOCAL_ACCESS_REQUIRED_CLAIMS.union({"nbf", "scope"})
_MAXIMUM_LOCAL_JWKS_CACHE_AGE = 86_400
_PUBLIC_JWK_FIELDS = {
    "EdDSA": frozenset({"alg", "crv", "key_ops", "kid", "kty", "use", "x"}),
    "ES256": frozenset({"alg", "crv", "key_ops", "kid", "kty", "use", "x", "y"}),
    "RS256": frozenset({"alg", "e", "key_ops", "kid", "kty", "n", "use"}),
}
_INVALID = InvalidCredentials()


class _RSAPublicJWK(TypedDict):
    alg: Literal["RS256"]
    e: str
    key_ops: list[Literal["verify"]]
    kid: str
    kty: Literal["RSA"]
    n: str
    use: Literal["sig"]


class _ECPublicJWK(TypedDict):
    alg: Literal["ES256"]
    crv: Literal["P-256"]
    key_ops: list[Literal["verify"]]
    kid: str
    kty: Literal["EC"]
    use: Literal["sig"]
    x: str
    y: str


class _OKPPublicJWK(TypedDict):
    alg: Literal["EdDSA"]
    crv: Literal["Ed25519"]
    key_ops: list[Literal["verify"]]
    kid: str
    kty: Literal["OKP"]
    use: Literal["sig"]
    x: str


class _LocalJWKSDocument(TypedDict):
    keys: list[_RSAPublicJWK | _ECPublicJWK | _OKPPublicJWK]


@dataclass(frozen=True, slots=True)
class JWTClaims:
    """Verified, normalized JWT claims without the compact credential."""

    issuer: str
    subject: str
    audiences: frozenset[str]
    expires_at: datetime
    issued_at: datetime
    not_before: datetime | None
    token_id: str | None
    client_id: str | None
    scopes: frozenset[str]
    raw: Mapping[str, JSONValue]

    def __post_init__(self) -> None:
        """Freeze nested collections at the verified-claims boundary."""
        object.__setattr__(self, "audiences", frozenset(self.audiences))
        object.__setattr__(self, "scopes", frozenset(self.scopes))
        object.__setattr__(self, "raw", cast("Mapping[str, JSONValue]", _freeze_json(dict(self.raw))))


@dataclass(frozen=True, slots=True)
class JWTValidationConfig:
    """Pin one issuer's accepted JWT verification profile."""

    issuer: str
    audiences: frozenset[str]
    algorithms: frozenset[str]
    required_claims: frozenset[str] = frozenset({"iss", "sub", "aud", "exp", "iat"})
    access_token_profile: bool = True
    clock_skew: timedelta = timedelta(seconds=30)
    maximum_lifetime: timedelta | None = timedelta(hours=1)
    token_types: frozenset[str] = _ACCESS_TOKEN_TYPES

    def __post_init__(self) -> None:
        """Normalize immutable inputs and reject an unsafe verification profile."""
        issuer = _strict_identifier(self.issuer)
        audiences = frozenset(_strict_identifier(audience) for audience in self.audiences)
        algorithms = frozenset(self.algorithms)
        unsupported = algorithms.difference(_SUPPORTED_ALGORITHMS)
        if not audiences:
            _raise_config("JWT validation audiences must not be empty")
        if not algorithms:
            _raise_config("JWT validation algorithms must not be empty")
        if unsupported:
            _raise_config(f"Unsupported JWT validation algorithm: {min(unsupported)}")
        if self.clock_skew < timedelta(0):
            _raise_config("JWT clock skew must not be negative")
        if self.maximum_lifetime is not None and self.maximum_lifetime <= timedelta(0):
            _raise_config("JWT maximum lifetime must be positive")
        required = frozenset(_strict_identifier(name) for name in self.required_claims).union(_BASE_REQUIRED_CLAIMS)
        if self.access_token_profile:
            required = required.union(_ACCESS_REQUIRED_CLAIMS)
        token_types = frozenset(_strict_identifier(value).lower() for value in self.token_types)
        if not token_types:
            _raise_config("JWT token types must not be empty")
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "audiences", audiences)
        object.__setattr__(self, "algorithms", algorithms)
        object.__setattr__(self, "required_claims", required)
        object.__setattr__(self, "token_types", token_types)


@dataclass(frozen=True, slots=True)
class SigningKey:
    """One explicit local signing key and its public verification metadata."""

    key_id: str
    algorithm: JWTAlgorithm
    private_key: bytes = field(repr=False)
    public_jwk: Mapping[str, JSONValue] | None = None
    _prepared_key: PreparedSigningKey = field(init=False, repr=False, compare=False)
    _verification_key: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate key strength, purpose, and public/private correspondence."""
        key_id = _strict_key_id(self.key_id)
        prepared, verification_key = _prepare_signing_material(self.private_key, self.algorithm)
        public_jwk = _prepare_public_jwk(self.public_jwk, prepared, self.algorithm, key_id)
        object.__setattr__(self, "key_id", key_id)
        object.__setattr__(self, "public_jwk", public_jwk)
        object.__setattr__(self, "_prepared_key", prepared)
        object.__setattr__(self, "_verification_key", verification_key)

    def as_verification_key(self) -> "VerificationKey":
        """Return the active key's verification-only representation."""
        return VerificationKey(
            key_id=self.key_id, algorithm=self.algorithm, key=self._verification_key, public_jwk=self.public_jwk
        )


@dataclass(frozen=True, slots=True)
class VerificationKey:
    """One explicit verification-only key retained for local rotation."""

    key_id: str
    algorithm: JWTAlgorithm
    key: bytes = field(repr=False)
    public_jwk: Mapping[str, JSONValue] | None = None
    _prepared_key: PreparedVerificationKey = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Reject private, weak, mismatched, or publication-unsafe material."""
        key_id = _strict_key_id(self.key_id)
        prepared = _prepare_retained_verification_key(self.key, self.algorithm)
        public_jwk = _prepare_public_jwk(self.public_jwk, prepared, self.algorithm, key_id)
        object.__setattr__(self, "key_id", key_id)
        object.__setattr__(self, "public_jwk", public_jwk)
        object.__setattr__(self, "_prepared_key", prepared)


@runtime_checkable
class TokenSigner(Protocol):
    """Sign caller-built local claims without owning application persistence."""

    async def sign(self, claims: Mapping[str, JSONValue], *, now: datetime) -> str:
        """Return one compact signed access token."""
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class VerificationKeySet:
    """One issuer's immutable verification-only keys for local or custom signers."""

    issuer: str
    keys: tuple[VerificationKey, ...]

    def __post_init__(self) -> None:
        """Normalize the issuer and reject empty or ambiguous key selection."""
        issuer = _strict_identifier(self.issuer)
        keys = tuple(self.keys)
        if not keys:
            _raise_config("Verification key set must contain at least one key")
        key_ids = tuple(key.key_id for key in keys)
        if len(frozenset(key_ids)) != len(key_ids):
            _raise_config("Duplicate local key id")
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "keys", keys)

    def build_verifier(
        self,
        config: JWTValidationConfig,
        *,
        mechanism_name: str = "jwt",
        slot_name: str = "authorization.bearer",
        limiter: CapacityLimiter | None = None,
    ) -> "JWTVerifier[JWTClaims]":
        """Build one exact-kid verifier across this trusted key set."""
        if config.issuer != self.issuer:
            _raise_config("Verification key set issuer must match JWT validation config issuer")
        mechanism_name = _strict_identifier(mechanism_name)
        slot_name = _strict_identifier(slot_name)
        verifiers: dict[tuple[str, str], PyJWTVerifier] = {}
        for verification_key in self.keys:
            if verification_key.algorithm not in config.algorithms:
                continue
            key_config = replace(config, algorithms=frozenset({verification_key.algorithm}))
            verifiers[(verification_key.key_id, verification_key.algorithm)] = PyJWTVerifier(
                config=key_config,
                key=verification_key.key,
                require_key_id=True,
                mechanism_name=mechanism_name,
                slot_name=slot_name,
                limiter=limiter,
            )
        if not verifiers:
            _raise_config("Verification key set has no key accepted by JWT validation config")
        return _LocalKeyRingVerifier(config=config, verifiers=MappingProxyType(verifiers))


@dataclass(frozen=True, slots=True)
class LocalKeyRing:
    """Immutable active and retained local key configuration."""

    issuer: str
    active_signing_key: SigningKey
    verification_keys: tuple[VerificationKey, ...] = ()
    _verification_key_set: VerificationKeySet = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Normalize the issuer and reject ambiguous rotation state."""
        issuer = _strict_identifier(self.issuer)
        verification_keys = tuple(self.verification_keys)
        key_set = VerificationKeySet(
            issuer=issuer, keys=(self.active_signing_key.as_verification_key(), *verification_keys)
        )
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "verification_keys", verification_keys)
        object.__setattr__(self, "_verification_key_set", key_set)

    @property
    def all_verification_keys(self) -> tuple[VerificationKey, ...]:
        """Return the active key followed by retained verification-only keys."""
        return self._verification_key_set.keys

    @property
    def verification_key_set(self) -> VerificationKeySet:
        """Return the public verification-only view used by local or custom signers."""
        return self._verification_key_set

    def build_signer(self, *, limiter: CapacityLimiter | None = None) -> TokenSigner:
        """Build the local signer without generating or discovering key material."""
        return _LocalJWTSigner(issuer=self.issuer, signing_key=self.active_signing_key, limiter=limiter)

    def build_verifier(
        self,
        config: JWTValidationConfig,
        *,
        mechanism_name: str = "jwt",
        slot_name: str = "authorization.bearer",
        limiter: CapacityLimiter | None = None,
    ) -> "JWTVerifier[JWTClaims]":
        """Build one exact-kid verifier across the active and retained keys."""
        if self.active_signing_key.algorithm not in config.algorithms:
            _raise_config("Local key ring active signing algorithm must be accepted by JWT validation config")
        return self._verification_key_set.build_verifier(
            config, mechanism_name=mechanism_name, slot_name=slot_name, limiter=limiter
        )


@dataclass(frozen=True, slots=True)
class LocalJWKSConfig:
    """Immutable public representation of one local verification-key generation."""

    key_set: VerificationKeySet
    route_prefix: str = "/auth"
    cache_max_age: int = 300
    document: Mapping[str, tuple[Mapping[str, JSONValue], ...]] = field(init=False)
    canonical_bytes: bytes = field(init=False, repr=False)
    etag: str = field(init=False)
    path: str = field(init=False)
    cache_control: str = field(init=False)

    def __post_init__(self) -> None:
        """Validate publication settings and build the canonical response once."""
        route_prefix = self.route_prefix.rstrip("/")
        if (
            not route_prefix.startswith("/")
            or route_prefix == ""
            or "//" in route_prefix
            or any(value in route_prefix for value in ("\\", "{", "}", "?", "#"))
            or any(segment in {".", ".."} for segment in route_prefix.split("/"))
            or any(character.isspace() or ord(character) < _ASCII_CONTROL_LIMIT for character in route_prefix)
        ):
            _raise_config("local JWKS route_prefix must be a non-root absolute path")
        if isinstance(self.cache_max_age, bool) or not 0 <= self.cache_max_age <= _MAXIMUM_LOCAL_JWKS_CACHE_AGE:
            _raise_config(f"local JWKS cache_max_age must be between 0 and {_MAXIMUM_LOCAL_JWKS_CACHE_AGE}")

        public_keys = tuple(
            sorted(
                (
                    MappingProxyType({
                        name: key.public_jwk[name]
                        for name in _PUBLIC_JWK_FIELDS[key.algorithm]
                        if name in key.public_jwk
                    })
                    for key in self.key_set.keys
                    if key.algorithm != "HS256" and key.public_jwk is not None
                ),
                key=lambda value: cast("str", value["kid"]),
            )
        )
        if not public_keys:
            _raise_config("local JWKS publication requires at least one asymmetric verification key")
        encoded_document = {"keys": [dict(key) for key in public_keys]}
        canonical_bytes = json.dumps(
            encoded_document, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode()

        object.__setattr__(self, "route_prefix", route_prefix)
        object.__setattr__(self, "document", MappingProxyType({"keys": public_keys}))
        object.__setattr__(self, "canonical_bytes", canonical_bytes)
        object.__setattr__(self, "etag", f'"{hashlib.sha256(canonical_bytes).hexdigest()}"')
        object.__setattr__(self, "path", f"{route_prefix}/.well-known/jwks.json")
        object.__setattr__(self, "cache_control", f"public, max-age={self.cache_max_age}")


def build_local_jwks_handler(config: LocalJWKSConfig) -> HTTPRouteHandler:
    """Build one native public Litestar handler for immutable local JWKS bytes."""
    headers = {"Cache-Control": config.cache_control, "ETag": config.etag}

    @get(
        config.path,
        name="litestar_security_local_jwks",
        operation_id="LitestarSecurityLocalJWKS",
        media_type="application/jwk-set+json",
        opt=security(public()),
        response_headers=(
            ResponseHeader(
                name="Cache-Control",
                documentation_only=True,
                description="Public cache policy for this immutable key-set generation.",
                required=True,
            ),
            ResponseHeader(
                name="ETag",
                documentation_only=True,
                description="Strong entity tag for conditional key-set requests.",
                required=True,
            ),
        ),
        responses={
            HTTP_304_NOT_MODIFIED: ResponseSpec(
                data_container=None,
                description="The client's entity tag already identifies the current key-set generation.",
            )
        },
        summary="Local JSON Web Key Set",
    )
    async def local_jwks(request: Request[Any, Any, Any]) -> Response[_LocalJWKSDocument]:
        if _if_none_match(request.headers.get("if-none-match"), config.etag):
            return Response(cast("_LocalJWKSDocument", b""), headers=headers, status_code=HTTP_304_NOT_MODIFIED)
        return Response(
            cast("_LocalJWKSDocument", config.canonical_bytes),
            headers=headers,
            media_type="application/jwk-set+json",
            status_code=HTTP_200_OK,
        )

    return local_jwks


def build_access_token_claims(  # noqa: PLR0913
    *,
    issuer: str,
    audience: str,
    subject: str,
    client_id: str,
    security_epoch: int,
    now: datetime,
    lifetime: timedelta,
    scopes: AbstractSet[str] = frozenset(),
    jti: str | None = None,
    not_before: datetime | None = None,
) -> Mapping[str, JSONValue]:
    """Build minimal deterministic RFC 9068-style local access-token claims."""
    issuer = _strict_identifier_value(issuer)
    audience = _strict_identifier_value(audience)
    subject = _strict_identifier_value(subject)
    client_id = _strict_identifier_value(client_id)
    epoch_value: object = security_epoch
    if (
        isinstance(epoch_value, bool)
        or not isinstance(epoch_value, int)  # pyright: ignore[reportUnnecessaryIsInstance]
        or epoch_value < 0
    ):
        _raise_value("Access-token security epoch must be a non-negative integer")
    now = _aware_utc(now)
    if lifetime <= timedelta(0):
        _raise_value("Access-token lifetime must be positive")
    expires_at = now + lifetime
    issued_timestamp = int(now.timestamp())
    expires_timestamp = int(expires_at.timestamp())
    if expires_timestamp <= issued_timestamp:
        _raise_value("Access-token lifetime must span at least one whole second")
    if not_before is not None:
        not_before = _aware_utc(not_before)
        if not_before >= expires_at:
            _raise_value("Access-token not-before must precede expiry")
    token_id = _strict_identifier_value(jti if jti is not None else token_urlsafe(32))
    normalized_scopes = frozenset(_strict_identifier_value(scope) for scope in scopes)
    claims: dict[str, JSONValue] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "exp": expires_timestamp,
        "iat": issued_timestamp,
        "client_id": client_id,
        "jti": token_id,
        "se": security_epoch,
    }
    if normalized_scopes:
        claims["scope"] = " ".join(sorted(normalized_scopes))
    if not_before is not None:
        claims["nbf"] = int(not_before.timestamp())
    return cast("Mapping[str, JSONValue]", MappingProxyType(claims))


class JWTVerifier(Protocol, Generic[ClaimsT]):
    """Verify one compact JWT against a configured trust domain."""

    config: JWTValidationConfig

    async def verify(self, token: str, *, now: datetime) -> AuthenticationOutcome[ClaimsT]:
        """Return a structured authentication outcome."""
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class UnverifiedJWTRoute:
    """Strictly parsed but cryptographically untrusted JOSE routing data."""

    header: Mapping[str, JSONValue]
    payload: Mapping[str, JSONValue]


def parse_unverified_jwt_route(
    token: str, *, maximum_token_bytes: int = 16_384, maximum_json_depth: int = 32
) -> UnverifiedJWTRoute | InvalidCredentials:
    """Parse untrusted JOSE routing fields without treating them as claims."""
    if maximum_token_bytes < 1 or maximum_json_depth < 1:
        return _INVALID
    try:
        encoded = token.encode("ascii")
    except (AttributeError, UnicodeEncodeError):
        return _INVALID
    if len(encoded) > maximum_token_bytes:
        return _INVALID
    segments = token.split(".")
    if len(segments) != _COMPACT_SEGMENT_COUNT or any(not segment for segment in segments):
        return _INVALID
    try:
        header = _decode_json_segment(segments[0], maximum_json_depth=maximum_json_depth)
        payload = _decode_json_segment(segments[1], maximum_json_depth=maximum_json_depth)
        _decode_base64url(segments[2])
    except (TypeError, ValueError):
        return _INVALID
    return UnverifiedJWTRoute(
        header=cast("Mapping[str, JSONValue]", _freeze_json(header)),
        payload=cast("Mapping[str, JSONValue]", _freeze_json(payload)),
    )


@dataclass(frozen=True, slots=True)
class PyJWTVerifier:
    """Verify one fixed-key JWT profile with PyJWT's signature primitive."""

    config: JWTValidationConfig
    key: VerificationKeyInput = field(repr=False)
    require_key_id: bool = True
    mechanism_name: str = "jwt"
    slot_name: str = "authorization.bearer"
    maximum_token_bytes: int = 16_384
    limiter: CapacityLimiter | None = field(default=None, repr=False, compare=False)
    _prepared_keys: Mapping[str, PreparedVerificationKey] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate and prepare fixed verification material once."""
        if self.maximum_token_bytes < 1:
            _raise_config("JWT maximum token bytes must be positive")
        mechanism_name = _strict_identifier(self.mechanism_name)
        slot_name = _strict_identifier(self.slot_name)
        prepared: dict[str, PreparedVerificationKey] = {}
        for algorithm in self.config.algorithms:
            prepared[algorithm] = _prepare_key(self.key, cast("JWTAlgorithm", algorithm))
        object.__setattr__(self, "mechanism_name", mechanism_name)
        object.__setattr__(self, "slot_name", slot_name)
        object.__setattr__(self, "_prepared_keys", MappingProxyType(prepared))

    async def verify(self, token: str, *, now: datetime) -> AuthenticationOutcome[JWTClaims]:  # noqa: PLR0911
        """Verify signature and claims, returning only sanitized outcomes."""
        if now.tzinfo is None or now.utcoffset() is None:
            return _INVALID
        now = now.astimezone(timezone.utc)
        route = parse_unverified_jwt_route(token, maximum_token_bytes=self.maximum_token_bytes)
        if isinstance(route, InvalidCredentials):
            return route
        header_result = _validate_header(route.header, self.config, require_key_id=self.require_key_id)
        if isinstance(header_result, InvalidCredentials):
            return header_result
        algorithm = header_result
        claims = _normalize_claims(route.payload, self.config, now=now)
        if isinstance(claims, InvalidCredentials):
            return claims
        verify = partial(_verify_signature, token, self._prepared_keys[algorithm], algorithm)
        try:
            await to_thread.run_sync(verify, abandon_on_cancel=True, limiter=self.limiter)
        except (PyJWTError, TypeError, ValueError):
            return _INVALID
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        return Authenticated(
            claims=claims,
            evidence=AuthenticationEvidence(
                mechanism=self.mechanism_name, slot=self.slot_name, authenticated_at=now, expires_at=claims.expires_at
            ),
        )


@dataclass(frozen=True, slots=True)
class _LocalJWTSigner:
    issuer: str
    signing_key: SigningKey = field(repr=False)
    limiter: CapacityLimiter | None = field(default=None, repr=False, compare=False)

    async def sign(self, claims: Mapping[str, JSONValue], *, now: datetime) -> str:
        """Validate and sign one minimal local access token in a worker."""
        normalized_now = _aware_utc(now)
        payload = _validate_local_access_claims(claims, issuer=self.issuer, now=normalized_now)
        sign = partial(
            jwt.encode,
            payload,
            cast("Any", self.signing_key)._prepared_key,  # noqa: SLF001
            algorithm=self.signing_key.algorithm,
            headers={"kid": self.signing_key.key_id, "typ": "at+jwt"},
        )
        try:
            token = await to_thread.run_sync(sign, abandon_on_cancel=True, limiter=self.limiter)
        except Exception:  # noqa: BLE001
            message = "Token signing unavailable"
            raise RuntimeError(message) from None
        return token


@dataclass(slots=True)
class _LocalKeyRingVerifier:
    config: JWTValidationConfig
    verifiers: Mapping[tuple[str, str], PyJWTVerifier] = field(repr=False)

    async def verify(self, token: str, *, now: datetime) -> AuthenticationOutcome[JWTClaims]:
        """Select only a configured local `(kid, alg)` tuple and verify once."""
        route = parse_unverified_jwt_route(token)
        if isinstance(route, InvalidCredentials):
            return route
        key_id = route.header.get("kid")
        algorithm = route.header.get("alg")
        if not isinstance(key_id, str) or not isinstance(algorithm, str):
            return _INVALID
        verifier = self.verifiers.get((key_id, algorithm))
        if verifier is None:
            return _INVALID
        return await verifier.verify(token, now=now)


@dataclass(frozen=True, slots=True)
class BearerSlotSelector:
    """Route unverified bearer metadata only to a configured trust domain."""

    issuers: frozenset[str]
    audiences: frozenset[str] = frozenset()
    token_types: frozenset[str] = _ACCESS_TOKEN_TYPES

    def __post_init__(self) -> None:
        """Normalize immutable selector values without broadening trust."""
        issuers = frozenset(_strict_identifier(issuer) for issuer in self.issuers)
        audiences = frozenset(_strict_identifier(audience) for audience in self.audiences)
        token_types = frozenset(_strict_identifier(token_type).lower() for token_type in self.token_types)
        if not issuers:
            _raise_config("Bearer selector issuers must not be empty")
        if not token_types:
            _raise_config("Bearer selector token types must not be empty")
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
        name = _strict_identifier(self.name)
        verifier_config = getattr(self.verifier, "config", None)
        if not isinstance(verifier_config, JWTValidationConfig):
            _raise_config(f"Bearer slot {name} verifier must expose JWTValidationConfig")
        selector = self.selector
        if (
            selector.issuers != frozenset({verifier_config.issuer})
            or (selector.audiences and not selector.audiences.issubset(verifier_config.audiences))
            or not selector.token_types.issubset(verifier_config.token_types)
        ):
            _raise_config(f"Bearer slot {name} selector does not match verifier validation config")
        object.__setattr__(self, "name", name)


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
        mechanism_name = _strict_identifier(self.mechanism_name)
        slots = tuple(self.slots)
        if not slots:
            _raise_config("Composite bearer authentication requires at least one slot")
        if self.maximum_token_bytes < 1:
            _raise_config("Composite bearer maximum token bytes must be positive")
        names: set[str] = set()
        selectors: set[tuple[frozenset[str], frozenset[str], frozenset[str]]] = set()
        for slot in slots:
            if slot.name in names:
                _raise_config(f"Duplicate bearer slot: {slot.name}")
            names.add(slot.name)
            selector = (slot.selector.issuers, slot.selector.audiences, slot.selector.token_types)
            if selector in selectors:
                _raise_config(f"Bearer slot {slot.name} has an identical selector")
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
        """Build one physical slot and one native bearer mechanism."""
        if not callable(clock):
            _raise_config("Composite bearer clock must be callable")
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


@dataclass(slots=True)
class _BearerCredentialSlot:
    maximum_token_bytes: int
    name: str = field(default="authorization.bearer", init=False)

    def extract(  # noqa: PLR0911
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
        return replace(outcome, evidence=replace(outcome.evidence, mechanism=self.name, slot=selected.name))


def _selector_matches(selector: BearerSlotSelector, route: UnverifiedJWTRoute) -> bool:
    issuer = route.payload.get("iss")
    token_type = route.header.get("typ")
    audiences = _normalize_audiences(route.payload.get("aud"))
    return (
        isinstance(issuer, str)
        and _is_strict_identifier(issuer)
        and issuer in selector.issuers
        and isinstance(token_type, str)
        and _is_strict_identifier(token_type)
        and token_type.lower() in selector.token_types
        and audiences is not None
        and (not selector.audiences or bool(audiences.intersection(selector.audiences)))
    )


def _verify_signature(token: str, key: PreparedVerificationKey, algorithm: str) -> None:
    jwt.decode_complete(
        token,
        key=key,  # pyright: ignore[reportArgumentType]
        algorithms=[algorithm],
        options={
            "require": [],
            "verify_aud": False,
            "verify_exp": False,
            "verify_iat": False,
            "verify_iss": False,
            "verify_jti": False,
            "verify_nbf": False,
            "verify_signature": True,
            "verify_sub": False,
        },
    )


def _validate_header(
    header: Mapping[str, JSONValue], config: JWTValidationConfig, *, require_key_id: bool
) -> str | InvalidCredentials:
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or algorithm not in config.algorithms or algorithm == "none":
        return _INVALID
    token_type = header.get("typ")
    if not isinstance(token_type, str) or token_type.lower() not in config.token_types:
        return _INVALID
    if _FORBIDDEN_JOSE_HEADERS.intersection(header):
        return _INVALID
    key_id = header.get("kid")
    if key_id is not None and (not isinstance(key_id, str) or not _is_strict_identifier(key_id)):
        return _INVALID
    if require_key_id and key_id is None:
        return _INVALID
    return algorithm


def _normalize_claims(  # noqa: PLR0911
    payload: Mapping[str, JSONValue], config: JWTValidationConfig, *, now: datetime
) -> JWTClaims | InvalidCredentials:
    if not config.required_claims.issubset(payload):
        return _INVALID
    issuer = payload.get("iss")
    subject = payload.get("sub")
    if (
        not isinstance(issuer, str)
        or issuer != config.issuer
        or not _is_strict_identifier(issuer)
        or not isinstance(subject, str)
        or not _is_strict_identifier(subject)
    ):
        return _INVALID
    audiences = _normalize_audiences(payload.get("aud"))
    if audiences is None or not audiences.intersection(config.audiences):
        return _INVALID
    issued_at = _numeric_date(payload.get("iat"))
    expires_at = _numeric_date(payload.get("exp"))
    not_before_value = payload.get("nbf")
    not_before = None if not_before_value is None else _numeric_date(not_before_value)
    if issued_at is None or expires_at is None or (not_before_value is not None and not_before is None):
        return _INVALID
    skew = config.clock_skew
    if issued_at > now + skew or expires_at <= now - skew or (not_before is not None and not_before > now + skew):
        return _INVALID
    lifetime = expires_at - issued_at
    if (
        lifetime <= timedelta(0)
        or (not_before is not None and not_before >= expires_at)
        or (config.maximum_lifetime is not None and lifetime > config.maximum_lifetime)
    ):
        return _INVALID
    token_id = _optional_identifier(payload.get("jti"))
    client_id = _optional_identifier(payload.get("client_id"))
    if (
        ("jti" in payload and token_id is None)
        or ("client_id" in payload and client_id is None)
        or (config.access_token_profile and (token_id is None or client_id is None))
    ):
        return _INVALID
    scopes = _normalize_scopes(payload)
    if scopes is None:
        return _INVALID
    return JWTClaims(
        issuer=issuer,
        subject=subject,
        audiences=audiences,
        expires_at=expires_at,
        issued_at=issued_at,
        not_before=not_before,
        token_id=token_id,
        client_id=client_id,
        scopes=scopes,
        raw=payload,
    )


def _normalize_audiences(value: JSONValue | None) -> frozenset[str] | None:
    if isinstance(value, str):
        return frozenset({value}) if _is_strict_identifier(value) else None
    if not isinstance(value, (list, tuple)) or not value:
        return None
    if any(not isinstance(item, str) or not _is_strict_identifier(item) for item in value):
        return None
    audience_values = cast("Sequence[str]", value)
    audiences = frozenset(audience_values)
    return audiences if len(audiences) == len(audience_values) else None


def _normalize_scopes(payload: Mapping[str, JSONValue]) -> frozenset[str] | None:
    scope = payload.get("scope")
    scp = payload.get("scp")
    if scope is not None and scp is not None:
        return None
    if scope is None and scp is None:
        return frozenset()
    if isinstance(scope, str):
        scope_values = scope.split(" ")
        if (
            not scope_values
            or len(scope_values) != len(frozenset(scope_values))
            or any(not _is_strict_identifier(value) for value in scope_values)
        ):
            return None
        return frozenset(scope_values)
    if isinstance(scp, (list, tuple)) and all(isinstance(value, str) and _is_strict_identifier(value) for value in scp):
        scp_values = cast("Sequence[str]", scp)
        return frozenset(scp_values) if len(scp_values) == len(frozenset(scp_values)) else None
    return None


def _numeric_date(value: JSONValue | None) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _optional_identifier(value: JSONValue | None) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) and _is_strict_identifier(value) else None


def _decode_json_segment(segment: str, *, maximum_json_depth: int) -> dict[str, JSONValue]:
    raw = _decode_base64url(segment)
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_non_finite)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError from exc
    if not isinstance(value, dict):
        raise TypeError
    decoded = cast("dict[str, JSONValue]", value)
    _validate_depth(decoded, maximum=maximum_json_depth)
    return decoded


def _decode_base64url(segment: str) -> bytes:
    if not _BASE64URL_PATTERN.fullmatch(segment):
        raise ValueError
    padding = "=" * (-len(segment) % 4)
    try:
        decoded = base64.b64decode(f"{segment}{padding}", altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != segment:
        raise ValueError
    return decoded


def _unique_object(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    value: dict[str, JSONValue] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _reject_non_finite(value: str) -> float:
    del value
    raise ValueError


def _validate_depth(value: JSONValue, *, maximum: int) -> None:
    stack: list[tuple[JSONValue, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > maximum:
            raise ValueError
        if isinstance(current, Mapping):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, (list, tuple)):
            stack.extend((item, depth + 1) for item in current)


def _freeze_json(value: JSONValue) -> JSONValue:
    if isinstance(value, dict):
        return cast("JSONValue", MappingProxyType({key: _freeze_json(item) for key, item in value.items()}))
    if isinstance(value, list):
        return cast("JSONValue", tuple(_freeze_json(item) for item in value))
    return value


def _prepare_signing_material(private_key: bytes, algorithm: JWTAlgorithm) -> tuple[PreparedSigningKey, bytes]:
    if algorithm not in _SUPPORTED_ALGORITHMS:
        _raise_config(f"Unsupported local signing algorithm: {algorithm}")
    try:
        key_value: object = private_key
        if not isinstance(key_value, bytes):  # pyright: ignore[reportUnnecessaryIsInstance]
            _reject()
        if algorithm == "HS256":
            if len(key_value) < _MINIMUM_HMAC_BYTES:
                _reject()
            return key_value, key_value
        loaded_key = serialization.load_pem_private_key(key_value, password=None)
        prepared = _validate_prepared_signing_key(loaded_key, algorithm)
        asymmetric_key = cast("rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey", prepared)
        verification_key = asymmetric_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except (TypeError, ValueError):
        _raise_config(f"Invalid {algorithm} JWT signing key")
    else:
        return prepared, verification_key


def _validate_prepared_signing_key(key: object, algorithm: JWTAlgorithm) -> PreparedSigningKey:
    if algorithm == "RS256" and (not isinstance(key, rsa.RSAPrivateKey) or key.key_size < _MINIMUM_RSA_BITS):
        _reject()
    if algorithm == "ES256" and (
        not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1)
    ):
        _reject()
    if algorithm == "EdDSA" and not isinstance(key, ed25519.Ed25519PrivateKey):
        _reject()
    return cast("PreparedSigningKey", key)


def _prepare_retained_verification_key(key: bytes, algorithm: JWTAlgorithm) -> PreparedVerificationKey:
    if algorithm not in _SUPPORTED_ALGORITHMS:
        _raise_config(f"Unsupported local verification algorithm: {algorithm}")
    try:
        key_value: object = key
        if not isinstance(key_value, bytes):  # pyright: ignore[reportUnnecessaryIsInstance]
            _reject()
        if algorithm == "HS256":
            if len(key_value) < _MINIMUM_HMAC_BYTES:
                _reject()
            return key_value
        prepared = serialization.load_pem_public_key(key_value)
        expected_type: type[object]
        if algorithm == "RS256":
            expected_type = rsa.RSAPublicKey
        elif algorithm == "ES256":
            expected_type = ec.EllipticCurvePublicKey
        else:
            expected_type = ed25519.Ed25519PublicKey
        if not isinstance(prepared, expected_type):
            _reject()
        return _validate_prepared_key(prepared, algorithm)
    except (TypeError, ValueError):
        _raise_config(f"Invalid {algorithm} JWT verification key")


def _prepare_public_jwk(
    value: Mapping[str, JSONValue] | None,
    key: PreparedSigningKey | PreparedVerificationKey,
    algorithm: JWTAlgorithm,
    key_id: str,
) -> Mapping[str, JSONValue] | None:
    if algorithm == "HS256":
        if value is not None:
            _raise_config("HS256 signing and verification keys cannot have a public JWK")
        return None
    public_key = _as_public_key(key)
    if value is None:
        raw = cast("dict[str, JSONValue]", jwt.get_algorithm_by_name(algorithm).to_jwk(public_key, as_dict=True))
        raw.update({"alg": algorithm, "kid": key_id, "key_ops": ["verify"], "use": "sig"})
    else:
        raw = dict(value)
        try:
            _validate_public_jwk(raw, algorithm)
            if raw.get("kid") not in {None, key_id}:
                _reject()
            jwk_key = _prepare_key(raw, algorithm)
        except (ImproperlyConfiguredException, PyJWTError, TypeError, ValueError):
            _raise_config(f"Invalid {algorithm} public JWK")
        if _public_key_bytes(jwk_key) != _public_key_bytes(public_key):
            _raise_config(f"{algorithm} public JWK does not correspond to key material")
        raw["kid"] = key_id
        raw["alg"] = algorithm
        raw["use"] = "sig"
        raw["key_ops"] = ["verify"]
    return cast("Mapping[str, JSONValue]", _freeze_json(cast("JSONValue", raw)))


def _as_public_key(
    key: PreparedSigningKey | PreparedVerificationKey,
) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey:
    if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey)):
        return key.public_key()
    return cast("rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey", key)


def _public_key_bytes(key: object) -> bytes:
    public_key = _as_public_key(cast("PreparedVerificationKey", key))
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _validate_local_access_claims(
    claims: Mapping[str, JSONValue], *, issuer: str, now: datetime
) -> dict[str, JSONValue]:
    payload = dict(claims)
    if not _LOCAL_ACCESS_REQUIRED_CLAIMS.issubset(payload) or frozenset(payload).difference(
        _LOCAL_ACCESS_ALLOWED_CLAIMS
    ):
        _raise_value("Invalid local access-token claims")
    identifiers = (
        payload.get("iss"),
        payload.get("sub"),
        payload.get("aud"),
        payload.get("client_id"),
        payload.get("jti"),
    )
    if (
        any(not isinstance(value, str) or not _is_strict_identifier(value) for value in identifiers)
        or payload.get("iss") != issuer
    ):
        _raise_value("Invalid local access-token claims")
    issued_at = payload.get("iat")
    expires_at = payload.get("exp")
    security_epoch = payload.get("se")
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or issued_at != int(now.timestamp())
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or expires_at <= issued_at
        or isinstance(security_epoch, bool)
        or not isinstance(security_epoch, int)
        or security_epoch < 0
    ):
        _raise_value("Invalid local access-token claims")
    not_before = payload.get("nbf")
    if not_before is not None and (
        isinstance(not_before, bool) or not isinstance(not_before, int) or not_before >= expires_at
    ):
        _raise_value("Invalid local access-token claims")
    scope = payload.get("scope")
    if scope is not None and (
        not isinstance(scope, str) or any(not _is_strict_identifier(value) for value in scope.split(" "))
    ):
        _raise_value("Invalid local access-token claims")
    return payload


def _if_none_match(value: str | None, etag: str) -> bool:
    if value is None:
        return False
    return any(
        candidate == "*" or candidate.removeprefix("W/") == etag for candidate in map(str.strip, value.split(","))
    )


def _aware_utc(value: datetime) -> datetime:
    timestamp_value: object = value
    if (
        not isinstance(timestamp_value, datetime)  # pyright: ignore[reportUnnecessaryIsInstance]
        or timestamp_value.tzinfo is None
        or timestamp_value.utcoffset() is None
    ):
        _raise_value("Access-token timestamps must be timezone-aware")
    return timestamp_value.astimezone(timezone.utc)


def _strict_identifier_value(value: str) -> str:
    identifier: object = value
    if (
        not isinstance(identifier, str)  # pyright: ignore[reportUnnecessaryIsInstance]
        or not _is_strict_identifier(identifier)
    ):
        _raise_value("Access-token identifiers must be non-empty normalized strings")
    return identifier


def _strict_key_id(value: str) -> str:
    key_id: object = value
    if (
        not isinstance(key_id, str)  # pyright: ignore[reportUnnecessaryIsInstance]
        or not _is_strict_identifier(key_id)
    ):
        _raise_config("Local key id must be a non-empty normalized string")
    return key_id


def _reject() -> NoReturn:
    raise ValueError


def _raise_value(message: str) -> NoReturn:
    raise ValueError(message)


def _prepare_key(key: VerificationKeyInput, algorithm: JWTAlgorithm) -> PreparedVerificationKey:
    try:
        prepared_input: object = key
        if isinstance(key, Mapping):
            _validate_public_jwk(key, algorithm)
            prepared_input = PyJWK.from_dict(cast("dict[str, object]", dict(key)), algorithm=algorithm).key
        prepared = jwt.get_algorithm_by_name(algorithm).prepare_key(prepared_input)
        return _validate_prepared_key(prepared, algorithm)
    except (NotImplementedError, PyJWTError, TypeError, ValueError):
        _raise_config(f"Invalid {algorithm} JWT verification key")


def _validate_public_jwk(value: Mapping[str, JSONValue], algorithm: JWTAlgorithm) -> None:
    if _PRIVATE_JWK_MEMBERS.intersection(value):
        raise ValueError
    if value.get("alg") not in {None, algorithm} or value.get("use") not in {None, "sig"}:
        raise ValueError
    key_ops = value.get("key_ops")
    if key_ops is not None and (
        not isinstance(key_ops, (list, tuple))
        or any(not isinstance(operation, str) for operation in key_ops)
        or tuple(key_ops) != ("verify",)
    ):
        raise ValueError
    expected = {"EdDSA": ("OKP", "Ed25519"), "ES256": ("EC", "P-256"), "RS256": ("RSA", None), "HS256": ("oct", None)}[
        algorithm
    ]
    if value.get("kty") != expected[0] or (expected[1] is not None and value.get("crv") != expected[1]):
        raise ValueError
    if algorithm == "HS256":
        raise ValueError


def _validate_prepared_key(key: object, algorithm: JWTAlgorithm) -> PreparedVerificationKey:
    if algorithm == "HS256":
        if not isinstance(key, bytes) or len(key) < _MINIMUM_HMAC_BYTES:
            raise ValueError
        return key
    if algorithm == "RS256":
        if not isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)) or key.key_size < _MINIMUM_RSA_BITS:
            raise ValueError
        return key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    if algorithm == "ES256":
        if not isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise ValueError
        return key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    if not isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        raise TypeError
    return key.public_key() if isinstance(key, ed25519.Ed25519PrivateKey) else key


def _strict_identifier(value: str) -> str:
    if not _is_strict_identifier(value):
        _raise_config("JWT identifiers must be non-empty normalized strings without controls or surrounding whitespace")
    return value


def _is_strict_identifier(value: str) -> bool:
    return (
        bool(value)
        and value == value.strip()
        and unicodedata.normalize("NFC", value) == value
        and all(not unicodedata.category(character).startswith("C") for character in value)
    )


def _raise_config(message: str) -> NoReturn:
    raise ImproperlyConfiguredException(detail=message)
