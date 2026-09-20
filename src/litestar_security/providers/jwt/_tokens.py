"""Token decoding, claim normalization, verification, and composite bearer slots."""

import base64
import binascii
import json
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from functools import partial
from inspect import iscoroutinefunction
from math import isfinite
from secrets import token_urlsafe
from time import perf_counter
from types import MappingProxyType
from typing import Any, Generic, Literal, NoReturn, Protocol, TypeAlias, TypedDict, TypeVar, cast, runtime_checkable

import jwt
from anyio import CapacityLimiter, fail_after, to_thread
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jwt import PyJWK
from jwt.exceptions import PyJWTError
from litestar.connection import ASGIConnection
from litestar.exceptions import ImproperlyConfiguredException
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
    VerificationUnavailable,
)
from litestar_security.context import AuthenticationEvidence
from litestar_security.providers._internal import (
    JSONValue,
    raise_config,
    reject_non_finite,
    safe_increment,
    safe_observe,
    unique_object,
    validate_depth,
)
from litestar_security.workers import NoOpSecurityMetrics, SecurityMetrics, WorkerLimits

__all__ = (
    "BearerSlotSelector",
    "BearerTokenSlot",
    "CompositeBearerConfig",
    "JWTAlgorithm",
    "JWTClaims",
    "JWTValidationConfig",
    "JWTVerifier",
    "LocalJWKSDocument",
    "PreparedSigningKey",
    "PreparedVerificationKey",
    "PyJWTVerifier",
    "SigningKey",
    "SyncJWTVerifier",
    "UnverifiedJWTRoute",
    "VerificationKey",
    "VerificationKeyInput",
    "aware_utc",
    "build_access_token_claims",
    "decode_base64url",
    "decode_json_segment",
    "extend_composite_bearer",
    "freeze_json",
    "is_scope_token",
    "is_strict_identifier",
    "metric_sink",
    "normalize_audiences",
    "normalize_claims",
    "normalize_verifier",
    "parse_unverified_jwt_route",
    "prepare_key",
    "prepared_verification_key",
    "raise_value",
    "reject",
    "run_worker",
    "strict_identifier",
    "strict_identifier_value",
    "strict_key_id",
    "strict_scope_value",
    "validate_header",
    "validate_limiter",
    "validate_local_access_claims",
)

JWTAlgorithm: TypeAlias = Literal["EdDSA", "ES256", "RS256", "HS256"]
VerificationKeyInput: TypeAlias = bytes | str | PyJWK | Mapping[str, JSONValue]
PreparedVerificationKey: TypeAlias = (
    bytes | str | PyJWK | rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey
)
PreparedSigningKey: TypeAlias = bytes | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey

ClaimsT = TypeVar("ClaimsT")
ResultT = TypeVar("ResultT")
UserT = TypeVar("UserT")

_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_SUPPORTED_ALGORITHMS = frozenset({"EdDSA", "ES256", "RS256", "HS256"})
_ACCESS_TOKEN_TYPES = frozenset({"at+jwt", "application/at+jwt"})
_BASE_REQUIRED_CLAIMS = frozenset({"iss", "aud", "exp", "iat"})
_ACCESS_REQUIRED_CLAIMS = frozenset({"client_id", "jti"})
_FORBIDDEN_JOSE_HEADERS = frozenset({"b64", "crit", "jku", "jwk", "x5c", "x5t", "x5t#S256", "x5u"})
_LOCAL_ACCESS_REQUIRED_CLAIMS = frozenset({"iss", "sub", "aud", "exp", "iat", "client_id", "jti", "se"})
_LOCAL_ACCESS_ALLOWED_CLAIMS = _LOCAL_ACCESS_REQUIRED_CLAIMS.union({
    "amr",
    "auth_time",
    "nbf",
    "scope",
    "security_traits",
})
_PRIVATE_JWK_MEMBERS = frozenset({"d", "dp", "dq", "k", "oth", "p", "q", "qi"})
_MINIMUM_HMAC_BYTES = 32
_MINIMUM_RSA_BITS = 2048
_MAXIMUM_WORKER_TOKENS = 1_024
_COMPACT_SEGMENT_COUNT = 3
_ASCII_CONTROL_LIMIT = 32
_ASCII_DELETE = 127
_BEARER_PREFIX_LENGTH = len(b"Bearer ")
_INVALID = InvalidCredentials()


def raise_value(message: str) -> NoReturn:
    """Raise a ValueError with a detail message."""
    raise ValueError(message)


def reject() -> NoReturn:
    """Raise an unadorned ValueError to reject invalid token material."""
    raise ValueError


def is_strict_identifier(value: str) -> bool:
    """Validate that a string is non-empty, stripped, NFC-normalized, and control-free."""
    return (
        bool(value)
        and value == value.strip()
        and unicodedata.normalize("NFC", value) == value
        and all(not unicodedata.category(character).startswith("C") for character in value)
    )


def is_scope_token(value: str) -> bool:
    """Validate that a string is a valid OAuth scope token."""
    return bool(value) and all(
        character == "!" or "#" <= character <= "[" or "]" <= character <= "~" for character in value
    )


def strict_identifier(value: str) -> str:
    """Ensure a string is a valid normalized identifier, raising ImproperlyConfiguredException."""
    if not is_strict_identifier(value):
        raise_config("JWT identifiers must be non-empty normalized strings without controls or surrounding whitespace")
    return value


def strict_identifier_value(value: str) -> str:
    """Ensure a string is a valid normalized identifier, raising ValueError."""
    identifier = cast("object", value)
    if not isinstance(identifier, str) or not is_strict_identifier(identifier):
        raise_value("Access-token identifiers must be non-empty normalized strings")
    return identifier


def strict_scope_value(value: str) -> str:
    """Ensure a string is a valid OAuth scope token, raising ValueError."""
    scope = cast("object", value)
    if not isinstance(scope, str) or not is_scope_token(scope):
        raise_value("Access-token scope values must be OAuth scope tokens")
    return scope


def strict_key_id(value: str) -> str:
    """Ensure a string is a valid key id, raising ImproperlyConfiguredException."""
    key_id = cast("object", value)
    if not isinstance(key_id, str) or not is_strict_identifier(key_id):
        raise_config("Local key id must be a non-empty normalized string")
    return key_id


def decode_base64url(segment: str) -> bytes:
    """Strictly decode a base64url-encoded segment without padding leniency."""
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


def freeze_json(value: JSONValue) -> JSONValue:
    """Recursively freeze JSON mappings and sequences into immutable containers."""
    if isinstance(value, dict):
        return cast("JSONValue", MappingProxyType({key: freeze_json(item) for key, item in value.items()}))
    if isinstance(value, list):
        return cast("JSONValue", tuple(freeze_json(item) for item in value))
    return value


def decode_json_segment(segment: str, *, maximum_json_depth: int) -> dict[str, JSONValue]:
    """Decode and validate one JSON segment from a compact token."""
    raw = decode_base64url(segment)
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_non_finite)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError from exc
    if not isinstance(value, dict):
        raise TypeError
    decoded = cast("dict[str, JSONValue]", value)
    validate_depth(decoded, maximum=maximum_json_depth)
    return decoded


def aware_utc(value: datetime) -> datetime:
    """Ensure a timestamp is timezone-aware and normalized to UTC."""
    timestamp_value = cast("object", value)
    if (
        not isinstance(timestamp_value, datetime)
        or timestamp_value.tzinfo is None
        or timestamp_value.utcoffset() is None
    ):
        raise_value("Access-token timestamps must be timezone-aware")
    return timestamp_value.astimezone(timezone.utc)


def metric_sink(metrics: SecurityMetrics | None) -> SecurityMetrics:
    """Validate and return an active or no-op SecurityMetrics instance."""
    sink = NoOpSecurityMetrics() if metrics is None else metrics
    if not callable(getattr(sink, "increment", None)) or not callable(getattr(sink, "observe", None)):
        raise_config("JWT metrics must implement SecurityMetrics")
    return sink


def validate_limiter(limiter: object) -> CapacityLimiter:
    """Ensure a capacity limiter has bounded, positive capacity."""
    total_tokens = getattr(limiter, "total_tokens", None)
    if (
        not isinstance(limiter, CapacityLimiter)
        or not isinstance(total_tokens, int)
        or isinstance(total_tokens, bool)
        or not 1 <= total_tokens <= _MAXIMUM_WORKER_TOKENS
    ):
        raise_config("JWT worker limiter must have finite bounded capacity")
    return limiter


async def run_worker(
    operation: Callable[[], ResultT],
    *,
    limiter: CapacityLimiter,
    worker_timeout: float,
    metrics: SecurityMetrics,
    operation_metric: str,
) -> ResultT:
    """Execute a CPU-bound operation inside a thread with timeout and metrics tracking."""
    if limiter.borrowed_tokens >= limiter.total_tokens:
        safe_increment(metrics, "security.worker.saturation")
    queued_at = perf_counter()

    def run() -> ResultT:
        started = perf_counter()
        safe_observe(metrics, "security.worker.wait", started - queued_at)
        try:
            return operation()
        finally:
            elapsed = perf_counter() - started
            safe_observe(metrics, "security.worker.duration", elapsed)
            safe_observe(metrics, operation_metric, elapsed)

    with fail_after(worker_timeout):
        return await to_thread.run_sync(run, abandon_on_cancel=True, limiter=limiter)


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
        key_id = strict_key_id(self.key_id)
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
        key_id = strict_key_id(self.key_id)
        prepared = _prepare_retained_verification_key(self.key, self.algorithm)
        public_jwk = _prepare_public_jwk(self.public_jwk, prepared, self.algorithm, key_id)
        object.__setattr__(self, "key_id", key_id)
        object.__setattr__(self, "public_jwk", public_jwk)
        object.__setattr__(self, "_prepared_key", prepared)


def prepared_verification_key(key: VerificationKey) -> PreparedVerificationKey:
    """Return validated key material already prepared during construction."""
    return cast("PreparedVerificationKey", cast("Any", key)._prepared_key)


def prepare_key(key: VerificationKeyInput, algorithm: JWTAlgorithm) -> PreparedVerificationKey:
    """Prepare verification key input into crypto-usable key material."""
    try:
        prepared_input: object = key
        if isinstance(key, Mapping):
            _validate_public_jwk(key, algorithm)
            prepared_input = PyJWK.from_dict(cast("dict[str, object]", dict(key)), algorithm=algorithm).key
        prepared = jwt.get_algorithm_by_name(algorithm).prepare_key(prepared_input)
        return _validate_prepared_key(prepared, algorithm)
    except (NotImplementedError, PyJWTError, TypeError, ValueError):
        raise_config(f"Invalid {algorithm} JWT verification key")


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


class LocalJWKSDocument(TypedDict):
    keys: list[_RSAPublicJWK | _ECPublicJWK | _OKPPublicJWK]


def _prepare_signing_material(private_key: bytes, algorithm: JWTAlgorithm) -> tuple[PreparedSigningKey, bytes]:
    if algorithm not in _SUPPORTED_ALGORITHMS:
        raise_config(f"Unsupported local signing algorithm: {algorithm}")
    try:
        key_value = cast("object", private_key)
        if not isinstance(key_value, bytes):
            reject()
        if algorithm == "HS256":
            if len(key_value) < _MINIMUM_HMAC_BYTES:
                reject()
            return key_value, key_value
        loaded_key = serialization.load_pem_private_key(key_value, password=None)
        prepared = _validate_prepared_signing_key(loaded_key, algorithm)
        asymmetric_key = cast("rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey", prepared)
        verification_key = asymmetric_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except (TypeError, ValueError):
        raise_config(f"Invalid {algorithm} JWT signing key")
    else:
        return prepared, verification_key


def _validate_prepared_signing_key(key: object, algorithm: JWTAlgorithm) -> PreparedSigningKey:
    if algorithm == "RS256" and (not isinstance(key, rsa.RSAPrivateKey) or key.key_size < _MINIMUM_RSA_BITS):
        reject()
    if algorithm == "ES256" and (
        not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1)
    ):
        reject()
    if algorithm == "EdDSA" and not isinstance(key, ed25519.Ed25519PrivateKey):
        reject()
    return cast("PreparedSigningKey", key)


def _prepare_retained_verification_key(key: bytes, algorithm: JWTAlgorithm) -> PreparedVerificationKey:
    if algorithm not in _SUPPORTED_ALGORITHMS:
        raise_config(f"Unsupported local verification algorithm: {algorithm}")
    try:
        key_value = cast("object", key)
        if not isinstance(key_value, bytes):
            reject()
        if algorithm == "HS256":
            if len(key_value) < _MINIMUM_HMAC_BYTES:
                reject()
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
            reject()
        return _validate_prepared_key(prepared, algorithm)
    except (TypeError, ValueError):
        raise_config(f"Invalid {algorithm} JWT verification key")


def _prepare_public_jwk(
    value: Mapping[str, JSONValue] | None,
    key: PreparedSigningKey | PreparedVerificationKey,
    algorithm: JWTAlgorithm,
    key_id: str,
) -> Mapping[str, JSONValue] | None:
    if algorithm == "HS256":
        if value is not None:
            raise_config("HS256 signing and verification keys cannot have a public JWK")
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
                reject()
            jwk_key = prepare_key(raw, algorithm)
        except (ImproperlyConfiguredException, PyJWTError, TypeError, ValueError):
            raise_config(f"Invalid {algorithm} public JWK")
        if _public_key_bytes(jwk_key) != _public_key_bytes(public_key):
            raise_config(f"{algorithm} public JWK does not correspond to key material")
        raw["kid"] = key_id
        raw["alg"] = algorithm
        raw["use"] = "sig"
        raw["key_ops"] = ["verify"]
    return cast("Mapping[str, JSONValue]", freeze_json(cast("JSONValue", raw)))


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


@dataclass(frozen=True, slots=True)
class JWTClaims:
    """Verified, normalized JWT claims without the compact credential."""

    issuer: str
    subject: str | None
    audiences: frozenset[str]
    expires_at: datetime
    issued_at: datetime
    not_before: datetime | None
    token_id: str | None
    client_id: str | None
    scopes: frozenset[str]
    raw: Mapping[str, JSONValue]
    bearer_slot: str | None = None

    def __post_init__(self) -> None:
        """Freeze nested collections at the verified-claims boundary."""
        object.__setattr__(self, "audiences", frozenset(self.audiences))
        object.__setattr__(self, "scopes", frozenset(self.scopes))
        object.__setattr__(self, "raw", cast("Mapping[str, JSONValue]", freeze_json(dict(self.raw))))


@dataclass(frozen=True, slots=True)
class JWTValidationConfig:
    """Pin one issuer's accepted JWT verification profile."""

    issuer: str
    audiences: frozenset[str]
    algorithms: frozenset[str]
    required_claims: frozenset[str] = frozenset({"iss", "sub", "aud", "exp", "iat"})
    access_token_profile: bool = True
    subject_required: bool = True
    clock_skew: timedelta = timedelta(seconds=30)
    maximum_lifetime: timedelta | None = timedelta(hours=1)
    token_types: frozenset[str] = _ACCESS_TOKEN_TYPES

    def __post_init__(self) -> None:
        """Normalize immutable inputs and reject an unsafe verification profile."""
        issuer = strict_identifier(self.issuer)
        audiences = frozenset(strict_identifier(audience) for audience in self.audiences)
        algorithms = frozenset(self.algorithms)
        unsupported = algorithms.difference(_SUPPORTED_ALGORITHMS)
        if not audiences:
            raise_config("JWT validation audiences must not be empty")
        if not algorithms:
            raise_config("JWT validation algorithms must not be empty")
        if unsupported:
            raise_config(f"Unsupported JWT validation algorithm: {min(unsupported)}")
        if self.clock_skew < timedelta(0):
            raise_config("JWT clock skew must not be negative")
        if self.maximum_lifetime is not None and self.maximum_lifetime <= timedelta(0):
            raise_config("JWT maximum lifetime must be positive")
        if self.subject_required.__class__ is not bool or (self.access_token_profile and not self.subject_required):
            raise_config("JWT subject requirement is invalid")
        required = frozenset(strict_identifier(name) for name in self.required_claims).union(_BASE_REQUIRED_CLAIMS)
        required = required.union({"sub"}) if self.subject_required else required.difference({"sub"})
        if self.access_token_profile:
            required = required.union(_ACCESS_REQUIRED_CLAIMS)
        token_types = frozenset(strict_identifier(value).lower() for value in self.token_types)
        if not token_types:
            raise_config("JWT token types must not be empty")
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "audiences", audiences)
        object.__setattr__(self, "algorithms", algorithms)
        object.__setattr__(self, "required_claims", required)
        object.__setattr__(self, "token_types", token_types)


def validate_header(
    header: Mapping[str, JSONValue], config: JWTValidationConfig, *, require_key_id: bool
) -> str | InvalidCredentials:
    """Validate untrusted JOSE header algorithm and type against configuration."""
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or algorithm not in config.algorithms or algorithm == "none":
        return _INVALID
    token_type = header.get("typ")
    if not isinstance(token_type, str) or token_type.lower() not in config.token_types:
        return _INVALID
    if _FORBIDDEN_JOSE_HEADERS.intersection(header):
        return _INVALID
    key_id = header.get("kid")
    if key_id is not None and (not isinstance(key_id, str) or not is_strict_identifier(key_id)):
        return _INVALID
    if require_key_id and key_id is None:
        return _INVALID
    return algorithm


def normalize_claims(
    payload: Mapping[str, JSONValue], config: JWTValidationConfig, *, now: datetime
) -> JWTClaims | InvalidCredentials:
    """Normalize verified claims against a pinned JWT validation profile."""
    if not config.required_claims.issubset(payload):
        return _INVALID
    issuer = payload.get("iss")
    subject = payload.get("sub")
    if (
        not isinstance(issuer, str)
        or issuer != config.issuer
        or not is_strict_identifier(issuer)
        or (subject is not None and (not isinstance(subject, str) or not is_strict_identifier(subject)))
        or (config.subject_required and subject is None)
    ):
        return _INVALID
    audiences = normalize_audiences(payload.get("aud"))
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


def normalize_audiences(value: JSONValue | None) -> frozenset[str] | None:
    """Normalize and validate audience claims into a frozenset of strict identifiers."""
    if isinstance(value, str):
        return frozenset({value}) if is_strict_identifier(value) else None
    if not isinstance(value, (list, tuple)) or not value:
        return None
    if any(not isinstance(item, str) or not is_strict_identifier(item) for item in value):
        return None
    audience_values = cast("Sequence[str]", value)
    audiences = frozenset(audience_values)
    return audiences if len(audiences) == len(audience_values) else None


def build_access_token_claims(
    *,
    issuer: str,
    audience: str,
    subject: str,
    client_id: str,
    security_epoch: int,
    now: datetime,
    lifetime: timedelta,
    scopes: AbstractSet[str] = frozenset(),
    methods: AbstractSet[str] = frozenset(),
    traits: AbstractSet[str] = frozenset(),
    amr: Sequence[str] = (),
    authenticated_at: datetime | None = None,
    jti: str | None = None,
    not_before: datetime | None = None,
) -> Mapping[str, JSONValue]:
    """Build minimal deterministic RFC 9068-style local access-token claims."""
    issuer = strict_identifier_value(issuer)
    audience = strict_identifier_value(audience)
    subject = strict_identifier_value(subject)
    client_id = strict_identifier_value(client_id)
    epoch_value = cast("object", security_epoch)
    if isinstance(epoch_value, bool) or not isinstance(epoch_value, int) or epoch_value < 0:
        raise_value("Access-token security epoch must be a non-negative integer")
    now = aware_utc(now)
    if lifetime <= timedelta(0):
        raise_value("Access-token lifetime must be positive")
    expires_at = now + lifetime
    issued_timestamp = int(now.timestamp())
    expires_timestamp = int(expires_at.timestamp())
    if expires_timestamp <= issued_timestamp:
        raise_value("Access-token lifetime must span at least one whole second")
    if not_before is not None:
        not_before = aware_utc(not_before)
        if not_before >= expires_at:
            raise_value("Access-token not-before must precede expiry")
    token_id = strict_identifier_value(jti if jti is not None else token_urlsafe(32))
    normalized_scopes = frozenset(strict_scope_value(scope) for scope in scopes)
    normalized_methods = frozenset(strict_identifier_value(method) for method in methods)
    normalized_traits = frozenset(strict_identifier_value(trait) for trait in traits)
    normalized_amr = tuple(strict_identifier_value(method) for method in amr)
    if authenticated_at is not None:
        authenticated_at = aware_utc(authenticated_at)
        if authenticated_at > now:
            raise_value("Access-token authentication time cannot be in the future")
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
    if normalized_methods or normalized_amr:
        claims["amr"] = cast("JSONValue", list(normalized_amr or sorted(normalized_methods)))
    if normalized_traits:
        claims["security_traits"] = cast("JSONValue", sorted(normalized_traits))
    if authenticated_at is not None:
        claims["auth_time"] = int(authenticated_at.timestamp())
    if not_before is not None:
        claims["nbf"] = int(not_before.timestamp())
    return cast("Mapping[str, JSONValue]", MappingProxyType(claims))


def validate_local_access_claims(
    claims: Mapping[str, JSONValue], *, issuer: str, now: datetime
) -> dict[str, JSONValue]:
    """Validate and enforce constraints for locally issued access tokens."""
    payload = dict(claims)
    if not _LOCAL_ACCESS_REQUIRED_CLAIMS.issubset(payload) or frozenset(payload).difference(
        _LOCAL_ACCESS_ALLOWED_CLAIMS
    ):
        raise_value("Invalid local access-token claims")
    identifiers = (
        payload.get("iss"),
        payload.get("sub"),
        payload.get("aud"),
        payload.get("client_id"),
        payload.get("jti"),
    )
    if (
        any(not isinstance(value, str) or not is_strict_identifier(value) for value in identifiers)
        or payload.get("iss") != issuer
    ):
        raise_value("Invalid local access-token claims")
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
        raise_value("Invalid local access-token claims")
    not_before = payload.get("nbf")
    if not_before is not None and (
        isinstance(not_before, bool) or not isinstance(not_before, int) or not_before >= expires_at
    ):
        raise_value("Invalid local access-token claims")
    authentication_time = payload.get("auth_time")
    if authentication_time is not None and (
        isinstance(authentication_time, bool)
        or not isinstance(authentication_time, int)
        or authentication_time > issued_at
    ):
        raise_value("Invalid local access-token claims")
    scope = payload.get("scope")
    if scope is not None and (
        not isinstance(scope, str) or any(not is_scope_token(value) for value in scope.split(" "))
    ):
        raise_value("Invalid local access-token claims")
    for claim_name in ("amr", "security_traits"):
        values = payload.get(claim_name)
        if values is not None and (
            not isinstance(values, list)
            or not values
            or len(values) != len(frozenset(cast("list[object]", values)))
            or any(not isinstance(value, str) or not is_strict_identifier(value) for value in values)
        ):
            raise_value("Invalid local access-token claims")
    return payload


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
            or any(not is_scope_token(value) for value in scope_values)
        ):
            return None
        return frozenset(scope_values)
    if isinstance(scp, (list, tuple)) and all(isinstance(value, str) and is_scope_token(value) for value in scp):
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
    return value if isinstance(value, str) and is_strict_identifier(value) else None


@runtime_checkable
class JWTVerifier(Protocol, Generic[ClaimsT]):
    """Verify one compact JWT against a configured trust domain."""

    @property
    def config(self) -> JWTValidationConfig:
        """Return the verifier's pinned trust profile."""
        ...

    async def verify(self, token: str, *, now: datetime) -> AuthenticationOutcome[ClaimsT]:
        """Return a structured authentication outcome."""
        ...


@runtime_checkable
class SyncJWTVerifier(Protocol, Generic[ClaimsT]):
    """Blocking custom verifier normalized once into the crypto worker."""

    @property
    def config(self) -> JWTValidationConfig:
        """Return the verifier's pinned trust profile."""
        ...

    def verify(self, token: str, *, now: datetime) -> AuthenticationOutcome[ClaimsT]:
        """Return a structured authentication outcome."""
        ...


def normalize_verifier(
    verifier: JWTVerifier[ClaimsT] | SyncJWTVerifier[ClaimsT],
    *,
    worker_limits: WorkerLimits | None = None,
    metrics: SecurityMetrics | None = None,
) -> JWTVerifier[ClaimsT]:
    """Normalize one custom verifier once without blocking the event loop."""
    verify_method = getattr(verifier, "verify", None)
    config = getattr(verifier, "config", None)
    if not callable(verify_method) or not isinstance(config, JWTValidationConfig):
        raise_config("JWT verifier must define verify and JWTValidationConfig")
    workers = WorkerLimits() if worker_limits is None else worker_limits
    workers_obj = cast("object", workers)
    if not isinstance(workers_obj, WorkerLimits):
        raise_config("JWT verifier worker limits must be WorkerLimits")
    sink = metric_sink(metrics)
    if iscoroutinefunction(verify_method):
        return cast("JWTVerifier[ClaimsT]", verifier)
    return _WorkerJWTVerifier(
        config=config,
        verify_sync=cast("Callable[..., AuthenticationOutcome[ClaimsT]]", verify_method),
        workers=workers,
        metrics=sink,
    )


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
        header = decode_json_segment(segments[0], maximum_json_depth=maximum_json_depth)
        payload = decode_json_segment(segments[1], maximum_json_depth=maximum_json_depth)
        decode_base64url(segments[2])
    except (TypeError, ValueError):
        return _INVALID
    return UnverifiedJWTRoute(
        header=cast("Mapping[str, JSONValue]", freeze_json(header)),
        payload=cast("Mapping[str, JSONValue]", freeze_json(payload)),
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
    worker_timeout: float = field(default=10.0, repr=False, compare=False)
    metrics: SecurityMetrics = field(default_factory=NoOpSecurityMetrics, repr=False, compare=False)
    _prepared_keys: Mapping[str, PreparedVerificationKey] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate and prepare fixed verification material once."""
        if self.maximum_token_bytes < 1:
            raise_config("JWT maximum token bytes must be positive")
        if (
            self.worker_timeout.__class__ not in {int, float}
            or not isfinite(self.worker_timeout)
            or self.worker_timeout <= 0
        ):
            raise_config("JWT worker timeout must be finite and positive")
        limiter = WorkerLimits().crypto_limiter if self.limiter is None else validate_limiter(self.limiter)
        metrics = metric_sink(self.metrics)
        mechanism_name = strict_identifier(self.mechanism_name)
        slot_name = strict_identifier(self.slot_name)
        prepared: dict[str, PreparedVerificationKey] = {}
        for algorithm in self.config.algorithms:
            prepared[algorithm] = prepare_key(self.key, cast("JWTAlgorithm", algorithm))
        object.__setattr__(self, "mechanism_name", mechanism_name)
        object.__setattr__(self, "slot_name", slot_name)
        object.__setattr__(self, "limiter", limiter)
        object.__setattr__(self, "worker_timeout", float(self.worker_timeout))
        object.__setattr__(self, "metrics", metrics)
        object.__setattr__(self, "_prepared_keys", MappingProxyType(prepared))

    async def verify(self, token: str, *, now: datetime) -> AuthenticationOutcome[JWTClaims]:
        """Verify signature and claims, returning only sanitized outcomes."""
        if now.tzinfo is None or now.utcoffset() is None:
            return _INVALID
        now = now.astimezone(timezone.utc)
        route = parse_unverified_jwt_route(token, maximum_token_bytes=self.maximum_token_bytes)
        if isinstance(route, InvalidCredentials):
            return route
        header_result = validate_header(route.header, self.config, require_key_id=self.require_key_id)
        if isinstance(header_result, InvalidCredentials):
            return header_result
        algorithm = header_result
        claims = normalize_claims(route.payload, self.config, now=now)
        if isinstance(claims, InvalidCredentials):
            return claims
        verify = partial(_verify_signature, token, self._prepared_keys[algorithm], algorithm)
        try:
            await run_worker(
                verify,
                limiter=cast("CapacityLimiter", self.limiter),
                worker_timeout=self.worker_timeout,
                metrics=self.metrics,
                operation_metric="security.jwt.verify_duration",
            )
        except (PyJWTError, TypeError, ValueError):
            return _INVALID
        except Exception:
            return VerificationUnavailable()
        return Authenticated(
            claims=claims,
            evidence=AuthenticationEvidence(
                mechanism=self.mechanism_name, slot=self.slot_name, authenticated_at=now, expires_at=claims.expires_at
            ),
        )


@dataclass(frozen=True, slots=True)
class _WorkerJWTVerifier(Generic[ClaimsT]):
    config: JWTValidationConfig
    verify_sync: Callable[..., AuthenticationOutcome[ClaimsT]] = field(repr=False)
    workers: WorkerLimits = field(repr=False)
    metrics: SecurityMetrics = field(repr=False)

    async def verify(self, token: str, *, now: datetime) -> AuthenticationOutcome[ClaimsT]:
        try:
            return await run_worker(
                partial(self.verify_sync, token, now=now),
                limiter=self.workers.crypto_limiter,
                worker_timeout=self.workers.timeout,
                metrics=self.metrics,
                operation_metric="security.jwt.verify_duration",
            )
        except Exception:
            return VerificationUnavailable()


def _verify_signature(token: str, key: PreparedVerificationKey, algorithm: str) -> None:
    jwt.decode_complete(
        token,
        key=key,
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
    """Extend one library-built composite while preserving one physical bearer owner."""
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
        """Build one physical slot and one native bearer mechanism."""
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

    def extract(self, connection: ASGIConnection[Any, Any, Any, Any]) -> CredentialExtraction[str]:
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
