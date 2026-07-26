"""JWT parsing, verification profiles, signing, and bearer composition."""

import base64
import binascii
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import partial
from types import MappingProxyType
from typing import Generic, Literal, NoReturn, Protocol, TypeAlias, TypeVar, cast

import jwt
from anyio import to_thread
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jwt import PyJWK
from jwt.exceptions import PyJWTError
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.authentication import (
    Authenticated,
    AuthenticationOutcome,
    InvalidCredentials,
    VerificationUnavailable,
)
from litestar_security.context import AuthenticationEvidence

__all__ = ("JSONValue", "JWTClaims", "JWTValidationConfig", "JWTVerifier")

JSONValue: TypeAlias = bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"] | None
JWTAlgorithm: TypeAlias = Literal["EdDSA", "ES256", "RS256", "HS256"]
VerificationKeyInput: TypeAlias = bytes | str | PyJWK | Mapping[str, JSONValue]
PreparedVerificationKey: TypeAlias = (
    bytes | str | PyJWK | rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey
)
ClaimsT = TypeVar("ClaimsT")

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
_INVALID = InvalidCredentials()


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


class JWTVerifier(Protocol, Generic[ClaimsT]):
    """Verify one compact JWT against a configured trust domain."""

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
            await to_thread.run_sync(verify, abandon_on_cancel=True)
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
