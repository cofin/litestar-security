"""Verified claim types, validation configuration, and claim normalization.

Claims are treated as untrusted input until a verifier has checked the signature,
so this module never selects keys or trust material; it only decides whether an
already-verified claim set is well formed.
"""

from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from types import MappingProxyType
from typing import Literal, TypeAlias, cast

from litestar_security.authentication import InvalidCredentials
from litestar_security.providers._internal import JSONValue, raise_config
from litestar_security.providers.jwt._internal import (
    aware_utc,
    freeze_json,
    is_scope_token,
    is_strict_identifier,
    raise_value,
    strict_identifier,
    strict_identifier_value,
    strict_scope_value,
)

__all__ = ("JWTClaims", "JWTValidationConfig", "build_access_token_claims")


JWTAlgorithm: TypeAlias = Literal["EdDSA", "ES256", "RS256", "HS256"]


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


_INVALID = InvalidCredentials()


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


def normalize_claims(  # noqa: PLR0911 - preserve explicit sanitized outcomes at each security boundary
    payload: Mapping[str, JSONValue], config: JWTValidationConfig, *, now: datetime
) -> JWTClaims | InvalidCredentials:
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
    if isinstance(value, str):
        return frozenset({value}) if is_strict_identifier(value) else None
    if not isinstance(value, (list, tuple)) or not value:
        return None
    if any(not isinstance(item, str) or not is_strict_identifier(item) for item in value):
        return None
    audience_values = cast("Sequence[str]", value)
    audiences = frozenset(audience_values)
    return audiences if len(audiences) == len(audience_values) else None


def build_access_token_claims(  # noqa: C901, PLR0913 - explicit validated claim construction remains cohesive
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
    """Build minimal deterministic RFC 9068-style local access-token claims.

    The claim set is server-owned and minimal. Application data stays out of it,
    so a leaked token reveals nothing beyond the account binding.

    Args:
        issuer: The ``iss`` claim.
        audience: The ``aud`` claim.
        subject: The ``sub`` claim, normally the account identifier.
        client_id: The ``client_id`` claim.
        security_epoch: The epoch the token is bound to, so a later change invalidates it.
        now: The issue timestamp.
        lifetime: How long the token stays valid.
        scopes: The scopes to record.
        methods: Normalized authentication methods to preserve.
        traits: Normalized assurance traits to preserve.
        amr: Ordered authentication-method references to preserve.
        authenticated_at: Original authentication time for freshness checks.
        jti: The token identifier, or ``None`` to omit it.
        not_before: When the token becomes valid, or ``None`` to omit it.

    Returns:
        The claim set, ready to sign.
    """
    issuer = strict_identifier_value(issuer)
    audience = strict_identifier_value(audience)
    subject = strict_identifier_value(subject)
    client_id = strict_identifier_value(client_id)
    epoch_value: object = security_epoch
    if (
        isinstance(epoch_value, bool)
        or not isinstance(epoch_value, int)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
        or epoch_value < 0
    ):
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
