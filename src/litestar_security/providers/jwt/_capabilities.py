"""Claim construction and normalization for stateless capability JWTs."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from math import isfinite
from secrets import token_urlsafe
from typing import cast

from litestar_security.authentication import InvalidCredentials
from litestar_security.providers._internal import JSONValue
from litestar_security.providers.jwt._claims import JWTAlgorithm
from litestar_security.providers.jwt._internal import (
    aware_utc,
    freeze_json,
    is_strict_identifier,
    raise_value,
    strict_identifier_value,
)

__all__ = ("CAPABILITY_TOKEN_TYPE", "VerifiedCapability")

CAPABILITY_TOKEN_TYPE = "capability+jwt"  # noqa: S105 - JOSE typ identifier, not a credential
_CAPABILITY_CLOCK_SKEW = timedelta(seconds=30)
_CAPABILITY_MAXIMUM_LIFETIME = timedelta(hours=24)
_MAXIMUM_APPLICATION_CLAIM_DEPTH = 32
_RESERVED_CAPABILITY_CLAIMS = frozenset({"iss", "sub", "aud", "exp", "iat", "nbf", "purpose", "jti"})
_REQUIRED_CAPABILITY_CLAIMS = _RESERVED_CAPABILITY_CLAIMS.difference({"nbf"})
_FORBIDDEN_JOSE_HEADERS = frozenset({"b64", "crit", "jku", "jwk", "x5c", "x5t", "x5t#S256", "x5u"})
_SUPPORTED_CAPABILITY_ALGORITHMS = frozenset({"EdDSA", "ES256", "RS256", "HS256"})
_INVALID = InvalidCredentials()


@dataclass(frozen=True, slots=True)
class VerifiedCapability:
    """Verified application capability claims without the compact credential.

    Args:
        purpose: The exact application-defined capability purpose.
        subject: The principal the capability represents.
        audience: The exact service or resource allowed to accept the capability.
        issued_at: The timezone-aware timestamp at which the capability was issued.
        expires_at: The timezone-aware timestamp at which the capability expires.
        token_id: The unique capability identifier used for optional application-level consumption.
        claims: The immutable application claims with reserved credential claims removed.

    Returns:
        A frozen capability projection that contains no compact credential.

    Raises:
        Never directly raises; invalid credentials are rejected before this value is created.
    """

    purpose: str
    subject: str
    audience: str
    issued_at: datetime
    expires_at: datetime
    token_id: str
    claims: Mapping[str, JSONValue]

    def __post_init__(self) -> None:
        """Freeze application claims at the verified boundary."""
        object.__setattr__(self, "claims", cast("Mapping[str, JSONValue]", freeze_json(dict(self.claims))))


def validate_capability_header(
    header: Mapping[str, JSONValue],
) -> tuple[JWTAlgorithm, str] | InvalidCredentials:
    """Validate immutable routing fields for one capability JWT.

    Args:
        header: The cryptographically untrusted JOSE header.

    Returns:
        The exact algorithm and key identifier to use for signature verification,
        or a sanitized rejected outcome.
    """
    algorithm = header.get("alg")
    token_type = header.get("typ")
    key_id = header.get("kid")
    if (
        not isinstance(algorithm, str)
        or algorithm not in _SUPPORTED_CAPABILITY_ALGORITHMS
        or algorithm == "none"
        or token_type != CAPABILITY_TOKEN_TYPE
        or not isinstance(key_id, str)
        or not is_strict_identifier(key_id)
        or _FORBIDDEN_JOSE_HEADERS.intersection(header)
    ):
        return _INVALID
    return cast("JWTAlgorithm", algorithm), key_id


def build_capability_claims(  # noqa: PLR0913 - explicit claim construction inputs remain cohesive
    *,
    issuer: str,
    purpose: str,
    subject: str,
    audience: str,
    lifetime: timedelta,
    claims: Mapping[str, JSONValue],
    now: datetime,
) -> Mapping[str, JSONValue]:
    """Build one bounded, single-purpose capability claim set."""
    issuer = strict_identifier_value(issuer)
    purpose = strict_identifier_value(purpose)
    subject = strict_identifier_value(subject)
    audience = strict_identifier_value(audience)
    now = aware_utc(now)
    if lifetime <= timedelta(0) or lifetime > _CAPABILITY_MAXIMUM_LIFETIME:
        raise_value("Capability lifetime must be positive and no longer than 24 hours")
    if any(key.__class__ is not str for key in claims):
        raise_value("Capability application claims must use JSON object keys")
    if _RESERVED_CAPABILITY_CLAIMS.intersection(claims):
        raise_value("Capability application claims must not use reserved names")
    expires_at = now + lifetime
    issued_timestamp = int(now.timestamp())
    expires_timestamp = int(expires_at.timestamp())
    if expires_timestamp <= issued_timestamp:
        raise_value("Capability lifetime must span at least one whole second")
    payload = {key: _copy_json(value) for key, value in claims.items()}
    payload.update({
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "exp": expires_timestamp,
        "iat": issued_timestamp,
        "purpose": purpose,
        "jti": strict_identifier_value(token_urlsafe(32)),
    })
    return payload


def normalize_capability_claims(  # noqa: PLR0911 - preserve explicit sanitized outcomes at each security boundary
    payload: Mapping[str, JSONValue], *, purpose: str, audience: str, issuer: str, now: datetime
) -> VerifiedCapability | InvalidCredentials:
    """Normalize verified capability claims into one sanitized outcome."""
    try:
        now = aware_utc(now)
    except (AttributeError, TypeError, ValueError):
        return _INVALID
    if not _REQUIRED_CAPABILITY_CLAIMS.issubset(payload):
        return _INVALID
    claim_issuer = payload.get("iss")
    claim_subject = payload.get("sub")
    claim_audience = payload.get("aud")
    claim_purpose = payload.get("purpose")
    claim_token_id = payload.get("jti")
    if (
        not isinstance(claim_issuer, str)
        or not is_strict_identifier(claim_issuer)
        or not isinstance(claim_subject, str)
        or not is_strict_identifier(claim_subject)
        or not isinstance(claim_audience, str)
        or not is_strict_identifier(claim_audience)
        or not isinstance(claim_purpose, str)
        or not is_strict_identifier(claim_purpose)
        or not isinstance(claim_token_id, str)
        or not is_strict_identifier(claim_token_id)
        or claim_issuer != issuer
        or claim_audience != audience
        or claim_purpose != purpose
    ):
        return _INVALID
    issued_at = _numeric_date(payload.get("iat"))
    expires_at = _numeric_date(payload.get("exp"))
    not_before_value = payload.get("nbf")
    not_before = None if not_before_value is None else _numeric_date(not_before_value)
    if issued_at is None or expires_at is None or (not_before_value is not None and not_before is None):
        return _INVALID
    if (
        issued_at > now + _CAPABILITY_CLOCK_SKEW
        or expires_at <= now - _CAPABILITY_CLOCK_SKEW
        or (not_before is not None and not_before > now + _CAPABILITY_CLOCK_SKEW)
    ):
        return _INVALID
    lifetime = expires_at - issued_at
    if (
        lifetime <= timedelta(0)
        or lifetime > _CAPABILITY_MAXIMUM_LIFETIME
        or (not_before is not None and not_before >= expires_at)
    ):
        return _INVALID
    application_claims = {key: value for key, value in payload.items() if key not in _RESERVED_CAPABILITY_CLAIMS}
    return VerifiedCapability(
        purpose=claim_purpose,
        subject=claim_subject,
        audience=claim_audience,
        issued_at=issued_at,
        expires_at=expires_at,
        token_id=claim_token_id,
        claims=application_claims,
    )


def _numeric_date(value: JSONValue | None) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _copy_json(value: object, *, depth: int = 1) -> JSONValue:
    if depth > _MAXIMUM_APPLICATION_CLAIM_DEPTH:
        raise_value("Capability application claims must be bounded JSON values")
    if value is None or value.__class__ in (bool, int, str):
        return value  # pyright: ignore[reportReturnType] - exact runtime classes are narrowed above
    if value.__class__ is float:
        if not isfinite(value):  # pyright: ignore[reportArgumentType] - exact float class is required above
            raise_value("Capability application claims must be finite JSON values")
        return value  # pyright: ignore[reportReturnType] - exact float class is required above
    if value.__class__ is list:
        return [_copy_json(item, depth=depth + 1) for item in cast("list[object]", value)]
    if value.__class__ is dict:
        copied: dict[str, JSONValue] = {}
        for key, item in cast("dict[object, object]", value).items():
            if key.__class__ is not str:
                raise_value("Capability application claims must use JSON object keys")
            copied[key] = _copy_json(item, depth=depth + 1)  # pyright: ignore[reportArgumentType] - exact str key
        return copied
    return raise_value("Capability application claims must be JSON values")
