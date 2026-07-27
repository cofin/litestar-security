"""Verifier protocols, the PyJWT-backed verifier, and unverified route parsing.

Route parsing deliberately reads an unverified token and returns only the issuer
and key hints needed to select trust material. It is kept beside the verifier so
the boundary between hint and verified claim stays visible in one file.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import partial
from inspect import iscoroutinefunction
from math import isfinite
from types import MappingProxyType
from typing import Generic, Protocol, TypeAlias, TypeVar, cast, runtime_checkable

import jwt
from anyio import CapacityLimiter
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jwt import PyJWK
from jwt.exceptions import PyJWTError

from litestar_security.authentication import (
    Authenticated,
    AuthenticationOutcome,
    InvalidCredentials,
    VerificationUnavailable,
)
from litestar_security.config import NoOpSecurityMetrics, SecurityMetrics, WorkerLimits
from litestar_security.context import AuthenticationEvidence
from litestar_security.providers._internal import JSONValue, raise_config
from litestar_security.providers.jwt._claims import (
    JWTAlgorithm,
    JWTClaims,
    JWTValidationConfig,
    normalize_claims,
    validate_header,
)
from litestar_security.providers.jwt._internal import (
    decode_base64url,
    decode_json_segment,
    freeze_json,
    strict_identifier,
)
from litestar_security.providers.jwt._keys import prepare_key
from litestar_security.providers.jwt._workers import metric_sink, run_worker, validate_limiter

__all__ = ("JWTVerifier", "SyncJWTVerifier", "normalize_verifier")


VerificationKeyInput: TypeAlias = bytes | str | PyJWK | Mapping[str, JSONValue]


PreparedVerificationKey: TypeAlias = (
    bytes | str | PyJWK | rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey
)


ClaimsT = TypeVar("ClaimsT")


_COMPACT_SEGMENT_COUNT = 3


_INVALID = InvalidCredentials()


@runtime_checkable
class JWTVerifier(Protocol, Generic[ClaimsT]):
    """Verify one compact JWT against a configured trust domain."""

    @property
    def config(self) -> JWTValidationConfig:
        """Return the verifier's pinned trust profile."""
        ...  # pragma: no cover

    async def verify(self, token: str, *, now: datetime) -> AuthenticationOutcome[ClaimsT]:
        """Return a structured authentication outcome.

        Args:
            token: The compact JWT to verify.
            now: The verification timestamp, used for expiry and not-before checks.

        Returns:
            The verified claims, or a sanitized outcome. A rejected signature and
            a rejected claim are not distinguished.
        """
        ...  # pragma: no cover


@runtime_checkable
class SyncJWTVerifier(Protocol, Generic[ClaimsT]):
    """Blocking custom verifier normalized once into the crypto worker."""

    @property
    def config(self) -> JWTValidationConfig:
        """Return the verifier's pinned trust profile."""
        ...  # pragma: no cover

    def verify(self, token: str, *, now: datetime) -> AuthenticationOutcome[ClaimsT]:
        """Return a structured authentication outcome.

        Args:
            token: The compact JWT to verify.
            now: The verification timestamp, used for expiry and not-before checks.

        Returns:
            The verified claims, or a sanitized outcome. A rejected signature and
            a rejected claim are not distinguished.
        """
        ...  # pragma: no cover


def normalize_verifier(
    verifier: JWTVerifier[ClaimsT] | SyncJWTVerifier[ClaimsT],
    *,
    worker_limits: WorkerLimits | None = None,
    metrics: SecurityMetrics | None = None,
) -> JWTVerifier[ClaimsT]:
    """Normalize one custom verifier once without blocking the event loop.

    Args:
        verifier: The application's verifier, blocking or async.
        worker_limits: The shared crypto-worker budget a blocking verifier runs inside.
        metrics: The sink offered verification measurements.

    Returns:
        An async verifier.
    """
    verify_method = getattr(verifier, "verify", None)
    config = getattr(verifier, "config", None)
    if not callable(verify_method) or not isinstance(config, JWTValidationConfig):
        raise_config("JWT verifier must define verify and JWTValidationConfig")
    workers = WorkerLimits() if worker_limits is None else worker_limits
    if not isinstance(workers, WorkerLimits):  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
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

    async def verify(self, token: str, *, now: datetime) -> AuthenticationOutcome[JWTClaims]:  # noqa: PLR0911 - preserve explicit sanitized outcomes at each security boundary
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
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
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
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()


def _verify_signature(token: str, key: PreparedVerificationKey, algorithm: str) -> None:
    jwt.decode_complete(
        token,
        key=key,  # pyright: ignore[reportArgumentType] - third-party signature is wider than its runtime contract
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
