"""Local key ring, verification key sets, signing, capabilities, and JWKS route."""

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from functools import partial
from inspect import iscoroutinefunction
from math import isfinite
from secrets import token_urlsafe
from types import MappingProxyType
from typing import Any, Protocol, cast, runtime_checkable

import jwt
from anyio import CapacityLimiter
from jwt.exceptions import PyJWTError
from litestar.connection.request import Request
from litestar.datastructures import ResponseHeader
from litestar.handlers.http_handlers import HTTPRouteHandler, get
from litestar.openapi.datastructures import ResponseSpec
from litestar.response import Response
from litestar.status_codes import HTTP_200_OK, HTTP_304_NOT_MODIFIED

from litestar_security.authentication import AuthenticationOutcome, InvalidCredentials, VerificationUnavailable, public
from litestar_security.providers._internal import JSONValue, raise_config
from litestar_security.providers.jwt._tokens import (
    JWTAlgorithm,
    JWTClaims,
    JWTValidationConfig,
    JWTVerifier,
    LocalJWKSDocument,
    PreparedVerificationKey,
    PyJWTVerifier,
    SigningKey,
    VerificationKey,
    aware_utc,
    freeze_json,
    is_strict_identifier,
    metric_sink,
    parse_unverified_jwt_route,
    prepared_verification_key,
    raise_value,
    run_worker,
    strict_identifier,
    strict_identifier_value,
    validate_limiter,
    validate_local_access_claims,
)
from litestar_security.workers import NoOpSecurityMetrics, SecurityMetrics, WorkerLimits

__all__ = (
    "CAPABILITY_TOKEN_TYPE",
    "LocalJWKSConfig",
    "LocalKeyRing",
    "SigningKey",
    "SyncTokenSigner",
    "TokenSigner",
    "VerificationKey",
    "VerificationKeySet",
    "VerifiedCapability",
    "build_capability_claims",
    "build_local_jwks_handler",
    "normalize_capability_claims",
    "normalize_signer",
    "validate_capability_header",
)


_ASCII_CONTROL_LIMIT = 32
_MAXIMUM_LOCAL_JWKS_CACHE_AGE = 86_400
_PUBLIC_JWK_FIELDS = {
    "EdDSA": frozenset({"alg", "crv", "key_ops", "kid", "kty", "use", "x"}),
    "ES256": frozenset({"alg", "crv", "key_ops", "kid", "kty", "use", "x", "y"}),
    "RS256": frozenset({"alg", "e", "key_ops", "kid", "kty", "n", "use"}),
}
_INVALID = InvalidCredentials()

CAPABILITY_TOKEN_TYPE = "capability+jwt"
_CAPABILITY_CLOCK_SKEW = timedelta(seconds=30)
_CAPABILITY_MAXIMUM_LIFETIME = timedelta(hours=24)
_MAXIMUM_APPLICATION_CLAIM_DEPTH = 32
_RESERVED_CAPABILITY_CLAIMS = frozenset({"iss", "sub", "aud", "exp", "iat", "nbf", "purpose", "jti"})
_REQUIRED_CAPABILITY_CLAIMS = _RESERVED_CAPABILITY_CLAIMS.difference({"nbf"})
_FORBIDDEN_JOSE_HEADERS = frozenset({"b64", "crit", "jku", "jwk", "x5c", "x5t", "x5t#S256", "x5u"})
_SUPPORTED_CAPABILITY_ALGORITHMS = frozenset({"EdDSA", "ES256", "RS256", "HS256"})


@runtime_checkable
class TokenSigner(Protocol):
    """Sign caller-built local claims without owning application persistence.

    Implementations emit access JWTs whose protected header has a non-empty
    kid, a supported non-none alg, and typ='at+jwt'. Untrusted
    caller claims must not choose those headers.
    """

    async def sign(self, claims: Mapping[str, JSONValue], *, now: datetime) -> str:
        """Return one compact signed access token.

        Args:
            claims: The claim set to sign.
            now: The signing timestamp.

        Returns:
            A compact access JWT with the required protected-header profile.

        Raises:
            Exception: When signing cannot produce that access JWT.
        """
        ...


@runtime_checkable
class SyncTokenSigner(Protocol):
    """Blocking custom access-JWT signer normalized once into the crypto worker.

    Implementations emit access JWTs whose protected header has a non-empty
    kid, a supported non-none alg, and typ='at+jwt'. Untrusted
    caller claims must not choose those headers.
    """

    def sign(self, claims: Mapping[str, JSONValue], *, now: datetime) -> str:
        """Return one compact signed access token.

        Args:
            claims: The claim set to sign.
            now: The signing timestamp.

        Returns:
            A compact access JWT with the required protected-header profile.

        Raises:
            Exception: When signing cannot produce that access JWT.
        """
        ...


def normalize_signer(
    signer: TokenSigner | SyncTokenSigner,
    *,
    worker_limits: WorkerLimits | None = None,
    metrics: SecurityMetrics | None = None,
) -> TokenSigner:
    """Normalize one custom signer once without blocking the event loop.

    Args:
        signer: The application's signer, blocking or async.
        worker_limits: The shared crypto-worker budget a blocking signer runs inside.
        metrics: The sink offered signing measurements.

    Returns:
        An async signer.
    """
    sign_method = getattr(signer, "sign", None)
    if not callable(sign_method):
        raise_config("Token signer must define sign")
    workers = WorkerLimits() if worker_limits is None else worker_limits
    check_workers = cast("object", workers)
    if not isinstance(check_workers, WorkerLimits):
        raise_config("Token signer worker limits must be WorkerLimits")
    sink = metric_sink(metrics)
    if iscoroutinefunction(sign_method):
        return cast("TokenSigner", signer)
    return _WorkerTokenSigner(sign_sync=cast("Callable[..., str]", sign_method), workers=workers, metrics=sink)


@dataclass(frozen=True, slots=True)
class _WorkerTokenSigner:
    sign_sync: Callable[..., str] = field(repr=False)
    workers: WorkerLimits = field(repr=False)
    metrics: SecurityMetrics = field(repr=False)

    async def sign(self, claims: Mapping[str, JSONValue], *, now: datetime) -> str:
        try:
            return await run_worker(
                partial(self.sign_sync, claims, now=now),
                limiter=self.workers.crypto_limiter,
                worker_timeout=self.workers.timeout,
                metrics=self.metrics,
                operation_metric="security.jwt.sign_duration",
            )
        except Exception:
            message = "Token signing unavailable"
            raise RuntimeError(message) from None


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


def validate_capability_header(header: Mapping[str, JSONValue]) -> tuple[JWTAlgorithm, str] | InvalidCredentials:
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


def build_capability_claims(
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


def normalize_capability_claims(
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
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise_value("Capability application claims must be finite JSON values")
        return value
    if isinstance(value, list):
        return [_copy_json(item, depth=depth + 1) for item in cast("list[object]", value)]
    if isinstance(value, dict):
        copied: dict[str, JSONValue] = {}
        for key, item in cast("dict[object, object]", value).items():
            if not isinstance(key, str):
                raise_value("Capability application claims must use JSON object keys")
            copied[key] = _copy_json(item, depth=depth + 1)
        return copied
    return raise_value("Capability application claims must be JSON values")


@dataclass(frozen=True, slots=True)
class VerificationKeySet:
    """One issuer's immutable verification-only keys for local or custom signers."""

    issuer: str
    keys: tuple[VerificationKey, ...]

    def __post_init__(self) -> None:
        """Normalize the issuer and reject empty or ambiguous key selection."""
        issuer = strict_identifier(self.issuer)
        keys = tuple(self.keys)
        if not keys:
            raise_config("Verification key set must contain at least one key")
        key_ids = tuple(key.key_id for key in keys)
        if len(frozenset(key_ids)) != len(key_ids):
            raise_config("Duplicate local key id")
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "keys", keys)

    def build_verifier(
        self,
        config: JWTValidationConfig,
        *,
        mechanism_name: str = "jwt",
        slot_name: str = "authorization.bearer",
        worker_limits: WorkerLimits | None = None,
        metrics: SecurityMetrics | None = None,
    ) -> "JWTVerifier[JWTClaims]":
        """Build one exact-kid verifier across this trusted key set.

        Args:
            config: The pinned trust profile. Its issuer must match this key set.
            mechanism_name: The mechanism the verifier belongs to.
            slot_name: The credential slot the verifier reads.
            worker_limits: The shared crypto-worker budget verification runs inside.
            metrics: The sink offered verification measurements.

        Returns:
            A verifier that selects keys by exact key identifier, never by a
            claim read from the unverified token.
        """
        if config.issuer != self.issuer:
            raise_config("Verification key set issuer must match JWT validation config issuer")
        mechanism_name = strict_identifier(mechanism_name)
        slot_name = strict_identifier(slot_name)
        workers = WorkerLimits() if worker_limits is None else worker_limits
        check_workers = cast("object", workers)
        if not isinstance(check_workers, WorkerLimits):
            raise_config("JWT verifier worker limits must be WorkerLimits")
        sink = metric_sink(metrics)
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
                limiter=workers.crypto_limiter,
                worker_timeout=workers.timeout,
                metrics=sink,
            )
        if not verifiers:
            raise_config("Verification key set has no key accepted by JWT validation config")
        return _LocalKeyRingVerifier(config=config, verifiers=MappingProxyType(verifiers))


@dataclass(frozen=True, slots=True)
class LocalKeyRing:
    """Immutable active and retained local key configuration."""

    issuer: str
    active_signing_key: SigningKey
    verification_keys: tuple[VerificationKey, ...] = ()
    worker_limits: WorkerLimits = field(default_factory=WorkerLimits, repr=False, compare=False)
    metrics: SecurityMetrics = field(default_factory=NoOpSecurityMetrics, repr=False, compare=False)
    _verification_key_set: VerificationKeySet = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Normalize the issuer and reject ambiguous rotation state."""
        issuer = strict_identifier(self.issuer)
        verification_keys = tuple(self.verification_keys)
        check_workers = cast("object", self.worker_limits)
        if not isinstance(check_workers, WorkerLimits):
            raise_config("Local key ring worker limits must be WorkerLimits")
        metrics = metric_sink(self.metrics)
        key_set = VerificationKeySet(
            issuer=issuer, keys=(self.active_signing_key.as_verification_key(), *verification_keys)
        )
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "verification_keys", verification_keys)
        object.__setattr__(self, "metrics", metrics)
        object.__setattr__(self, "_verification_key_set", key_set)

    @property
    def all_verification_keys(self) -> tuple[VerificationKey, ...]:
        """Return the active key followed by retained verification-only keys."""
        return self._verification_key_set.keys

    @property
    def verification_key_set(self) -> VerificationKeySet:
        """Return the public verification-only view used by local or custom signers."""
        return self._verification_key_set

    def build_signer(self) -> TokenSigner:
        """Build the local signer without generating or discovering key material.

        Returns:
            A signer bound to the configured active signing key.
        """
        return _LocalJWTSigner(
            issuer=self.issuer,
            signing_key=self.active_signing_key,
            limiter=self.worker_limits.crypto_limiter,
            worker_timeout=self.worker_limits.timeout,
            metrics=self.metrics,
        )

    def build_verifier(
        self, config: JWTValidationConfig, *, mechanism_name: str = "jwt", slot_name: str = "authorization.bearer"
    ) -> "JWTVerifier[JWTClaims]":
        """Build one exact-kid verifier across the active and retained keys.

        Retained keys stay accepted so tokens signed before a rotation keep
        verifying until they expire.

        Args:
            config: The pinned trust profile. Its issuer must match this key ring.
            mechanism_name: The mechanism the verifier belongs to.
            slot_name: The credential slot the verifier reads.

        Returns:
            A verifier that selects keys by exact key identifier.
        """
        if self.active_signing_key.algorithm not in config.algorithms:
            raise_config("Local key ring active signing algorithm must be accepted by JWT validation config")
        return self._verification_key_set.build_verifier(
            config,
            mechanism_name=mechanism_name,
            slot_name=slot_name,
            worker_limits=self.worker_limits,
            metrics=self.metrics,
        )

    async def mint_capability(
        self,
        *,
        purpose: str,
        subject: str,
        audience: str,
        lifetime: timedelta,
        claims: Mapping[str, JSONValue] | None = None,
    ) -> str:
        """Mint one bounded, single-purpose capability JWT.

        Args:
            purpose: The application-defined capability purpose.
            subject: The principal this capability represents.
            audience: The exact service or resource that may accept it.
            lifetime: The positive capability lifetime, no longer than 24 hours.
            claims: Optional JSON application claims, excluding reserved names.

        Returns:
            A compact capability JWT with a hard-pinned capability+jwt type.

        Raises:
            ValueError: If a capability input or lifetime is invalid.
            RuntimeError: If capability signing is unavailable.
        """
        now = datetime.now(timezone.utc)
        payload = build_capability_claims(
            issuer=self.issuer,
            purpose=purpose,
            subject=subject,
            audience=audience,
            lifetime=lifetime,
            claims={} if claims is None else claims,
            now=now,
        )
        sign = partial(
            jwt.encode,
            dict(payload),
            cast("Any", self.active_signing_key)._prepared_key,
            algorithm=self.active_signing_key.algorithm,
            headers={"kid": self.active_signing_key.key_id, "typ": CAPABILITY_TOKEN_TYPE},
        )
        try:
            return await run_worker(
                sign,
                limiter=self.worker_limits.crypto_limiter,
                worker_timeout=self.worker_limits.timeout,
                metrics=self.metrics,
                operation_metric="security.jwt.sign_duration",
            )
        except Exception:
            message = "Capability minting unavailable"
            raise RuntimeError(message) from None

    async def verify_capability(
        self, raw: str, *, purpose: str, audience: str, now: datetime
    ) -> VerifiedCapability | InvalidCredentials | VerificationUnavailable:
        """Verify one capability JWT against this key ring.

        Args:
            raw: The untrusted compact JWT.
            purpose: The exact application-defined capability purpose to accept.
            audience: The exact service or resource that may accept the capability.
            now: The timezone-aware verification timestamp.

        Returns:
            The verified capability, a sanitized invalid-credential outcome, or
            an unavailable-verification outcome for unexpected worker failures.

        Raises:
            Never for untrusted credential input; failures are returned as
            sanitized invalid-credential or unavailable-verification outcomes.
        """
        if now.tzinfo is None or now.utcoffset() is None:
            return _INVALID
        now = now.astimezone(timezone.utc)
        route = parse_unverified_jwt_route(raw)
        if isinstance(route, InvalidCredentials):
            return route
        header_result = validate_capability_header(route.header)
        if isinstance(header_result, InvalidCredentials):
            return header_result
        algorithm, key_id = header_result
        key = next(
            (
                candidate
                for candidate in self.all_verification_keys
                if candidate.key_id == key_id and candidate.algorithm == algorithm
            ),
            None,
        )
        if key is None:
            return _INVALID
        verify = partial(_verify_capability_signature, raw, prepared_verification_key(key), algorithm)
        try:
            await run_worker(
                verify,
                limiter=self.worker_limits.crypto_limiter,
                worker_timeout=self.worker_limits.timeout,
                metrics=self.metrics,
                operation_metric="security.jwt.verify_duration",
            )
        except (PyJWTError, TypeError, ValueError):
            return _INVALID
        except Exception:
            return VerificationUnavailable()
        return normalize_capability_claims(
            route.payload, purpose=purpose, audience=audience, issuer=self.issuer, now=now
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
            raise_config("local JWKS route_prefix must be a non-root absolute path")
        if isinstance(self.cache_max_age, bool) or not 0 <= self.cache_max_age <= _MAXIMUM_LOCAL_JWKS_CACHE_AGE:
            raise_config(f"local JWKS cache_max_age must be between 0 and {_MAXIMUM_LOCAL_JWKS_CACHE_AGE}")

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
            raise_config("local JWKS publication requires at least one asymmetric verification key")
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
    """Build one native public Litestar handler for immutable local JWKS bytes.

    Args:
        config: The publication settings and precomputed canonical response.

    Returns:
        A public handler serving the key set with a stable ETag and cache headers.
    """
    headers = {"Cache-Control": config.cache_control, "ETag": config.etag}

    @get(
        config.path,
        name="litestar_security_local_jwks",
        operation_id="LitestarSecurityLocalJWKS",
        media_type="application/jwk-set+json",
        auth=public(),
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
    async def local_jwks(request: Request[Any, Any, Any]) -> Response[LocalJWKSDocument]:
        if _if_none_match(request.headers.get("if-none-match"), config.etag):
            return Response(cast("LocalJWKSDocument", b""), headers=headers, status_code=HTTP_304_NOT_MODIFIED)
        return Response(
            cast("LocalJWKSDocument", config.canonical_bytes),
            headers=headers,
            media_type="application/jwk-set+json",
            status_code=HTTP_200_OK,
        )

    return local_jwks


@dataclass(slots=True)
class _LocalKeyRingVerifier:
    config: JWTValidationConfig
    verifiers: Mapping[tuple[str, str], PyJWTVerifier] = field(repr=False)

    async def verify(self, token: str, *, now: datetime) -> AuthenticationOutcome[JWTClaims]:
        """Select only a configured local (kid, alg) tuple and verify once."""
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
class _LocalJWTSigner:
    issuer: str
    signing_key: SigningKey = field(repr=False)
    limiter: CapacityLimiter | None = field(default=None, repr=False, compare=False)
    worker_timeout: float = field(default=10.0, repr=False, compare=False)
    metrics: SecurityMetrics = field(default_factory=NoOpSecurityMetrics, repr=False, compare=False)

    def __post_init__(self) -> None:
        limiter = WorkerLimits().crypto_limiter if self.limiter is None else validate_limiter(self.limiter)
        if (
            self.worker_timeout.__class__ not in {int, float}
            or not isfinite(self.worker_timeout)
            or self.worker_timeout <= 0
        ):
            raise_config("JWT worker timeout must be finite and positive")
        object.__setattr__(self, "limiter", limiter)
        object.__setattr__(self, "worker_timeout", float(self.worker_timeout))
        object.__setattr__(self, "metrics", metric_sink(self.metrics))

    async def sign(self, claims: Mapping[str, JSONValue], *, now: datetime) -> str:
        """Validate and sign one minimal local access token in a worker."""
        normalized_now = aware_utc(now)
        payload = validate_local_access_claims(claims, issuer=self.issuer, now=normalized_now)
        sign = partial(
            jwt.encode,
            payload,
            cast("Any", self.signing_key)._prepared_key,
            algorithm=self.signing_key.algorithm,
            headers={"kid": self.signing_key.key_id, "typ": "at+jwt"},
        )
        try:
            token = await run_worker(
                sign,
                limiter=cast("CapacityLimiter", self.limiter),
                worker_timeout=self.worker_timeout,
                metrics=self.metrics,
                operation_metric="security.jwt.sign_duration",
            )
        except Exception:
            message = "Token signing unavailable"
            raise RuntimeError(message) from None
        return token


def _if_none_match(value: str | None, etag: str) -> bool:
    if value is None:
        return False
    return any(
        candidate == "*" or candidate.removeprefix("W/") == etag for candidate in map(str.strip, value.split(","))
    )


def _verify_capability_signature(token: str, key: PreparedVerificationKey, algorithm: str) -> None:
    """Verify only one selected capability JWT signature."""
    jwt.decode_complete(
        token,
        key=cast("Any", key),
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
