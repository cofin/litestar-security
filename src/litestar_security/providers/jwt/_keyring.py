"""Local key ring, verification key sets, and the JWKS publication route.

This is where key material, signers, and verifiers are composed. It sits above all
three so that keys, protocols, and primitives stay independently testable.
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime
from functools import partial
from math import isfinite
from types import MappingProxyType
from typing import Any, cast

import jwt
from anyio import CapacityLimiter
from litestar.connection.request import Request
from litestar.datastructures import ResponseHeader
from litestar.handlers.http_handlers import HTTPRouteHandler, get
from litestar.openapi.datastructures import ResponseSpec
from litestar.response import Response
from litestar.status_codes import HTTP_200_OK, HTTP_304_NOT_MODIFIED

from litestar_security.authentication import AuthenticationOutcome, InvalidCredentials, public, security
from litestar_security.config import NoOpSecurityMetrics, SecurityMetrics, WorkerLimits
from litestar_security.providers._internal import JSONValue, raise_config
from litestar_security.providers.jwt._claims import JWTClaims, JWTValidationConfig, validate_local_access_claims
from litestar_security.providers.jwt._internal import aware_utc, strict_identifier
from litestar_security.providers.jwt._keys import LocalJWKSDocument, SigningKey, VerificationKey
from litestar_security.providers.jwt._signing import TokenSigner
from litestar_security.providers.jwt._verification import JWTVerifier, PyJWTVerifier, parse_unverified_jwt_route
from litestar_security.providers.jwt._workers import metric_sink, run_worker, validate_limiter

__all__ = ("LocalJWKSConfig", "LocalKeyRing", "VerificationKeySet", "build_local_jwks_handler")


_ASCII_CONTROL_LIMIT = 32


_MAXIMUM_LOCAL_JWKS_CACHE_AGE = 86_400


_PUBLIC_JWK_FIELDS = {
    "EdDSA": frozenset({"alg", "crv", "key_ops", "kid", "kty", "use", "x"}),
    "ES256": frozenset({"alg", "crv", "key_ops", "kid", "kty", "use", "x", "y"}),
    "RS256": frozenset({"alg", "e", "key_ops", "kid", "kty", "n", "use"}),
}


_INVALID = InvalidCredentials()


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
        """Build one exact-kid verifier across this trusted key set."""
        if config.issuer != self.issuer:
            raise_config("Verification key set issuer must match JWT validation config issuer")
        mechanism_name = strict_identifier(mechanism_name)
        slot_name = strict_identifier(slot_name)
        workers = WorkerLimits() if worker_limits is None else worker_limits
        if not isinstance(workers, WorkerLimits):  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
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
        if not isinstance(self.worker_limits, WorkerLimits):  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
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
        """Build the local signer without generating or discovering key material."""
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
        """Build one exact-kid verifier across the active and retained keys."""
        if self.active_signing_key.algorithm not in config.algorithms:
            raise_config("Local key ring active signing algorithm must be accepted by JWT validation config")
        return self._verification_key_set.build_verifier(
            config,
            mechanism_name=mechanism_name,
            slot_name=slot_name,
            worker_limits=self.worker_limits,
            metrics=self.metrics,
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
            cast("Any", self.signing_key)._prepared_key,  # noqa: SLF001 - read the prepared key material PyJWT exposes only privately
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
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            message = "Token signing unavailable"
            raise RuntimeError(message) from None
        return token


def _if_none_match(value: str | None, etag: str) -> bool:
    if value is None:
        return False
    return any(
        candidate == "*" or candidate.removeprefix("W/") == etag for candidate in map(str.strip, value.split(","))
    )
