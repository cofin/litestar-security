"""Shared JWKS-backed JWT verification over DynamicVerifierCache."""

from dataclasses import replace
from datetime import datetime, timezone
from typing import cast

from litestar_security.authentication import AuthenticationOutcome, InvalidCredentials, VerificationUnavailable
from litestar_security.config import WorkerLimits
from litestar_security.providers._internal import DynamicVerifierCache
from litestar_security.providers.jwks._provider import JWKSProvider
from litestar_security.providers.jwt import (
    JWTClaims,
    JWTValidationConfig,
    PyJWTVerifier,
    VerificationKey,
    parse_unverified_jwt_route,
)

__all__ = ()

_INVALID = InvalidCredentials()


async def verify_jwks_jwt(  # noqa: PLR0913 - verification seam keeps issuer, JWKS, cache, and limits explicit
    token: str,
    *,
    config: JWTValidationConfig,
    jwks: JWKSProvider,
    jwks_uri: str,
    verifiers: DynamicVerifierCache[PyJWTVerifier],
    mechanism_name: str,
    slot_name: str,
    worker_limits: WorkerLimits,
    now: datetime,
    maximum_token_bytes: int = 16_384,
) -> AuthenticationOutcome[JWTClaims]:
    """Route an unverified JWT to its pinned JWKS key and verify signature and claims."""
    if now.tzinfo is None or now.utcoffset() is None:
        return _INVALID
    normalized_now = now.astimezone(timezone.utc)
    route = parse_unverified_jwt_route(token, maximum_token_bytes=maximum_token_bytes)
    if isinstance(route, InvalidCredentials):
        return route
    algorithm = route.header.get("alg")
    key_id = route.header.get("kid")
    if (
        not isinstance(algorithm, str)
        or algorithm not in config.algorithms
        or not isinstance(key_id, str)
        or not key_id
    ):
        return _INVALID
    selection = cast("object", await jwks.select_key(config.issuer, jwks_uri, key_id, algorithm, now=normalized_now))
    if isinstance(selection, (InvalidCredentials, VerificationUnavailable)):
        return selection
    if not isinstance(selection, VerificationKey):
        return VerificationUnavailable()
    verifier = verifiers.get_or_create(
        (key_id, algorithm),
        selection.key,
        lambda: PyJWTVerifier(
            config=replace(config, algorithms=frozenset({algorithm})),
            key=selection.key,
            mechanism_name=mechanism_name,
            slot_name=slot_name,
            maximum_token_bytes=maximum_token_bytes,
            limiter=worker_limits.crypto_limiter,
            worker_timeout=worker_limits.timeout,
        ),
    )
    return await verifier.verify(token, now=normalized_now)
