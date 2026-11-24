"""Shared JWKS-backed JWT verification over DynamicVerifierCache."""

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import cast

from litestar_security.authentication import AuthenticationOutcome, InvalidCredentials, VerificationUnavailable
from litestar_security.config import WorkerLimits
from litestar_security.providers._internal import DynamicVerifierCache, raise_config
from litestar_security.providers.jwks._internal import strict_value
from litestar_security.providers.jwks._provider import JWKSProvider
from litestar_security.providers.jwt import (
    JWTClaims,
    JWTValidationConfig,
    PyJWTVerifier,
    VerificationKey,
    parse_unverified_jwt_route,
)

__all__ = ("JWKSJWTVerifier",)

_INVALID = InvalidCredentials()


@dataclass(frozen=True, slots=True)
class JWKSJWTVerifier:
    """Verify signed JWTs against a remote JWKS provider.

    Routes each token to its pinned key by ``kid`` and ``alg``, caches prepared
    verifiers per ``(kid, alg)`` and key material, and runs cryptographic
    verification inside bounded worker limits.
    """

    config: JWTValidationConfig
    jwks: JWKSProvider
    jwks_uri: str
    mechanism_name: str = "jwt"
    slot_name: str = "jwks"
    worker_limits: WorkerLimits = field(default_factory=WorkerLimits, repr=False, compare=False)
    maximum_token_bytes: int = 16_384
    _verifiers: DynamicVerifierCache[PyJWTVerifier] = field(
        default_factory=DynamicVerifierCache[PyJWTVerifier], init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        """Validate verification configuration, JWKS provider, and worker bounds."""
        if not isinstance(cast("object", self.config), JWTValidationConfig):
            raise_config("JWKS JWT verifier config must be a JWTValidationConfig")
        if not isinstance(cast("object", self.jwks), JWKSProvider):
            raise_config("JWKS JWT verifier jwks must implement JWKSProvider")
        strict_value(self.jwks_uri, "JWKS URI")
        strict_value(self.mechanism_name, "mechanism name")
        strict_value(self.slot_name, "slot name")
        if not isinstance(cast("object", self.worker_limits), WorkerLimits):
            raise_config("JWKS JWT verifier worker limits must be WorkerLimits")
        maximum_bytes = cast("object", self.maximum_token_bytes)
        if not isinstance(maximum_bytes, int) or isinstance(maximum_bytes, bool) or maximum_bytes <= 0:
            raise_config("JWKS JWT verifier maximum_token_bytes must be a positive integer")

    async def verify(self, token: str, *, now: datetime) -> AuthenticationOutcome[JWTClaims]:
        """Verify ``token`` against ``self.jwks`` using ``self.config``.

        Args:
            token: Compact JWS token to verify.
            now: Timezone-aware verification timestamp.

        Returns:
            ``Authenticated[JWTClaims]``, ``InvalidCredentials``, or
            ``VerificationUnavailable``.
        """
        return await verify_jwks_jwt(
            token,
            config=self.config,
            jwks=self.jwks,
            jwks_uri=self.jwks_uri,
            verifiers=self._verifiers,
            mechanism_name=self.mechanism_name,
            slot_name=self.slot_name,
            worker_limits=self.worker_limits,
            now=now,
            maximum_token_bytes=self.maximum_token_bytes,
        )


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
