"""Verified OIDC back-channel logout-token consumption."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException

from litestar_security.authentication import Authenticated
from litestar_security.providers.jwt import JWTClaims, JWTVerifier
from litestar_security.providers.oauth import OIDCLogoutIdentity

__all__ = ("OIDCJWTLogoutTokenConsumer",)

_BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"
_LOGOUT_TOKEN_TYPES = frozenset({"logout+jwt"})


@dataclass(frozen=True, slots=True)
class OIDCJWTLogoutTokenConsumer:
    """Verify logout-token JWTs for atomic application-side consumption."""

    verifiers: Mapping[str, JWTVerifier[JWTClaims]]

    def __post_init__(self) -> None:
        """Require fixed logout-token verifier profiles."""
        if not self.verifiers or any(
            not provider.strip()
            or not isinstance(cast("object", verifier), JWTVerifier)
            or verifier.config.subject_required
            or verifier.config.token_types != _LOGOUT_TOKEN_TYPES
            for provider, verifier in self.verifiers.items()
        ):
            message = "OIDC logout token consumer configuration is invalid"
            raise ImproperlyConfiguredException(detail=message)

    async def consume(self, provider: str, logout_token: str, *, now: datetime) -> OIDCLogoutIdentity:
        """Verify signature and logout claims, then atomically consume jti."""
        verifier = self.verifiers.get(provider)
        if verifier is None or not logout_token.strip():
            raise NotAuthorizedException(detail="OIDC logout token is invalid")
        outcome = await verifier.verify(logout_token, now=now)
        if not isinstance(outcome, Authenticated):
            raise NotAuthorizedException(detail="OIDC logout token is invalid")
        claims = outcome.claims
        events = claims.raw.get("events")
        session_id = claims.raw.get("sid")
        if (
            claims.token_id is None
            or "nonce" in claims.raw
            or not isinstance(events, Mapping)
            or set(events) != {_BACKCHANNEL_EVENT}
            or not isinstance(events[_BACKCHANNEL_EVENT], Mapping)
            or bool(events[_BACKCHANNEL_EVENT])
            or (session_id is not None and (not isinstance(session_id, str) or not session_id.strip()))
            or (claims.subject is None and session_id is None)
        ):
            raise NotAuthorizedException(detail="OIDC logout token is invalid")
        return OIDCLogoutIdentity(
            provider=provider,
            issuer=claims.issuer,
            subject=claims.subject,
            session_id=session_id,
            token_id=claims.token_id,
            expires_at=claims.expires_at,
        )
