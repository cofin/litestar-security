"""Local access-token issuing and bearer identity resolution.

This module is a backward-compatible shim re-exporting access token symbols
from litestar_security.accounts.tokens.
"""

from litestar_security.accounts import tokens as _tokens
from litestar_security.accounts.tokens import (
    LocalAccessToken,
    LocalAccessTokenIssuer,
    LocalAccessVerifier,
    LocalBearerIdentityResolver,
    validate_access_token_lifetime,
)

__all__ = (
    "LocalAccessToken",
    "LocalAccessTokenIssuer",
    "LocalAccessVerifier",
    "LocalBearerIdentityResolver",
    "validate_access_token_lifetime",
)


def __getattr__(name: str) -> object:
    return getattr(_tokens, name)
