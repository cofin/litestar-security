"""Local access-token issuing and bearer identity resolution."""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from binascii import Error as BinasciiError
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Generic, Literal, TypeVar, cast
from unicodedata import normalize

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._internal import (
    aware_utc_time,
    new_event_id,
    strict_text,
    utc_now,
    valid_security_epoch,
)
from litestar_security.accounts._records import LocalAccount
from litestar_security.accounts._stores import AccountLookup, SecurityEpochStore, SecurityEpochValidator
from litestar_security.authentication import (
    Authenticated,
    AuthenticationOutcome,
    InvalidCredentials,
    VerificationUnavailable,
)
from litestar_security.context import AuthorizationSnapshot, Principal
from litestar_security.providers.jwt import (
    JWTClaims,
    JWTValidationConfig,
    JWTVerifier,
    TokenSigner,
    build_access_token_claims,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Set as AbstractSet


__all__ = ("LocalAccessToken", "LocalAccessTokenIssuer", "LocalBearerIdentityResolver")

UserT = TypeVar("UserT")
_ASCII_CONTROL_LIMIT = 32
_DEFAULT_ACCESS_TOKEN_LIFETIME = timedelta(minutes=10)
_MINIMUM_ACCESS_TOKEN_LIFETIME = timedelta(seconds=30)
_MAXIMUM_ACCESS_TOKEN_LIFETIME = timedelta(hours=1)
_DEFAULT_LOCAL_CLIENT_ID = "local"
_MAXIMUM_ACCESS_TOKEN_BYTES = 16_384
_COMPACT_JWT_SEGMENTS = 3


@dataclass(frozen=True, slots=True)
class LocalAccessToken:
    """Secret-safe response from one local access-token issuance."""

    access_token: str = field(repr=False)
    expires_in: int
    token_type: Literal["Bearer"] = field(default="Bearer", init=False)

    def __post_init__(self) -> None:
        """Require one compact credential and a bounded whole-second lifetime."""
        token_value: object = self.access_token
        if (
            not _valid_compact_access_token(token_value)
            or self.expires_in.__class__ is not int
            or not int(_MINIMUM_ACCESS_TOKEN_LIFETIME.total_seconds())
            <= self.expires_in
            <= int(_MAXIMUM_ACCESS_TOKEN_LIFETIME.total_seconds())
        ):
            msg = "Local access token requires a compact credential and bounded expiry"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class LocalAccessTokenIssuer(Generic[UserT]):
    """Issue local access tokens by signing a minimal server-owned claim set.

    Every claim is chosen here rather than taken from the caller, so a token can only
    describe the account it was issued for.
    """

    signer: TokenSigner = field(repr=False)
    issuer: str
    audience: str
    client_id: str = _DEFAULT_LOCAL_CLIENT_ID
    lifetime: timedelta = _DEFAULT_ACCESS_TOKEN_LIFETIME
    clock: "Callable[[], datetime]" = field(default=utc_now, repr=False, compare=False)
    token_ids: "Callable[[], str]" = field(default=new_event_id, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate server-owned claims and the configured access-token lifetime."""
        signer_value: object = object.__getattribute__(self, "signer")
        clock_value: object = object.__getattribute__(self, "clock")
        token_ids_value: object = object.__getattribute__(self, "token_ids")
        if not isinstance(signer_value, TokenSigner):
            msg = "Local access-token issuer signer must implement TokenSigner"
            raise ImproperlyConfiguredException(detail=msg)
        for value, name in ((self.issuer, "issuer"), (self.audience, "audience"), (self.client_id, "client id")):
            if not _strict_claim_text(value):
                msg = f"Local access-token {name} must be non-empty normalized text"
                raise ImproperlyConfiguredException(detail=msg)
        validate_access_token_lifetime(self.lifetime)
        if not callable(clock_value) or not callable(token_ids_value):
            msg = "Local access-token clock and token id factory must be callable"
            raise ImproperlyConfiguredException(detail=msg)

    async def issue(
        self, account: LocalAccount[UserT], *, scopes: "AbstractSet[str]" = frozenset(), now: datetime | None = None
    ) -> LocalAccessToken | InvalidCredentials | VerificationUnavailable:
        """Issue one short-lived epoch-bound token without serializing application data."""
        account_value: object = account
        if (
            not isinstance(account_value, LocalAccount)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
            or not account_value.active
            or not account_value.verified
        ):
            return InvalidCredentials()
        try:
            issued_at = aware_utc_time(self.clock() if now is None else now)
            token_id = self.token_ids()
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        try:
            claims = build_access_token_claims(
                issuer=self.issuer,
                audience=self.audience,
                subject=account_value.account_id,
                client_id=self.client_id,
                security_epoch=account_value.security_epoch,
                now=issued_at,
                lifetime=self.lifetime,
                scopes=scopes,
                jti=token_id,
            )
        except (TypeError, ValueError):
            return InvalidCredentials()
        try:
            token = await self.signer.sign(claims, now=issued_at)
            return LocalAccessToken(access_token=token, expires_in=int(self.lifetime.total_seconds()))
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()


@dataclass(slots=True)
class LocalAccessVerifier:
    """Promote only application-issued local scopes into authorization grants."""

    config: JWTValidationConfig
    verifier: JWTVerifier[JWTClaims] = field(repr=False)

    async def verify(self, token: str, *, now: datetime) -> AuthenticationOutcome[JWTClaims]:
        outcome = await self.verifier.verify(token, now=now)
        if not isinstance(outcome, Authenticated):
            return outcome
        return replace(outcome, grants=AuthorizationSnapshot(scopes=outcome.claims.scopes))


@dataclass(frozen=True, slots=True)
class LocalBearerIdentityResolver(Generic[UserT]):
    """Resolve verified local JWT claims through exact account and epoch state."""

    accounts: AccountLookup[UserT] = field(repr=False)
    _epochs: SecurityEpochValidator = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Require account and authoritative security-epoch lookup capabilities."""
        accounts_value: object = object.__getattribute__(self, "accounts")
        if not isinstance(accounts_value, AccountLookup) or not isinstance(accounts_value, SecurityEpochStore):
            msg = "Local bearer resolver accounts must implement AccountLookup and SecurityEpochStore"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(self, "_epochs", SecurityEpochValidator(store=cast("SecurityEpochStore", accounts_value)))

    async def resolve(self, claims: JWTClaims) -> Principal[UserT] | InvalidCredentials | VerificationUnavailable:
        """Return a principal only for an active account at the exact current epoch."""
        epoch = claims.raw.get("se")
        if not valid_security_epoch(epoch):
            return InvalidCredentials()
        try:
            account = await self.accounts.get_by_id(claims.subject)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if (
            account is None
            or account.account_id != claims.subject
            or not account.active
            or not account.verified
            or account.security_epoch != epoch
        ):
            return InvalidCredentials()
        epoch_result = await self._epochs.validate(claims.subject, cast("int", epoch))
        if epoch_result is not None:
            return epoch_result
        return Principal(id=account.account_id, display_name=account.display_name, user=account.user)


def validate_access_token_lifetime(value: object) -> None:
    if not isinstance(value, timedelta):
        msg = "Local access-token lifetime must be a timedelta"
        raise ImproperlyConfiguredException(detail=msg)
    if value < _MINIMUM_ACCESS_TOKEN_LIFETIME:
        msg = "Local access-token lifetime must be at least 30 seconds"
        raise ImproperlyConfiguredException(detail=msg)
    if value > _MAXIMUM_ACCESS_TOKEN_LIFETIME:
        msg = "Local access-token lifetime must be at most one hour"
        raise ImproperlyConfiguredException(detail=msg)
    if value.microseconds:
        msg = "Local access-token lifetime must use whole seconds"
        raise ImproperlyConfiguredException(detail=msg)


def _strict_claim_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.__class__ is str
        and bool(value)
        and value == value.strip()
        and normalize("NFC", value) == value
        and all(not character.isspace() and ord(character) >= _ASCII_CONTROL_LIMIT for character in value)
    )


def _valid_compact_access_token(value: object) -> bool:
    if not isinstance(value, str) or value.__class__ is not str:
        return False
    segments = value.split(".")
    structurally_valid = (
        strict_text(value)
        and len(value.encode("ascii", errors="ignore")) == len(value)
        and len(value) <= _MAXIMUM_ACCESS_TOKEN_BYTES
        and len(segments) == _COMPACT_JWT_SEGMENTS
        and all(segments)
    )
    if not structurally_valid:
        return False
    try:
        return all(
            urlsafe_b64encode(urlsafe_b64decode(f"{segment}{'=' * (-len(segment) % 4)}")).rstrip(b"=").decode("ascii")
            == segment
            for segment in segments
        )
    except (BinasciiError, UnicodeEncodeError, ValueError):
        return False
