"""Sealed refresh receipts that make an interrupted rotation safe to retry.

A receipt is an AEAD-sealed copy of a rotation response handed back to the client.
Sealing and unsealing sit below the rotation service so that replay detection can
be tested against the envelope format alone.
"""

import json
from binascii import Error as BinasciiError
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from secrets import token_bytes
from types import MappingProxyType
from typing import TypeVar, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._internal import (
    DIGEST_BYTES,
    aware_utc_time,
    decode_random,
    decode_random_unbounded,
    encode_random,
    strict_context_text,
    valid_identifier,
    valid_security_epoch,
)
from litestar_security.accounts._refresh_tokens import RefreshFamilyContext, RefreshTokenResponse
from litestar_security.authentication import InvalidCredentials

__all__ = ("RefreshReceiptContext", "RefreshReceiptKey", "RefreshReceiptReplay", "RefreshReceiptSealer")


UserT = TypeVar("UserT")


_REFRESH_TOKEN_PREFIX = "rt_"  # noqa: S105 - public token namespace, not a credential


_REFRESH_FAMILY_PREFIX = "rf_"


_REFRESH_RECEIPT_VERSION = "rr1"


_RECEIPT_NONCE_BYTES = 12


_MAXIMUM_RECEIPT_BYTES = 32_768


_AES_256_KEY_BYTES = 32


@dataclass(frozen=True, slots=True)
class RefreshReceiptContext:
    """Public receipt binding values; no raw credential material is retained."""

    token_id: str
    family_id: str
    account_id: str
    security_epoch: int
    idempotency_digest: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Validate every authenticated receipt binding value."""
        if (
            not valid_identifier(self.token_id, prefix=_REFRESH_TOKEN_PREFIX)
            or not valid_identifier(self.family_id, prefix=_REFRESH_FAMILY_PREFIX)
            or not strict_context_text(self.account_id)
            or not valid_security_epoch(self.security_epoch)
            or (
                self.idempotency_digest is not None
                and (self.idempotency_digest.__class__ is not bytes or len(self.idempotency_digest) != DIGEST_BYTES)
            )
        ):
            msg = "Refresh receipt context is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RefreshReceiptKey:
    """One AES-256-GCM receipt key selected by a non-secret key ID."""

    key_id: str
    key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Require one safe lookup ID and exact AES-256 key."""
        if (
            not strict_context_text(self.key_id)
            or any(
                not (character.isascii() and (character.isalnum() or character in "_-")) for character in self.key_id
            )
            or self.key.__class__ is not bytes
            or len(self.key) != _AES_256_KEY_BYTES
        ):
            msg = "Refresh receipt key requires a safe ID and 32-byte key"
            raise ImproperlyConfiguredException(detail=msg)


@dataclass(frozen=True, slots=True)
class RefreshReceiptSealer:
    """Seal exact refresh responses with rotating AES-GCM keys and bound AAD."""

    active_key: RefreshReceiptKey = field(repr=False)
    retained_keys: tuple[RefreshReceiptKey, ...] = field(default=(), repr=False)
    entropy: Callable[[int], bytes] = field(default=token_bytes, repr=False, compare=False)
    _keys: Mapping[str, RefreshReceiptKey] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Compile active and retained receipt keys by unique ID."""
        active_key_value: object = self.active_key
        retained_values: tuple[object, ...] = tuple(self.retained_keys)
        entropy_value: object = self.entropy
        keys = (_require_receipt_key(active_key_value), *(_require_receipt_key(key) for key in retained_values))
        if len({key.key_id for key in keys}) != len(keys):
            msg = "Refresh receipt key IDs must be unique"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(entropy_value):
            msg = "Refresh receipt entropy source must be callable"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(self, "retained_keys", tuple(self.retained_keys))
        object.__setattr__(self, "_keys", MappingProxyType({key.key_id: key for key in keys}))

    def seal(self, response: RefreshTokenResponse, context: RefreshReceiptContext, *, expires_at: datetime) -> bytes:
        """Seal one exact response and authenticate all replay decision fields."""
        expiry = _receipt_expiry(expires_at)
        nonce = self.entropy(_RECEIPT_NONCE_BYTES)
        if nonce.__class__ is not bytes or len(nonce) != _RECEIPT_NONCE_BYTES:
            msg = "Refresh receipt entropy source returned an invalid nonce"
            raise RuntimeError(msg)
        plaintext = json.dumps(
            {
                "access_token": response.access_token,
                "expires_in": response.expires_in,
                "refresh_token": response.refresh_token,
                "token_type": response.token_type,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        ciphertext = AESGCM(self.active_key.key).encrypt(
            nonce, plaintext, _receipt_aad(context, expiry, self.active_key.key_id)
        )
        return ".".join((
            _REFRESH_RECEIPT_VERSION,
            self.active_key.key_id,
            str(expiry),
            encode_random(nonce),
            encode_random(ciphertext),
        )).encode("ascii")

    def unseal(  # noqa: PLR0911 - each malformed receipt boundary fails closed explicitly
        self, sealed_receipt: bytes, context: RefreshReceiptContext, *, now: datetime
    ) -> RefreshTokenResponse | InvalidCredentials:
        """Recover one response only while its bound receipt and key remain valid."""
        try:
            current = aware_utc_time(now)
        except (AttributeError, ValueError):
            return InvalidCredentials()
        parsed = _parse_receipt_envelope(sealed_receipt)
        if parsed is None:
            return InvalidCredentials()
        key_id, expiry, nonce, ciphertext = parsed
        key = self._keys.get(key_id)
        if key is None or _timestamp_microseconds(current) >= expiry:
            return InvalidCredentials()
        try:
            plaintext = AESGCM(key.key).decrypt(nonce, ciphertext, _receipt_aad(context, expiry, key_id))
            payload_value: object = json.loads(plaintext)
            if not isinstance(payload_value, dict):
                return InvalidCredentials()
            payload = cast("Mapping[str, object]", payload_value)
            if frozenset(payload) != frozenset({"access_token", "expires_in", "refresh_token", "token_type"}):
                return InvalidCredentials()
            access_token = payload.get("access_token")
            refresh_token = payload.get("refresh_token")
            expires_in = payload.get("expires_in")
            if (
                payload.get("token_type") != "Bearer"
                or access_token.__class__ is not str
                or refresh_token.__class__ is not str
                or expires_in.__class__ is not int
            ):
                return InvalidCredentials()
            return RefreshTokenResponse(
                access_token=cast("str", access_token),  # type: ignore[redundant-cast]  # mypy narrows this; pyright does not
                refresh_token=cast("str", refresh_token),  # type: ignore[redundant-cast]  # mypy narrows this; pyright does not
                expires_in=cast("int", expires_in),  # type: ignore[redundant-cast]  # mypy narrows this; pyright does not
            )
        except (InvalidTag, KeyError, TypeError, UnicodeDecodeError, ValueError):
            return InvalidCredentials()


@dataclass(frozen=True, slots=True)
class RefreshReceiptReplay:
    """Proof-checked same-key replay recoverable without speculative crypto."""

    context: RefreshFamilyContext
    sealed_receipt: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Validate bounded ciphertext and exact replay context."""
        if (
            self.context.__class__ is not RefreshFamilyContext
            or self.sealed_receipt.__class__ is not bytes
            or not self.sealed_receipt
            or len(self.sealed_receipt) > _MAXIMUM_RECEIPT_BYTES
        ):
            msg = "Refresh receipt replay is invalid"
            raise ValueError(msg)


def _require_receipt_key(value: object) -> RefreshReceiptKey:
    if not isinstance(value, RefreshReceiptKey) or value.__class__ is not RefreshReceiptKey:
        msg = "Refresh receipt keys must be RefreshReceiptKey values"
        raise ImproperlyConfiguredException(detail=msg)
    return value


def _receipt_expiry(value: datetime) -> int:
    try:
        normalized = aware_utc_time(value)
    except (AttributeError, ValueError):
        msg = "Refresh receipt expiry must be timezone-aware"
        raise ValueError(msg) from None
    expiry = _timestamp_microseconds(normalized)
    if expiry < 1:
        msg = "Refresh receipt expiry is invalid"
        raise ValueError(msg)
    return expiry


def _timestamp_microseconds(value: datetime) -> int:
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value - epoch
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def _receipt_aad(context: RefreshReceiptContext, expiry: int, key_id: str) -> bytes:
    return json.dumps(
        {
            "account_id": context.account_id,
            "expiry": expiry,
            "family_id": context.family_id,
            "idempotency": (None if context.idempotency_digest is None else context.idempotency_digest.hex()),
            "key_id": key_id,
            "security_epoch": context.security_epoch,
            "token_id": context.token_id,
            "version": _REFRESH_RECEIPT_VERSION,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _parse_receipt_envelope(value: object) -> tuple[str, int, bytes, bytes] | None:
    if value.__class__ is not bytes:
        return None
    receipt = cast("bytes", value)  # type: ignore[redundant-cast]  # mypy narrows this; pyright does not
    if not receipt or len(receipt) > _MAXIMUM_RECEIPT_BYTES:
        return None
    try:
        version, key_id, expiry_text, nonce_text, ciphertext_text = receipt.decode("ascii").split(".")
        if (
            version != _REFRESH_RECEIPT_VERSION
            or not strict_context_text(key_id)
            or any(not (character.isascii() and (character.isalnum() or character in "_-")) for character in key_id)
            or not expiry_text.isascii()
            or not expiry_text.isdecimal()
            or str(expiry := int(expiry_text)) != expiry_text
        ):
            return None
        nonce = decode_random(nonce_text, _RECEIPT_NONCE_BYTES)
        ciphertext = decode_random_unbounded(ciphertext_text)
    except (BinasciiError, UnicodeDecodeError, UnicodeEncodeError, ValueError):
        return None
    if nonce is None or not ciphertext:
        return None
    return key_id, expiry, nonce, ciphertext
