"""Unit contracts for composite bearer extraction and configuration."""

import base64
import json
from collections.abc import Callable
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, cast

import pytest
from litestar.exceptions import ImproperlyConfiguredException
from litestar.openapi.spec import SecurityScheme

from litestar_security.authentication import (
    AuthenticationRegistry,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
)
from litestar_security.providers.jwt import BearerSlotSelector, BearerTokenSlot, CompositeBearerConfig
from tests.fixtures.collaborators import ProviderPrincipalResolver as _Resolver
from tests.fixtures.collaborators import build_recording_jwt_verifier as _recording_jwt_verifier

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)

_JWT_ISSUER = "https://issuer.example"

_JWT_AUDIENCE = "litestar-security"


def _jwt_segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _compact_jwt(header: bytes, payload: bytes, signature: bytes = b"signature") -> str:
    return ".".join((_jwt_segment(header), _jwt_segment(payload), _jwt_segment(signature)))


def _routing_token(*, issuer: str, audiences: str | list[str]) -> str:
    return _compact_jwt(
        json.dumps({"alg": "RS256", "kid": "shared", "typ": "at+jwt"}, separators=(",", ":")).encode(),
        json.dumps({"iss": issuer, "aud": audiences}, separators=(",", ":")).encode(),
    )


@pytest.mark.parametrize(
    ("headers", "expected_type", "expected_value"),
    [
        ([], NoCredentials, None),
        ([(b"authorization", b"Bearer compact.jwt.value")], PresentedCredential, "compact.jwt.value"),
        ([(b"authorization", b"bEaReR compact.jwt.value")], PresentedCredential, "compact.jwt.value"),
        (
            [(b"authorization", b"Bearer one.two.three"), (b"Authorization", b"Bearer four.five.six")],
            InvalidCredentials,
            None,
        ),
        ([(b"authorization", b"")], InvalidCredentials, None),
        ([(b"authorization", b"Basic credential")], InvalidCredentials, None),
        ([(b"authorization", b" Bearer one.two.three")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer  one.two.three")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer\tone.two.three")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer one.two.three\x7f")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer \xff")], InvalidCredentials, None),
    ],
)
def test_composite_bearer_extracts_the_authorization_namespace_once(
    headers: list[tuple[bytes, bytes]],
    expected_type: type[NoCredentials] | type[PresentedCredential[object]] | type[InvalidCredentials],
    expected_value: str | None,
) -> None:
    physical_slot, _ = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
    ).build(_Resolver())

    extraction = physical_slot.extract(SimpleNamespace(scope={"headers": headers}))  # type: ignore[arg-type]

    assert isinstance(extraction, expected_type)
    assert getattr(extraction, "value", None) == expected_value


def test_composite_bearer_rejects_oversized_credentials_during_extraction() -> None:
    physical_slot, _ = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
        maximum_token_bytes=5,
    ).build(_Resolver())

    extraction = physical_slot.extract(
        SimpleNamespace(scope={"headers": [(b"authorization", b"Bearer longer")]})  # type: ignore[arg-type]
    )

    assert extraction == InvalidCredentials()


async def test_composite_bearer_rejects_malformed_routes_before_verification() -> None:
    verifier = _recording_jwt_verifier(InvalidCredentials())
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=verifier,  # type: ignore[arg-type]
            ),
        ),
    )
    _, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)

    outcome = await mechanism_value.authenticator.authenticate("malformed", SimpleNamespace())  # type: ignore[arg-type]

    assert outcome == InvalidCredentials()
    assert not verifier.calls


async def test_composite_bearer_uses_an_aware_utc_clock_by_default() -> None:
    verifier = _recording_jwt_verifier(InvalidCredentials())
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=verifier,  # type: ignore[arg-type]
            ),
        ),
    )
    _, mechanism_value = composite.build(_Resolver())

    await mechanism_value.authenticator.authenticate(
        _routing_token(issuer=_JWT_ISSUER, audiences=_JWT_AUDIENCE),
        SimpleNamespace(),  # type: ignore[arg-type]
    )

    assert verifier.calls[0][1].tzinfo is timezone.utc


def test_composite_bearer_builds_one_native_registry_mechanism() -> None:
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
    )

    physical_slot, mechanism_value = composite.build(_Resolver())
    registry = AuthenticationRegistry(slots=(physical_slot,), mechanisms=(mechanism_value,))  # type: ignore[arg-type]

    assert registry.slot_names == ("authorization.bearer",)
    assert registry.mechanism_names == ("bearer",)
    assert mechanism_value.scheme_name == "bearer"
    assert mechanism_value.security_scheme == SecurityScheme(type="http", scheme="bearer", bearer_format="JWT")


async def test_composite_bearer_never_retains_or_represents_the_raw_token() -> None:
    verifier = _recording_jwt_verifier(InvalidCredentials())
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=verifier,  # type: ignore[arg-type]
            ),
        ),
    )
    physical_slot, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)
    token = _routing_token(issuer=_JWT_ISSUER, audiences=_JWT_AUDIENCE)
    extraction = physical_slot.extract(
        SimpleNamespace(scope={"headers": [(b"authorization", f"Bearer {token}".encode())]})  # type: ignore[arg-type]
    )
    outcome = await mechanism_value.authenticator.authenticate(token, SimpleNamespace())  # type: ignore[arg-type]

    assert isinstance(extraction, PresentedCredential)
    assert outcome == InvalidCredentials()
    assert all(
        token not in repr(value)
        for value in (composite, physical_slot, mechanism_value, mechanism_value.authenticator, extraction, outcome)
    )


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (lambda: BearerSlotSelector(issuers=frozenset()), "issuer"),
        (lambda: BearerSlotSelector(issuers=frozenset({_JWT_ISSUER}), token_types=frozenset()), "token types"),
        (lambda: CompositeBearerConfig(mechanism_name="bearer", slots=()), "at least one"),
        (
            lambda: CompositeBearerConfig(
                mechanism_name="bearer",
                slots=(
                    BearerTokenSlot(
                        name="duplicate",
                        selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                        verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
                    ),
                    BearerTokenSlot(
                        name="duplicate",
                        selector=BearerSlotSelector(issuers=frozenset({"https://other.example"})),
                        verifier=_recording_jwt_verifier(InvalidCredentials(), issuer="https://other.example"),  # type: ignore[arg-type]
                    ),
                ),
            ),
            "Duplicate bearer slot",
        ),
        (
            lambda: CompositeBearerConfig(
                mechanism_name="bearer",
                slots=tuple(
                    BearerTokenSlot(
                        name=f"slot-{index}",
                        selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                        verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
                    )
                    for index in range(2)
                ),
            ),
            "identical selector",
        ),
        (
            lambda: CompositeBearerConfig(
                mechanism_name="bearer",
                slots=(
                    BearerTokenSlot(
                        name="local",
                        selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                        verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
                    ),
                ),
                maximum_token_bytes=0,
            ),
            "maximum token bytes",
        ),
        (
            lambda: BearerTokenSlot(
                name="missing-config",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=cast("Any", SimpleNamespace()),
            ),
            "must expose JWTValidationConfig",
        ),
        (
            lambda: BearerTokenSlot(
                name="issuer-mismatch",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials(), issuer="https://other.example"),  # type: ignore[arg-type]
            ),
            "does not match verifier",
        ),
        (
            lambda: BearerTokenSlot(
                name="audience-mismatch",
                selector=BearerSlotSelector(
                    issuers=frozenset({_JWT_ISSUER}), audiences=frozenset({"another-audience"})
                ),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
            "does not match verifier",
        ),
        (
            lambda: BearerTokenSlot(
                name="type-mismatch",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER}), token_types=frozenset({"id+jwt"})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
            "does not match verifier",
        ),
    ],
)
def test_composite_bearer_configuration_rejects_ambiguous_or_unsafe_values(
    factory: Callable[[], object], match: str
) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        factory()


def test_composite_bearer_requires_a_callable_clock() -> None:
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
    )

    with pytest.raises(ImproperlyConfiguredException, match="clock must be callable"):
        composite.build(_Resolver(), clock=None)  # type: ignore[arg-type]
