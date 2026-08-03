"""Bounded properties for untrusted security inputs and state codecs."""

from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Any, cast

from hypothesis import given, settings
from hypothesis import strategies as st
from litestar.exceptions import ImproperlyConfiguredException, WebSocketException

from litestar_security import any_of
from litestar_security.accounts import RefreshTokenCodec
from litestar_security.authentication import InvalidCredentials
from litestar_security.headers import ContentSecurityPolicy
from litestar_security.providers.api_key import APIKeyCodec
from litestar_security.providers.jwt import UnverifiedJWTRoute, parse_unverified_jwt_route
from litestar_security.providers.oauth import pkce_s256
from litestar_security.websocket import WebSocketSecurityConfig, extract_websocket_handshake

_PROPERTY_SETTINGS = settings(max_examples=100, derandomize=True, deadline=None)
_IDENTIFIER = st.from_regex(r"[a-z][a-z0-9-]{0,31}", fullmatch=True)
_CSP_SOURCE = st.from_regex(r"[A-Za-z0-9'/:._*+-]{1,64}", fullmatch=True)
_PKCE_VERIFIER = st.text(
    min_size=43, max_size=128, alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
)


@_PROPERTY_SETTINGS
@given(st.lists(_IDENTIFIER, min_size=1, max_size=8, unique=True))
def test_policy_normalization_preserves_explicit_unique_order(names: list[str]) -> None:
    policy = any_of(*names)

    assert [requirement.name for requirement in policy.requirements] == names


@_PROPERTY_SETTINGS
@given(st.one_of(st.text(max_size=512), st.binary(max_size=512), st.integers()))
def test_api_key_parser_is_total_for_arbitrary_runtime_values(value: object) -> None:
    proof = APIKeyCodec(pepper=b"p" * 32).proof(value)

    assert proof is None or len(proof.digest) == 32


@_PROPERTY_SETTINGS
@given(st.text(max_size=1_024))
def test_unverified_jwt_parser_is_bounded_and_total(token: str) -> None:
    result = parse_unverified_jwt_route(token, maximum_token_bytes=512, maximum_json_depth=8)

    assert isinstance(result, (InvalidCredentials, UnverifiedJWTRoute))


@_PROPERTY_SETTINGS
@given(_IDENTIFIER, st.lists(_CSP_SOURCE, max_size=8, unique=True))
def test_csp_serialization_is_deterministic_and_control_free(directive: str, sources: list[str]) -> None:
    policy = ContentSecurityPolicy(directives={directive: tuple(sources)})

    assert policy.serialize() == policy.serialize()
    assert not re.search(r"[\x00-\x1f\x7f]", policy.serialize())


@_PROPERTY_SETTINGS
@given(_PKCE_VERIFIER)
def test_pkce_challenges_are_unpadded_fixed_base64url(verifier: str) -> None:
    challenge = pkce_s256(verifier)

    assert len(challenge) == 43
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge)


@_PROPERTY_SETTINGS
@given(st.text(max_size=512))
def test_refresh_token_parser_returns_one_sanitized_outcome(value: str) -> None:
    outcome = RefreshTokenCodec(pepper=b"r" * 32).verify(value)

    assert isinstance(outcome, InvalidCredentials) or len(outcome.digest) == 32


@_PROPERTY_SETTINGS
@given(st.binary(max_size=512), st.lists(st.tuples(st.binary(max_size=32), st.binary(max_size=128)), max_size=8))
def test_websocket_handshake_parser_fails_only_with_typed_transport_error(
    query_string: bytes, headers: list[tuple[bytes, bytes]]
) -> None:
    connection = SimpleNamespace(scope={"headers": headers, "query_string": query_string})
    try:
        result = extract_websocket_handshake(
            cast("Any", connection), config=WebSocketSecurityConfig(), uses_cookie_credentials=False
        )
    except WebSocketException:
        return
    assert result.connect_token is None or isinstance(result.connect_token, str)


@_PROPERTY_SETTINGS
@given(st.text(max_size=128))
def test_csp_rejects_or_safely_serializes_arbitrary_sources(source: str) -> None:
    try:
        serialized = ContentSecurityPolicy(directives={"script-src": (source,)}).serialize()
    except ImproperlyConfiguredException:
        return
    assert "\r" not in serialized
    assert "\n" not in serialized
