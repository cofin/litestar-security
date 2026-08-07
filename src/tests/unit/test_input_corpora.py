"""Totality and sanitization boundaries, over the adversarial input corpora.

One test per boundary, each parametrized across ``src/tests/fixtures/corpora.py``
and carrying the non-default arguments that make its corpus meaningful: the
parsers stay total, the serializers stay control-character free, and the codecs
return one sanitized outcome for any input at all.
"""

import re
from types import SimpleNamespace
from typing import Any, cast

import pytest
from litestar.exceptions import ImproperlyConfiguredException, WebSocketException

from litestar_security import any_of
from litestar_security.accounts import RefreshTokenCodec
from litestar_security.authentication import InvalidCredentials
from litestar_security.headers import ContentSecurityPolicy
from litestar_security.providers.api_key import APIKeyCodec
from litestar_security.providers.jwt import UnverifiedJWTRoute, parse_unverified_jwt_route
from litestar_security.providers.oauth import pkce_s256
from litestar_security.websocket import WebSocketSecurityConfig, extract_websocket_handshake
from tests.fixtures import corpora

CORPUS_NAMES = (
    "ADVERSARIAL_TEXT",
    "IDENTIFIERS",
    "ARBITRARY_RUNTIME_VALUES",
    "JWT_LIKE_TOKENS",
    "JWT_DEPTH_BOMBS",
    "CSP_SOURCES",
    "CSP_DIRECTIVES",
    "CSP_SOURCE_LISTS",
    "PKCE_VERIFIERS",
    "HANDSHAKE_BYTES",
)


@pytest.mark.parametrize("name", CORPUS_NAMES)
def test_every_corpus_is_a_non_empty_tuple(name: str) -> None:
    corpus = getattr(corpora, name)
    assert isinstance(corpus, tuple)
    assert corpus


@pytest.mark.parametrize("names", corpora.IDENTIFIERS)
def test_policy_normalization_preserves_explicit_unique_order(names: tuple[str, ...]) -> None:
    assert [requirement.name for requirement in any_of(*names).requirements] == list(names)


@pytest.mark.parametrize("value", corpora.ARBITRARY_RUNTIME_VALUES)
def test_api_key_parser_is_total(value: object) -> None:
    proof = APIKeyCodec(pepper=b"p" * 32).proof(value)
    assert proof is None or len(proof.digest) == 32


@pytest.mark.parametrize("token", [*corpora.JWT_LIKE_TOKENS, *corpora.JWT_DEPTH_BOMBS])
def test_unverified_jwt_parser_is_bounded_and_total(token: str) -> None:
    outcome = parse_unverified_jwt_route(token, maximum_token_bytes=512, maximum_json_depth=8)
    assert isinstance(outcome, (InvalidCredentials, UnverifiedJWTRoute))


def test_depth_bomb_comments_are_true() -> None:
    accepted, rejected = (
        parse_unverified_jwt_route(token, maximum_token_bytes=512, maximum_json_depth=8)
        for token in corpora.JWT_DEPTH_BOMBS
    )
    assert isinstance(accepted, UnverifiedJWTRoute), "the shallower bomb is documented as accepted"
    assert isinstance(rejected, InvalidCredentials), "the deeper bomb is documented as rejected"


@pytest.mark.parametrize("source", corpora.CSP_SOURCES)
def test_csp_source_alphabet_serializes_deterministically(source: str) -> None:
    policy = ContentSecurityPolicy(directives={"script-src": (source,)})
    assert policy.serialize() == policy.serialize()
    assert not re.search(r"[\x00-\x1f\x7f]", policy.serialize())


@pytest.mark.parametrize("directive", corpora.CSP_DIRECTIVES)
@pytest.mark.parametrize("sources", corpora.CSP_SOURCE_LISTS)
def test_csp_serialization_is_deterministic_and_control_free(directive: str, sources: tuple[str, ...]) -> None:
    policy = ContentSecurityPolicy(directives={directive: sources})

    assert policy.serialize() == policy.serialize()
    assert not re.search(r"[\x00-\x1f\x7f]", policy.serialize())


@pytest.mark.parametrize("verifier", corpora.PKCE_VERIFIERS)
def test_pkce_challenges_are_unpadded_fixed_base64url(verifier: str) -> None:
    challenge = pkce_s256(verifier)
    assert len(challenge) == 43
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge)


@pytest.mark.parametrize("value", corpora.ADVERSARIAL_TEXT)
def test_refresh_token_parser_returns_one_sanitized_outcome(value: str) -> None:
    outcome = RefreshTokenCodec(pepper=b"r" * 32).verify(value)
    assert isinstance(outcome, InvalidCredentials) or len(outcome.digest) == 32


@pytest.mark.parametrize("source", corpora.ADVERSARIAL_TEXT)
def test_csp_rejects_or_safely_serializes_arbitrary_sources(source: str) -> None:
    try:
        serialized = ContentSecurityPolicy(directives={"script-src": (source,)}).serialize()
    except ImproperlyConfiguredException:
        return
    assert "\r" not in serialized
    assert "\n" not in serialized


@pytest.mark.parametrize(("query_string", "headers"), corpora.HANDSHAKE_BYTES)
def test_websocket_handshake_parser_fails_only_with_typed_transport_error(
    query_string: bytes, headers: list[tuple[bytes, bytes]]
) -> None:
    connection = SimpleNamespace(scope={"headers": headers, "query_string": query_string})
    try:
        handshake = extract_websocket_handshake(
            cast("Any", connection), config=WebSocketSecurityConfig(), uses_cookie_credentials=False
        )
    except WebSocketException:
        return
    assert handshake.connect_token is None or isinstance(handshake.connect_token, str)
