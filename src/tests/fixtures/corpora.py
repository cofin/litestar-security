"""Adversarial input corpora for the security parsers and serializers.

One corpus per boundary, each entry commented with the failure class it stands
for. ``src/tests/unit/test_input_corpora.py`` parametrizes over them and keeps
the totality assertion each corpus exists to defend.

Every corpus is a ``tuple``, so it is immutable and safe to share at any scope.

**A corpus is only half of a boundary.** The properties pass non-default
arguments that make their boundary values meaningful, and those arguments die
with the property file. They are restated here:

===============================  =============================================
Corpus                           Argument that makes its boundary meaningful
===============================  =============================================
``JWT_LIKE_TOKENS``              ``maximum_token_bytes=512``,
                                 ``maximum_json_depth=8``. The library defaults
                                 are 16,384 and 32, so the 512-boundary and
                                 depth-8/9 entries mean nothing without them.
``ADVERSARIAL_TEXT`` (refresh)   ``RefreshTokenCodec(pepper=b"r" * 32)``
``ADVERSARIAL_TEXT`` (API key)   ``APIKeyCodec(pepper=b"p" * 32)``
``HANDSHAKE_BYTES``              ``WebSocketSecurityConfig()``,
                                 ``uses_cookie_credentials=False``
``CSP_DIRECTIVES``               Parametrized as a product with
                                 ``CSP_SOURCE_LISTS``, so the directive
                                 name and the source arity vary
                                 independently.
``CSP_SOURCE_LISTS``             Its empty entry reaches the bare-directive
                                 branch and its duplicate pair reaches the
                                 deduplication branch.
===============================  =============================================

Confusable and bidirectional characters are written as escapes. Ruff runs
``select = ["ALL"]`` and the test-tree ignores cover only ANN/D/PLR2004/S101, so
a literal confusable trips RUF001/RUF003 and a literal bidi override trips
PLE2502 -- and the escaped form is the readable one in a diff anyway.
"""

from __future__ import annotations

import json
from base64 import urlsafe_b64encode

# Shared by the refresh-token, API-key and CSP properties: untrusted text that
# must produce one sanitized outcome rather than an exception or a leak.
# Covers test_refresh_token_parser_returns_one_sanitized_outcome and
# test_csp_rejects_or_safely_serializes_arbitrary_sources.
ADVERSARIAL_TEXT: tuple[str, ...] = (
    "",  # empty
    " ",  # whitespace only
    "\x00",  # NUL
    "\x1f",  # C0 control
    "\x7f",  # DEL
    "\r\n",  # header injection
    "a" * 4096,  # oversized
    "\U0001f600",  # astral plane
    "\u0430dmin",  # unicode-confusable: Cyrillic a
    "\u202eadmin",  # bidi override
    "%00",  # percent-encoded NUL
    "%0d%0a",  # percent-encoded CRLF
)

# Policy requirement names, from r"[a-z][a-z0-9-]{0,31}".
# Covers test_policy_normalization_preserves_explicit_unique_order, whose point
# is that explicit order and uniqueness survive normalization.
IDENTIFIERS: tuple[tuple[str, ...], ...] = (
    ("a",),  # shortest legal name
    ("a" + "b" * 31,),  # longest legal name, 32 characters
    ("a---------------",),  # all-hyphen tail
    ("a1",),  # digit after the leading letter
    ("beta", "alpha"),  # order is significant and must not be sorted
    ("alpha", "beta", "gamma"),  # multiple, already ordered
    ("a", "a-b", "a-b-c"),  # shared prefixes must stay distinct
)

# Values reaching APIKeyCodec.proof from a runtime that never type-checked them.
# Covers test_api_key_parser_is_total_for_arbitrary_runtime_values: the parser
# must be total, returning None or a 32-byte digest, for any object at all.
ARBITRARY_RUNTIME_VALUES: tuple[object, ...] = (
    "",  # empty text
    "valid-looking-key",  # plausible text
    b"",  # empty bytes
    b"\xff\xfe",  # non-UTF-8 bytes
    b"a" * 512,  # oversized bytes
    0,  # falsy integer
    -1,  # negative integer
    2**64,  # integer beyond 64 bits
    None,  # missing value
    True,  # bool, which is also an int
    object(),  # arbitrary object with no text protocol
    ["key"],  # container instead of a scalar
)

# Tokens presented where a compact JWT is expected.
# Covers test_unverified_jwt_parser_is_bounded_and_total, which passes
# maximum_token_bytes=512 and maximum_json_depth=8 -- both boundaries below
# refer to those limits, not to the library defaults.
JWT_LIKE_TOKENS: tuple[str, ...] = (
    "",  # empty
    "a",  # one segment
    "a.b",  # two segments
    "a.b.c.d",  # four segments
    "..",  # three empty segments
    "!!!.!!!.!!!",  # non-base64 segments
    "a" * 511,  # one byte under the 512-byte bound
    "a" * 512,  # exactly the 512-byte bound
    "a" * 513,  # one byte over the 512-byte bound
)


def _depth_bomb(depth: int) -> str:
    """Build a compact JWT whose payload nests to an exact depth.

    Args:
        depth: How many nested objects the payload carries.

    Returns:
        A three-segment token whose payload decodes to that nesting depth.
    """
    payload: object = "leaf"
    for _ in range(depth):
        payload = {"n": payload}
    encoded = urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).rstrip(b"=").decode("ascii")
    return f"{_HEADER_SEGMENT}.{encoded}.{_SIGNATURE_SEGMENT}"


_SIGNATURE_SEGMENT = urlsafe_b64encode(b"signature").rstrip(b"=").decode("ascii")
_HEADER_SEGMENT = (
    urlsafe_b64encode(json.dumps({"alg": "none"}, separators=(",", ":")).encode("utf-8")).rstrip(b"=").decode("ascii")
)

# Depth bombs, separate because they are computed rather than literal. The pair
# straddles the limit: measured against the property's maximum_json_depth=8, a
# payload of 7 nested objects parses and one of 8 does not. A pair that does not
# straddle proves nothing, so re-measure before changing either number.
JWT_DEPTH_BOMBS: tuple[str, ...] = (
    _depth_bomb(7),  # deepest payload still accepted at maximum_json_depth=8
    _depth_bomb(8),  # shallowest payload rejected at maximum_json_depth=8
)

# Content-Security-Policy source expressions, from r"[A-Za-z0-9'/:._*+-]{1,64}".
# Covers test_csp_serialization_is_deterministic_and_control_free, whose
# assertions are that serialization is idempotent and control-character free.
CSP_SOURCES: tuple[str, ...] = (
    "a",  # shortest legal source
    "a" * 64,  # longest legal source
    "'self'",  # quoted keyword
    "https://cdn.example.com",  # scheme, colon and slashes
    "*.example.com",  # wildcard host
    "sha256-abc+def/ghi",  # plus and slash, as in a base64 hash
    "data:",  # bare scheme
    "example.com:8443",  # explicit port
    "a-b_c.d",  # every remaining allowed punctuation
)

# Directive names, from the same r"[a-z][a-z0-9-]{0,31}" the CSP boundary draws
# its first argument from. CSP_SOURCES varies only the source expression, so
# without these the directive-name axis is untested.
CSP_DIRECTIVES: tuple[str, ...] = (
    "a",  # shortest legal directive name
    "a" + "b" * 31,  # longest legal directive name, 32 characters
    "a1",  # digit after the leading letter
    "a---------------",  # all-hyphen tail
    "script-src",  # a real directive, for readability of the failure
)

# Source lists, from lists of up to 8 unique sources. The minimum size is zero,
# so an empty list is a live input reaching a distinct branch: a directive
# serialized with no sources at all.
CSP_SOURCE_LISTS: tuple[tuple[str, ...], ...] = (
    (),  # empty: the directive serializes bare, verified -> "script-src"
    ("a",),  # single source
    ("'self'", "https://cdn.example.com", "*.example.com"),  # several
    ("a", "a"),  # duplicates: deduplicated, verified -> "script-src a"
    tuple(f"s{index}.example.com" for index in range(8)),  # the widest list
)

# PKCE code verifiers, from the RFC 7636 unreserved alphabet.
# Covers test_pkce_challenges_are_unpadded_fixed_base64url, which asserts the
# challenge is always exactly 43 unpadded base64url characters.
PKCE_VERIFIERS: tuple[str, ...] = (
    "a" * 43,  # RFC 7636 minimum length
    "a" * 128,  # RFC 7636 maximum length
    "a" * 42 + "-",  # minimum length ending in a hyphen
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~" + "a" * 44,  # full unreserved alphabet
    "-._~" * 12,  # punctuation only, 48 characters
)

# WebSocket handshake scopes, as (query_string, headers) pairs.
# Covers test_websocket_handshake_parser_fails_only_with_typed_transport_error,
# which builds a scope with WebSocketSecurityConfig() and
# uses_cookie_credentials=False: the parser must either return a handshake or
# raise WebSocketException, never anything else.
HANDSHAKE_BYTES: tuple[tuple[bytes, list[tuple[bytes, bytes]]], ...] = (
    (b"", []),  # empty query string and no headers
    (b"\xff\xfe", []),  # non-UTF-8 query string
    (b"token=", []),  # present but empty parameter
    (b"token=" + b"a" * 128, []),  # oversized parameter value
    (b"a" * 32, []),  # 32-byte query-string boundary
    (b"a" * 128, []),  # 128-byte query-string boundary
    (b"token=a\x00b", []),  # embedded NUL in the query string
    (b"", [(b"cookie", b"a=1"), (b"cookie", b"b=2")]),  # duplicate header names
    (b"", [(b"origin", b"")]),  # empty origin
    (b"", [(b"\xff", b"\xfe")]),  # non-UTF-8 header name and value
    (b"", [(b"origin", b"a" * 128)]),  # oversized header value
    (b"", [(b"origin", b"https://app.example\r\nx: y")]),  # header injection attempt
)
