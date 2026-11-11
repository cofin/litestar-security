"""Adversarial input corpora for the security parsers and serializers.

Each boundary has one immutable ``tuple`` corpus whose failure classes and
required caller arguments are cataloged in this docstring.
``src/tests/unit/test_input_corpora.py`` parametrizes over them to enforce
totality and sanitization guarantees.

**Caller arguments defining boundary values:**

===============================  =============================================
Corpus                           Argument that makes its boundary meaningful
===============================  =============================================
``JWT_LIKE_TOKENS``              ``maximum_token_bytes=512``,
                                 ``maximum_json_depth=8`` (library defaults are
                                 16,384 and 32).
``ADVERSARIAL_TEXT`` (refresh)   ``RefreshTokenCodec(pepper=b"r" * 32)``
``ADVERSARIAL_TEXT`` (API key)   ``APIKeyCodec(pepper=b"p" * 32)``
``HANDSHAKE_BYTES``              ``WebSocketSecurityConfig()``,
                                 ``uses_cookie_credentials=False``
``CSP_DIRECTIVES``               Parametrized as a Cartesian product with
                                 ``CSP_SOURCE_LISTS`` so directive name and
                                 source arity vary independently.
``CSP_SOURCE_LISTS``             Empty entry hits the bare-directive branch;
                                 duplicate pair hits deduplication.
===============================  =============================================

**Corpus inventory and entry failure classes:**

- ``ADVERSARIAL_TEXT``: untrusted text shared across refresh-token, API-key,
  and CSP checks covering empty string, whitespace-only text, NUL, C0 control,
  DEL, CRLF header injection, oversized 4096-byte text, astral-plane character,
  Cyrillic ``a`` confusable, right-to-left bidi override, percent-encoded NUL,
  and percent-encoded CRLF. Confusable and bidirectional code points remain
  escaped in source so Ruff ``RUF001``/``RUF003``/``PLE2502`` stay satisfied.
- ``IDENTIFIERS``: valid policy requirement names from
  ``r"[a-z][a-z0-9-]{0,31}"`` covering 1-char minimum, 32-char maximum,
  all-hyphen tail, trailing digit, unsorted pair preserving caller order,
  multi-entry ordered tuple, and shared prefixes staying distinct.
- ``ARBITRARY_RUNTIME_VALUES``: untyped inputs to ``APIKeyCodec.proof`` covering
  empty/plausible text, empty/non-UTF-8/oversized bytes, zero/negative/65-bit
  integers, ``None``, ``bool`` subclassing ``int``, bare ``object()``, and list
  container.
- ``JWT_LIKE_TOKENS``: malformed or boundary-sized compact JWT candidates under
  ``maximum_token_bytes=512`` covering empty, 1/2/4 segments, three empty
  segments, non-base64 segments, and 511/512/513-byte lengths.
- ``JWT_DEPTH_BOMBS``: computed three-segment JWTs straddling
  ``maximum_json_depth=8`` (7 nested objects accepted; 8 nested objects
  rejected). Re-measure both if the depth bound changes.
- ``CSP_SOURCES``: legal source expressions from
  ``r"[A-Za-z0-9'/:._*+-]{1,64}"`` covering 1-char minimum, 64-char maximum,
  quoted ``'self'``, HTTPS origin, wildcard host, base64 hash characters, bare
  ``data:`` scheme, explicit port, and remaining punctuation ``-_.``.
- ``CSP_DIRECTIVES``: legal directive names covering 1-char minimum, 32-char
  maximum, digit suffix, all-hyphen tail, and canonical ``script-src``.
- ``CSP_SOURCE_LISTS``: 0-to-8 source lists covering empty bare serialization,
  single source, three mixed sources, duplicate collapse, and 8-host width.
- ``PKCE_VERIFIERS``: RFC 7636 unreserved verifiers covering 43-char minimum,
  128-char maximum, hyphen-terminated minimum, full unreserved alphabet, and
  48-char punctuation-only verifier producing 43-char unpadded base64url S256.
- ``HANDSHAKE_BYTES``: WebSocket ``(query_string, headers)`` pairs covering
  empty input, non-UTF-8 query string, empty/oversized query token, 32/128-byte
  query boundaries, embedded query NUL, duplicate ``cookie`` headers, empty
  origin, non-UTF-8 header pair, oversized origin, and CRLF header injection.
"""

import json
from base64 import urlsafe_b64encode

ADVERSARIAL_TEXT: tuple[str, ...] = (
    "",
    " ",
    "\x00",
    "\x1f",
    "\x7f",
    "\r\n",
    "a" * 4096,
    "\U0001f600",
    "\u0430dmin",
    "\u202eadmin",
    "%00",
    "%0d%0a",
)

IDENTIFIERS: tuple[tuple[str, ...], ...] = (
    ("a",),
    ("a" + "b" * 31,),
    ("a---------------",),
    ("a1",),
    ("beta", "alpha"),
    ("alpha", "beta", "gamma"),
    ("a", "a-b", "a-b-c"),
)

ARBITRARY_RUNTIME_VALUES: tuple[object, ...] = (
    "",
    "valid-looking-key",
    b"",
    b"\xff\xfe",
    b"a" * 512,
    0,
    -1,
    2**64,
    None,
    True,
    object(),
    ["key"],
)

JWT_LIKE_TOKENS: tuple[str, ...] = ("", "a", "a.b", "a.b.c.d", "..", "!!!.!!!.!!!", "a" * 511, "a" * 512, "a" * 513)

_SIGNATURE_SEGMENT = urlsafe_b64encode(b"signature").rstrip(b"=").decode("ascii")
_HEADER_SEGMENT = (
    urlsafe_b64encode(json.dumps({"alg": "none"}, separators=(",", ":")).encode("utf-8")).rstrip(b"=").decode("ascii")
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


JWT_DEPTH_BOMBS: tuple[str, ...] = (_depth_bomb(7), _depth_bomb(8))

CSP_SOURCES: tuple[str, ...] = (
    "a",
    "a" * 64,
    "'self'",
    "https://cdn.example.com",
    "*.example.com",
    "sha256-abc+def/ghi",
    "data:",
    "example.com:8443",
    "a-b_c.d",
)

CSP_DIRECTIVES: tuple[str, ...] = ("a", "a" + "b" * 31, "a1", "a---------------", "script-src")

CSP_SOURCE_LISTS: tuple[tuple[str, ...], ...] = (
    (),
    ("a",),
    ("'self'", "https://cdn.example.com", "*.example.com"),
    ("a", "a"),
    tuple(f"s{index}.example.com" for index in range(8)),
)

PKCE_VERIFIERS: tuple[str, ...] = (
    "a" * 43,
    "a" * 128,
    "a" * 42 + "-",
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~" + "a" * 44,
    "-._~" * 12,
)

HANDSHAKE_BYTES: tuple[tuple[bytes, list[tuple[bytes, bytes]]], ...] = (
    (b"", []),
    (b"\xff\xfe", []),
    (b"token=", []),
    (b"token=" + b"a" * 128, []),
    (b"a" * 32, []),
    (b"a" * 128, []),
    (b"token=a\x00b", []),
    (b"", [(b"cookie", b"a=1"), (b"cookie", b"b=2")]),
    (b"", [(b"origin", b"")]),
    (b"", [(b"\xff", b"\xfe")]),
    (b"", [(b"origin", b"a" * 128)]),
    (b"", [(b"origin", b"https://app.example\r\nx: y")]),
)
