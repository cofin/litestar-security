"""OIDC discovery behavior.."""

import gzip
import json
from collections.abc import Callable, Mapping

import httpx
import pytest
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.providers import _internal as providers_internal
from litestar_security.providers.oidc import DiscoveryPolicy, OIDCDiscoveryClient, OIDCDiscoveryError, OIDCMetadata
from litestar_security.providers.oidc import _discovery as oidc_discovery
from tests.fixtures.collaborators import ChunkedByteStream as _ChunkedOIDCStream
from tests.fixtures.collaborators import RecordingDNSResolver as _FakeOIDCResolver
from tests.fixtures.collaborators import RecordingMockTransport as _RecordingMockTransport

_OIDC_ISSUER = "https://issuer.example/tenant"

_OIDC_DISCOVERY_URL = f"{_OIDC_ISSUER}/.well-known/openid-configuration"

_OIDC_PUBLIC_IP = "93.184.216.34"


def _oidc_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "issuer": _OIDC_ISSUER,
        "jwks_uri": f"{_OIDC_ISSUER}/jwks",
        "authorization_endpoint": f"{_OIDC_ISSUER}/authorize",
        "token_endpoint": f"{_OIDC_ISSUER}/token",
        "end_session_endpoint": f"{_OIDC_ISSUER}/logout",
        "revocation_endpoint": f"{_OIDC_ISSUER}/revoke",
        "id_token_signing_alg_values_supported": ["EdDSA", "RS256"],
    }
    document.update(overrides)
    return document


def _oidc_response(
    document: Mapping[str, object] | None = None,
    *,
    status_code: int = 200,
    content: bytes | None = None,
    content_type: str | None = "application/json",
) -> httpx.Response:
    headers = {} if content_type is None else {"content-type": content_type}
    body = (
        json.dumps(dict(document if document is not None else _oidc_document()), separators=(",", ":")).encode()
        if content is None
        else content
    )
    return httpx.Response(status_code, content=body, headers=headers)


def _oidc_client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    policy: DiscoveryPolicy | None = None,
    algorithms: frozenset[str] = frozenset({"EdDSA", "ES256"}),
    answers: Mapping[str, tuple[str, ...]] | None = None,
) -> tuple[OIDCDiscoveryClient, _RecordingMockTransport, _FakeOIDCResolver]:
    transport = _RecordingMockTransport(handler)
    resolver = _FakeOIDCResolver(
        {"issuer.example": (_OIDC_PUBLIC_IP,), "keys.example": (_OIDC_PUBLIC_IP,)} if answers is None else answers
    )
    client = OIDCDiscoveryClient(
        policy=policy or DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER})),
        algorithms=algorithms,
        transport=transport,
        resolver=resolver,
    )
    return client, transport, resolver


async def _discover_and_close(client: OIDCDiscoveryClient, issuer: str = _OIDC_ISSUER) -> OIDCMetadata:
    try:
        return await client.discover(issuer)
    finally:
        await client.aclose()


async def test_oidc_discovery_derives_one_exact_url_and_returns_pinned_metadata() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert str(request.url) == _OIDC_DISCOVERY_URL
        return _oidc_response(content_type="application/json; charset=utf-8")

    client, transport, resolver = _oidc_client(handler)

    metadata = await _discover_and_close(client)

    assert metadata == OIDCMetadata(
        issuer=_OIDC_ISSUER,
        jwks_uri=f"{_OIDC_ISSUER}/jwks",
        authorization_endpoint=f"{_OIDC_ISSUER}/authorize",
        token_endpoint=f"{_OIDC_ISSUER}/token",
        end_session_endpoint=f"{_OIDC_ISSUER}/logout",
        revocation_endpoint=f"{_OIDC_ISSUER}/revoke",
        algorithms=frozenset({"EdDSA"}),
    )
    assert transport.was_closed is True
    assert transport.requests[0].url == httpx.URL(_OIDC_DISCOVERY_URL)
    assert ("issuer.example", 443) in resolver.calls


async def test_oidc_discovery_url_override_replaces_the_derived_path() -> None:
    override = "https://issuer.example/.well-known/openid-configuration"

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == override
        return _oidc_response()

    client, transport, _resolver = _oidc_client(handler)

    try:
        metadata = await client.discover(_OIDC_ISSUER, discovery_url=override)
    finally:
        await client.aclose()

    assert metadata.issuer == _OIDC_ISSUER
    assert transport.requests[0].url == httpx.URL(override)


@pytest.mark.parametrize(
    "override",
    [
        "https://elsewhere.example/.well-known/openid-configuration",
        "https://issuer.example:8443/.well-known/openid-configuration",
        "http://issuer.example/.well-known/openid-configuration",
        "/.well-known/openid-configuration",
        "",
    ],
)
async def test_oidc_discovery_url_override_must_share_the_issuer_origin(override: str) -> None:
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response())

    try:
        with pytest.raises(ImproperlyConfiguredException):
            await client.discover(_OIDC_ISSUER, discovery_url=override)
    finally:
        await client.aclose()

    assert transport.requests == []


async def test_oidc_discovery_url_override_still_pins_the_issuer_claim() -> None:
    override = "https://issuer.example/.well-known/openid-configuration"

    def handler(_request: httpx.Request) -> httpx.Response:
        return _oidc_response(_oidc_document(issuer="https://issuer.example/other"))

    client, _transport, _resolver = _oidc_client(handler)

    try:
        with pytest.raises(OIDCDiscoveryError):
            await client.discover(_OIDC_ISSUER, discovery_url=override)
    finally:
        await client.aclose()


async def test_oidc_discovery_client_context_returns_itself_and_closes_transport() -> None:
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response())

    async with client as entered:
        assert entered is client
        metadata = await entered.discover(_OIDC_ISSUER)

    assert metadata.issuer == _OIDC_ISSUER
    assert transport.was_closed is True


def test_discovery_policy_normalizes_configured_trust_boundaries_once() -> None:
    policy = DiscoveryPolicy(
        allowed_issuers=frozenset({"https://BÜCHER.example:443/", "https://EXAMPLE.com/tenant"}),
        allowed_jwks_origins=frozenset({"https://KEYS.example:443"}),
    )

    assert policy.allowed_issuers == frozenset({"https://xn--bcher-kva.example", "https://example.com/tenant"})
    assert policy.allowed_jwks_origins == frozenset({"https://keys.example"})


@pytest.mark.parametrize(
    "kwargs",
    [
        {"allowed_issuers": frozenset()},
        {"allowed_issuers": frozenset({""})},
        {"allowed_issuers": frozenset({7})},
        {"allowed_issuers": frozenset({"issuer.example"})},
        {"allowed_issuers": frozenset({"http://issuer.example"})},
        {"allowed_issuers": frozenset({"https://user@issuer.example"})},
        {"allowed_issuers": frozenset({"https://issuer.example?tenant=one"})},
        {"allowed_issuers": frozenset({"https://issuer.example#tenant"})},
        {"allowed_issuers": frozenset({"https://issuer.example:8443"})},
        {"allowed_issuers": frozenset({"https://issuer.example/tenant/"})},
        {"allowed_issuers": frozenset({"https://issuer.example/tenant/../other"})},
        {"allowed_issuers": frozenset({"https://issuer.example/tenant/%2e%2e/other"})},
        {
            "allowed_issuers": frozenset({_OIDC_ISSUER}),
            "allowed_jwks_origins": frozenset({"https://keys.example/path"}),
        },
        {"allowed_issuers": frozenset({_OIDC_ISSUER}), "allowed_ports": frozenset()},
        {"allowed_issuers": frozenset({_OIDC_ISSUER}), "allowed_ports": frozenset({0})},
        {"allowed_issuers": frozenset({_OIDC_ISSUER}), "connect_timeout": 0},
        {"allowed_issuers": frozenset({_OIDC_ISSUER}), "read_timeout": -1},
        {"allowed_issuers": frozenset({_OIDC_ISSUER}), "maximum_document_bytes": 0},
    ],
    ids=[
        "empty-allowlist",
        "empty-url",
        "non-string-url",
        "relative",
        "http",
        "userinfo",
        "query",
        "fragment",
        "port",
        "non-root-trailing-slash",
        "dot-segment",
        "encoded-dot-segment",
        "jwks-origin-path",
        "empty-ports",
        "invalid-port",
        "connect-timeout",
        "read-timeout",
        "body-limit",
    ],
)
def test_discovery_policy_rejects_ambiguous_or_unsafe_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        DiscoveryPolicy(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "algorithms",
    [frozenset(), frozenset({"none"}), frozenset({""}), frozenset({" RS256"}), frozenset({7})],
    ids=["empty", "unsupported", "empty-member", "unnormalized", "non-string"],
)
def test_oidc_discovery_client_rejects_invalid_pinned_algorithms(algorithms: frozenset[object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        OIDCDiscoveryClient(
            policy=DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER})),
            algorithms=algorithms,  # type: ignore[arg-type]
            transport=_RecordingMockTransport(lambda _request: _oidc_response()),
            resolver=_FakeOIDCResolver({"issuer.example": (_OIDC_PUBLIC_IP,)}),
        )


@pytest.mark.parametrize(
    "issuer",
    ["https://issuer.example/tenant/", "https://issuer.example/other", "https://unconfigured.example/tenant"],
    ids=["trailing-slash", "different-path", "different-host"],
)
async def test_oidc_discovery_rejects_non_exact_issuer_without_dns_or_network(issuer: str) -> None:
    def fail_request(_request: httpx.Request) -> httpx.Response:
        msg = "Discovery transport must not run"
        raise AssertionError(msg)

    client, transport, resolver = _oidc_client(fail_request, answers={})

    with pytest.raises(ImproperlyConfiguredException):
        await _discover_and_close(client, issuer)

    assert transport.requests == []
    assert resolver.calls == []


@pytest.mark.parametrize("issuer", ["https://ISSUER.example/tenant", "https://issuer.example:443/tenant"])
async def test_oidc_discovery_canonicalizes_equivalent_allowed_issuer_forms(issuer: str) -> None:
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response())

    metadata = await _discover_and_close(client, issuer)

    assert metadata.issuer == _OIDC_ISSUER
    assert transport.requests[0].url == httpx.URL(_OIDC_DISCOVERY_URL)


@pytest.mark.parametrize(
    ("addresses", "accepted"),
    [
        (("93.184.216.34",), True),
        (("2001:4860:4860::8888",), True),
        (("93.184.216.34", "10.0.0.1"), False),
        (("127.0.0.1",), False),
        (("10.0.0.1",), False),
        (("172.16.0.1",), False),
        (("192.168.0.1",), False),
        (("169.254.1.1",), False),
        (("224.0.0.1",), False),
        (("0.0.0.0",), False),  # noqa: S104 - SSRF rejection fixture
        (("240.0.0.1",), False),
        (("::1",), False),
        (("fc00::1",), False),
        (("fe80::1",), False),
        (("ff00::1",), False),
        (("::",), False),
        (("::ffff:10.0.0.1",), False),
        (("not-an-ip",), False),
    ],
    ids=[
        "public-ipv4",
        "public-ipv6",
        "mixed-public-private",
        "loopback-v4",
        "private-10",
        "private-172",
        "private-192",
        "link-local-v4",
        "multicast-v4",
        "unspecified-v4",
        "reserved-v4",
        "loopback-v6",
        "private-v6",
        "link-local-v6",
        "multicast-v6",
        "unspecified-v6",
        "mapped-private-v4",
        "malformed-answer",
    ],
)
async def test_oidc_discovery_classifies_every_dns_answer(addresses: tuple[str, ...], *, accepted: bool) -> None:
    client, transport, _resolver = _oidc_client(
        lambda _request: _oidc_response(), answers={"issuer.example": addresses}
    )

    if accepted:
        metadata = await _discover_and_close(client)
        assert metadata.issuer == _OIDC_ISSUER
        assert len(transport.requests) == 1
    else:
        with pytest.raises(OIDCDiscoveryError):
            await _discover_and_close(client)
        assert transport.requests == []


async def test_oidc_discovery_maps_resolver_runtime_failures_without_network() -> None:
    async def fail_resolution(_hostname: str, _port: int) -> tuple[str, ...]:
        message = "resolver detail must not escape"
        raise RuntimeError(message)

    transport = _RecordingMockTransport(lambda _request: _oidc_response())
    client = OIDCDiscoveryClient(
        policy=DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER})),
        algorithms=frozenset({"EdDSA"}),
        transport=transport,
        resolver=fail_resolution,
    )

    with pytest.raises(OIDCDiscoveryError) as exc_info:
        await _discover_and_close(client)

    assert transport.requests == []
    assert "resolver detail" not in repr(exc_info.value)


async def test_oidc_discovery_rejects_an_empty_dns_result_without_network() -> None:
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response(), answers={"issuer.example": ()})

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)

    assert transport.requests == []


async def test_oidc_discovery_classifies_literal_public_ip_without_resolving() -> None:
    issuer = "https://93.184.216.34"
    resolver_calls: list[tuple[str, int]] = []

    async def fail_if_resolved(hostname: str, port: int) -> tuple[str, ...]:
        resolver_calls.append((hostname, port))
        message = "Literal addresses must not reach DNS"
        raise AssertionError(message)

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == f"{issuer}/.well-known/openid-configuration"
        return _oidc_response(
            _oidc_document(
                issuer=issuer,
                jwks_uri=f"{issuer}/jwks",
                authorization_endpoint=None,
                token_endpoint=None,
                end_session_endpoint=None,
                revocation_endpoint=None,
            )
        )

    transport = _RecordingMockTransport(handler)
    client = OIDCDiscoveryClient(
        policy=DiscoveryPolicy(allowed_issuers=frozenset({issuer})),
        algorithms=frozenset({"EdDSA"}),
        transport=transport,
        resolver=fail_if_resolved,
    )

    metadata = await _discover_and_close(client, issuer)

    assert metadata.issuer == issuer
    assert resolver_calls == []


def test_shared_ssrf_primitives_live_in_providers_internal() -> None:
    assert callable(providers_internal.public_address)
    assert callable(providers_internal.resolve_addresses)


async def test_oidc_discovery_default_resolver_deduplicates_getaddrinfo_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int, int]] = []

    async def fake_getaddrinfo(host: str, port: int, **kwargs: int) -> list[tuple[object, ...]]:
        calls.append((host, port, kwargs["type"]))
        address = (_OIDC_PUBLIC_IP, port)
        return [(object(), object(), object(), "", address), (object(), object(), object(), "", address)]

    monkeypatch.setattr(providers_internal, "getaddrinfo", fake_getaddrinfo)
    transport = _RecordingMockTransport(lambda _request: _oidc_response())
    client = OIDCDiscoveryClient(
        policy=DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER})),
        algorithms=frozenset({"EdDSA"}),
        transport=transport,
    )

    metadata = await _discover_and_close(client)

    assert metadata.issuer == _OIDC_ISSUER
    assert calls == [("issuer.example", 443, providers_internal.socket.SOCK_STREAM)]


async def test_oidc_discovery_allows_explicit_controlled_private_keycloak_hosts() -> None:
    issuer = "http://keycloak.internal:8080/realms/application"
    policy = DiscoveryPolicy(
        allowed_issuers=frozenset({issuer}),
        require_https=False,
        allow_private_hosts=True,
        allowed_ports=frozenset({8080}),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == f"{issuer}/.well-known/openid-configuration"
        return _oidc_response(
            _oidc_document(
                issuer=issuer,
                jwks_uri=f"{issuer}/protocol/openid-connect/certs",
                authorization_endpoint=None,
                token_endpoint=None,
                end_session_endpoint=None,
                revocation_endpoint=None,
            )
        )

    client, _transport, _resolver = _oidc_client(handler, policy=policy, answers={"keycloak.internal": ("10.0.0.10",)})

    metadata = await _discover_and_close(client, issuer)

    assert metadata.issuer == issuer
    assert metadata.jwks_uri == f"{issuer}/protocol/openid-connect/certs"


@pytest.mark.parametrize("allowed", [False, True])
async def test_oidc_discovery_requires_explicit_cross_origin_jwks(*, allowed: bool) -> None:
    policy = DiscoveryPolicy(
        allowed_issuers=frozenset({_OIDC_ISSUER}),
        allowed_jwks_origins=frozenset({"https://keys.example"}) if allowed else frozenset(),
    )
    client, _transport, resolver = _oidc_client(
        lambda _request: _oidc_response(_oidc_document(jwks_uri="https://keys.example/jwks")), policy=policy
    )

    if allowed:
        metadata = await _discover_and_close(client)
        assert metadata.jwks_uri == "https://keys.example/jwks"
        assert ("keys.example", 443) in resolver.calls
    else:
        with pytest.raises(OIDCDiscoveryError):
            await _discover_and_close(client)
        assert resolver.calls == [("issuer.example", 443)]


@pytest.mark.parametrize(
    ("jwks_uri", "answers"),
    [
        ("http://issuer.example/tenant/jwks", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://issuer.example:8443/tenant/jwks", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://user@issuer.example/tenant/jwks", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://issuer.example/tenant/jwks?version=1", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://issuer.example/tenant/jwks#keys", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://issuer.example/tenant/../jwks", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://private.example/jwks", {"issuer.example": (_OIDC_PUBLIC_IP,), "private.example": ("192.168.1.10",)}),
    ],
    ids=["http", "port", "userinfo", "query", "fragment", "dot-segment", "private-dns"],
)
async def test_oidc_discovery_revalidates_untrusted_jwks_targets(
    jwks_uri: str, answers: Mapping[str, tuple[str, ...]]
) -> None:
    allowed_origins = frozenset({"https://private.example"}) if "private.example" in jwks_uri else frozenset()
    policy = DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER}), allowed_jwks_origins=allowed_origins)
    client, _transport, _resolver = _oidc_client(
        lambda _request: _oidc_response(_oidc_document(jwks_uri=jwks_uri)), policy=policy, answers=answers
    )

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


async def test_oidc_discovery_refuses_redirects_without_following_location() -> None:
    client, transport, resolver = _oidc_client(
        lambda _request: httpx.Response(302, headers={"location": "https://private.example/metadata"}),
        answers={"issuer.example": (_OIDC_PUBLIC_IP,)},
    )

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)

    assert len(transport.requests) == 1
    assert resolver.calls == [("issuer.example", 443)]


async def test_oidc_discovery_ignores_proxy_environment_with_injected_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8080")
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response())

    metadata = await _discover_and_close(client)

    assert metadata.issuer == _OIDC_ISSUER
    assert len(transport.requests) == 1


async def test_oidc_discovery_requests_identity_response_encoding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept-encoding"] == "identity"
        return _oidc_response()

    client, _transport, _resolver = _oidc_client(handler)

    metadata = await _discover_and_close(client)

    assert metadata.issuer == _OIDC_ISSUER


async def test_oidc_discovery_rejects_compressed_response_before_decoding() -> None:
    encoded = json.dumps(_oidc_document(), separators=(",", ":")).encode()
    stream = _ChunkedOIDCStream(gzip.compress(encoded))
    response = httpx.Response(
        200, headers={"content-type": "application/json", "content-encoding": "gzip"}, stream=stream
    )
    client, _transport, _resolver = _oidc_client(lambda _request: response)

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)

    assert stream.was_iterated is False


async def test_oidc_discovery_checks_streaming_capacity_before_extending(monkeypatch: pytest.MonkeyPatch) -> None:
    class _CapacityCheckedBytearray(bytearray):
        def extend(self, chunk: bytes) -> None:
            if len(self) + len(chunk) > 64:
                message = "Streaming chunk was appended before its size was checked"
                raise AssertionError(message)
            super().extend(chunk)

    monkeypatch.setattr(oidc_discovery, "bytearray", _CapacityCheckedBytearray, raising=False)
    policy = DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER}), maximum_document_bytes=64)
    response = httpx.Response(
        200, headers={"content-type": "application/json"}, stream=_ChunkedOIDCStream(b"x" * 40, b"x" * 40)
    )
    client, _transport, _resolver = _oidc_client(lambda _request: response, policy=policy)

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


async def test_oidc_discovery_enforces_streaming_body_limit_without_content_length() -> None:
    policy = DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER}), maximum_document_bytes=64)
    response = httpx.Response(
        200, headers={"content-type": "application/json"}, stream=_ChunkedOIDCStream(b"x" * 40, b"x" * 40)
    )
    assert "content-length" not in response.headers
    client, _transport, _resolver = _oidc_client(lambda _request: response, policy=policy)

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


async def test_oidc_discovery_rejects_excessive_json_depth() -> None:
    nested: object = None
    for _ in range(65):
        nested = {"nested": nested}
    document = _oidc_document(extension=nested)
    client, _transport, _resolver = _oidc_client(lambda _request: _oidc_response(document))

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.parametrize(
    ("response", "case"),
    [
        (httpx.Response(404, json={"error": "missing"}), "status-4xx"),
        (httpx.Response(503, json={"error": "unavailable"}), "status-5xx"),
        (_oidc_response(content_type=None), "missing-content-type"),
        (_oidc_response(content_type="text/plain"), "wrong-content-type"),
        (_oidc_response(content=b"{"), "invalid-json"),
        (_oidc_response(content=b'{"issuer":"one","issuer":"two"}'), "duplicate-json-member"),
        (_oidc_response(content=b"[]"), "non-object-json"),
        (_oidc_response(content=b'{"unsupported":NaN}'), "non-finite-json"),
        (_oidc_response(content=b"x" * 65_537), "body-limit"),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
async def test_oidc_discovery_rejects_untrusted_http_or_document_shapes(response: httpx.Response, case: str) -> None:
    del case
    client, _transport, _resolver = _oidc_client(lambda _request: response)

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.parametrize(
    "document",
    [
        _oidc_document(issuer="https://issuer.examp\u043be/tenant"),
        {key: value for key, value in _oidc_document().items() if key != "issuer"},
        {key: value for key, value in _oidc_document().items() if key != "jwks_uri"},
        _oidc_document(issuer=7),
        _oidc_document(jwks_uri=["https://issuer.example/jwks"]),
        _oidc_document(authorization_endpoint=7),
        _oidc_document(token_endpoint=[]),
        _oidc_document(end_session_endpoint={}),
        _oidc_document(id_token_signing_alg_values_supported="EdDSA"),  # noqa: S106 - algorithm type fixture
        _oidc_document(id_token_signing_alg_values_supported=["EdDSA", 7]),
        _oidc_document(id_token_signing_alg_values_supported=[]),
        _oidc_document(id_token_signing_alg_values_supported=["RS256"]),
    ],
    ids=[
        "issuer-mismatch",
        "missing-issuer",
        "missing-jwks-uri",
        "issuer-type",
        "jwks-type",
        "authorization-endpoint-type",
        "token-endpoint-type",
        "end-session-endpoint-type",
        "algorithm-type",
        "algorithm-member-type",
        "empty-provider-algorithms",
        "empty-pinned-intersection",
    ],
)
async def test_oidc_discovery_rejects_mismatched_or_unsupported_metadata(document: dict[str, object]) -> None:
    client, _transport, _resolver = _oidc_client(lambda _request: _oidc_response(document))

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


async def test_oidc_discovery_preserves_absent_optional_endpoints() -> None:
    client, _transport, _resolver = _oidc_client(
        lambda _request: _oidc_response(
            _oidc_document(authorization_endpoint=None, token_endpoint=None, end_session_endpoint=None)
        )
    )

    metadata = await _discover_and_close(client)

    assert metadata.authorization_endpoint is None
    assert metadata.token_endpoint is None
    assert metadata.end_session_endpoint is None


@pytest.mark.parametrize(
    ("field", "value", "answers"),
    [
        ("authorization_endpoint", "/authorize", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("token_endpoint", "http://issuer.example/token", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("end_session_endpoint", "https://user@issuer.example/logout", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        (
            "authorization_endpoint",
            "https://issuer.example/authorize?prompt=login",
            {"issuer.example": (_OIDC_PUBLIC_IP,)},
        ),
        ("token_endpoint", "https://issuer.example/token#fragment", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("end_session_endpoint", "https://issuer.example/tenant/../logout", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        (
            "token_endpoint",
            "https://private.example/token",
            {"issuer.example": (_OIDC_PUBLIC_IP,), "private.example": ("10.0.0.10",)},
        ),
    ],
    ids=["relative", "http", "userinfo", "query", "fragment", "dot-segment", "private-dns"],
)
async def test_oidc_discovery_rejects_unsafe_optional_endpoint_urls(
    field: str, value: str, answers: Mapping[str, tuple[str, ...]]
) -> None:
    client, _transport, _resolver = _oidc_client(
        lambda _request: _oidc_response(_oidc_document(**{field: value})), answers=answers
    )

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


async def test_oidc_discovery_requires_explicit_cross_origin_oauth_endpoint_trust() -> None:
    endpoints = {
        "authorization_endpoint": "https://login.example/authorize",
        "token_endpoint": "https://login.example/token",
        "end_session_endpoint": "https://login.example/logout",
    }
    answers = {"issuer.example": (_OIDC_PUBLIC_IP,), "login.example": (_OIDC_PUBLIC_IP,)}
    client, _transport, _resolver = _oidc_client(
        lambda _request: _oidc_response(_oidc_document(**endpoints)), answers=answers
    )

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)

    client, _transport, resolver = _oidc_client(
        lambda _request: _oidc_response(_oidc_document(**endpoints)),
        policy=DiscoveryPolicy(
            allowed_issuers=frozenset({_OIDC_ISSUER}), allowed_oauth_origins=frozenset({"https://login.example"})
        ),
        answers=answers,
    )
    metadata = await _discover_and_close(client)

    assert metadata.authorization_endpoint == endpoints["authorization_endpoint"]
    assert metadata.token_endpoint == endpoints["token_endpoint"]
    assert metadata.end_session_endpoint == endpoints["end_session_endpoint"]
    assert ("login.example", 443) in resolver.calls


async def test_oidc_discovery_sanitizes_transport_failures() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        message = "internal-host.example must not escape"
        raise httpx.ConnectError(message, request=request)

    client, _transport, _resolver = _oidc_client(fail)

    with pytest.raises(OIDCDiscoveryError) as exc_info:
        await _discover_and_close(client)

    assert "internal-host.example" not in repr(exc_info.value)


async def test_oidc_discovery_close_is_idempotent_and_closes_injected_transport() -> None:
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response())

    await client.aclose()
    await client.aclose()

    assert transport.was_closed is True
    with pytest.raises(OIDCDiscoveryError):
        await client.discover(_OIDC_ISSUER)
