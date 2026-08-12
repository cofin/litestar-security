"""HTTPX JWKS fetching tests."""

from typing import cast

import httpx
import pytest
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.providers.jwks import HttpxJWKSFetcher, JWKSFetchOutcome, JWKSFetchTarget
from litestar_security.providers.jwks import _httpx as jwks_httpx
from tests.fixtures.collaborators import ChunkedByteStream as _ChunkedOIDCStream
from tests.fixtures.collaborators import RecordingMockTransport as _RecordingMockTransport

_JWT_ISSUER = "https://issuer.example"

_OIDC_PUBLIC_IP = "93.184.216.34"

_JWKS_URI = f"{_JWT_ISSUER}/.well-known/jwks.json"


@pytest.mark.parametrize(
    "uri",
    [
        "/jwks.json",
        "http://issuer.example/jwks.json",
        "https://user@issuer.example/jwks.json",
        "",
        " https://issuer.example/jwks.json",
        "https://issuer.example:bad-port/jwks.json",
        cast("str", 7),
    ],
    ids=["relative", "http", "userinfo", "empty", "whitespace", "invalid-port", "non-string"],
)
async def test_httpx_jwks_fetcher_rejects_non_absolute_https_uri_before_resolution(uri: str) -> None:
    async def resolver(_host: str, _port: int) -> tuple[str, ...]:
        message = "Invalid JWKS URI must not reach DNS"
        raise AssertionError(message)

    transport = _RecordingMockTransport(lambda _request: httpx.Response(200))
    fetcher = HttpxJWKSFetcher(transport=transport, resolver=resolver)

    with pytest.raises(jwks_httpx._FetchGuardError):  # noqa: SLF001 - assert the private transport boundary failure
        await fetcher.fetch(JWKSFetchTarget(issuer=_JWT_ISSUER, jwks_uri=uri))

    assert transport.requests == []
    await fetcher.aclose()


async def test_httpx_jwks_fetcher_rejects_encoded_response_before_decoding() -> None:
    async def resolver(_host: str, _port: int) -> tuple[str, ...]:
        return (_OIDC_PUBLIC_IP,)

    stream = _ChunkedOIDCStream(b"encoded")
    response = httpx.Response(200, headers={"content-encoding": "gzip"}, stream=stream)
    fetcher = HttpxJWKSFetcher(transport=_RecordingMockTransport(lambda _request: response), resolver=resolver)

    with pytest.raises(jwks_httpx._FetchGuardError):  # noqa: SLF001 - assert the private transport boundary failure
        await fetcher.fetch(JWKSFetchTarget(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI))

    assert stream.was_iterated is False
    await fetcher.aclose()


async def test_httpx_jwks_fetcher_sends_if_none_match_returns_unfollowed_redirect_and_closes_idempotently() -> None:
    """The transport preserves conditional and non-success responses for the cache layer."""

    async def resolver(_host: str, _port: int) -> tuple[str, ...]:
        return (_OIDC_PUBLIC_IP,)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["if-none-match"] == '"v1"'
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(304, headers={"etag": '"v1"'})

    transport = _RecordingMockTransport(handler)
    fetcher = HttpxJWKSFetcher(transport=transport, resolver=resolver)

    response = await fetcher.fetch(JWKSFetchTarget(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI, etag='"v1"'))

    assert response == JWKSFetchOutcome(status_code=304, body=b"", headers={"etag": '"v1"'})
    await fetcher.aclose()
    await fetcher.aclose()
    assert transport.was_closed is True


async def test_httpx_jwks_fetcher_returns_redirect_verbatim_without_following_location() -> None:
    """A redirect remains a response for the cache layer to classify as unavailable."""

    async def resolver(_host: str, _port: int) -> tuple[str, ...]:
        return (_OIDC_PUBLIC_IP,)

    transport = _RecordingMockTransport(
        lambda _request: httpx.Response(301, headers={"location": "https://private.example/jwks.json"})
    )
    fetcher = HttpxJWKSFetcher(transport=transport, resolver=resolver)

    response = await fetcher.fetch(JWKSFetchTarget(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI))

    assert response.status_code == 301
    assert response.headers["location"] == "https://private.example/jwks.json"
    assert len(transport.requests) == 1
    await fetcher.aclose()


async def test_httpx_jwks_fetcher_checks_byte_ceiling_before_extending(monkeypatch: pytest.MonkeyPatch) -> None:
    """A streaming oversized chunk is rejected before allocating it into the body buffer."""

    class _CapacityCheckedBytearray(bytearray):
        def extend(self, chunk: bytes) -> None:
            if len(self) + len(chunk) > 64:
                message = "Streaming chunk was appended before its size was checked"
                raise AssertionError(message)
            super().extend(chunk)

    async def resolver(_host: str, _port: int) -> tuple[str, ...]:
        return (_OIDC_PUBLIC_IP,)

    monkeypatch.setattr(jwks_httpx, "bytearray", _CapacityCheckedBytearray, raising=False)
    response = httpx.Response(200, stream=_ChunkedOIDCStream(b"x" * 40, b"x" * 40))
    fetcher = HttpxJWKSFetcher(
        maximum_response_bytes=64, transport=_RecordingMockTransport(lambda _request: response), resolver=resolver
    )

    with pytest.raises(jwks_httpx._FetchGuardError):  # noqa: SLF001 - assert the private transport boundary failure
        await fetcher.fetch(JWKSFetchTarget(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI))

    await fetcher.aclose()


async def test_httpx_jwks_fetcher_enforces_ssrf_boundary_unless_private_hosts_are_explicitly_allowed() -> None:
    """Private resolved addresses require an explicit operator opt-in."""

    async def private_resolver(_host: str, _port: int) -> tuple[str, ...]:
        return ("127.0.0.1",)

    request = JWKSFetchTarget(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI)
    denied = HttpxJWKSFetcher(
        transport=_RecordingMockTransport(lambda _request: httpx.Response(200)), resolver=private_resolver
    )
    allowed_transport = _RecordingMockTransport(lambda _request: httpx.Response(200, content=b'{"keys":[]}'))
    allowed = HttpxJWKSFetcher(transport=allowed_transport, resolver=private_resolver, allow_private_hosts=True)

    with pytest.raises(jwks_httpx._FetchGuardError):  # noqa: SLF001 - assert the private transport boundary failure
        await denied.fetch(request)
    response = await allowed.fetch(request)

    assert response.body == b'{"keys":[]}'
    assert len(allowed_transport.requests) == 1
    await denied.aclose()
    await allowed.aclose()


async def test_httpx_jwks_fetcher_maps_resolution_failures_and_rejects_invalid_dns_answers() -> None:
    """Resolver failures, empty results, and malformed answers cannot leave the boundary."""

    async def failed_resolver(_host: str, _port: int) -> tuple[str, ...]:
        message = "private resolver failure"
        raise OSError(message)

    async def empty_resolver(_host: str, _port: int) -> tuple[str, ...]:
        return ()

    async def malformed_resolver(_host: str, _port: int) -> tuple[str, ...]:
        return ("not-an-ip",)

    request = JWKSFetchTarget(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI)
    fetchers = tuple(
        HttpxJWKSFetcher(transport=_RecordingMockTransport(lambda _request: httpx.Response(200)), resolver=resolver)
        for resolver in (failed_resolver, empty_resolver, malformed_resolver)
    )

    for fetcher in fetchers:
        with pytest.raises(jwks_httpx._FetchGuardError):  # noqa: SLF001 - assert the private transport boundary failure
            await fetcher.fetch(request)
        await fetcher.aclose()


async def test_httpx_jwks_fetcher_accepts_a_public_literal_without_dns() -> None:
    """Literal public IP endpoints are classified directly instead of resolved again."""

    async def fail_resolution(_host: str, _port: int) -> tuple[str, ...]:
        message = "Literal public IP must not reach DNS"
        raise AssertionError(message)

    fetcher = HttpxJWKSFetcher(
        transport=_RecordingMockTransport(lambda _request: httpx.Response(200, content=b'{"keys":[]}')),
        resolver=fail_resolution,
    )

    response = await fetcher.fetch(JWKSFetchTarget(issuer=_JWT_ISSUER, jwks_uri="https://93.184.216.34/jwks.json"))

    assert response.status_code == 200
    await fetcher.aclose()


async def test_httpx_jwks_fetcher_uses_the_exact_configured_timeout() -> None:
    """The bounded client preserves the configured timeout."""
    fetcher = HttpxJWKSFetcher(timeout=5)

    assert fetcher._client.timeout == httpx.Timeout(5.0)  # noqa: SLF001 - assert the configured client boundary
    await fetcher.aclose()


@pytest.mark.parametrize("timeout", [True, 0, -1, float("inf"), float("nan"), cast("float", "5")])
def test_httpx_jwks_fetcher_rejects_invalid_timeout(timeout: float) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        HttpxJWKSFetcher(timeout=timeout)


@pytest.mark.parametrize("maximum_response_bytes", [False, 0, -1, cast("int", 1.5), cast("int", "1024")])
def test_httpx_jwks_fetcher_rejects_invalid_byte_ceiling(maximum_response_bytes: int) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        HttpxJWKSFetcher(maximum_response_bytes=maximum_response_bytes)
