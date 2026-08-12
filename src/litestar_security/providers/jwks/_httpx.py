"""HTTPX-backed bounded transport for exact configured JWKS sources."""

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass, field
from math import isfinite
from urllib.parse import urlsplit

import httpx

from litestar_security.providers._internal import AddressResolver, public_address, raise_config, resolve_addresses
from litestar_security.providers.jwks._fetching import JWKSFetchOutcome, JWKSFetchTarget

__all__ = ("HttpxJWKSFetcher",)


_HOST_RESOLUTION_UNAVAILABLE = "JWKS host resolution unavailable"
_RESPONSE_TOO_LARGE = "JWKS response exceeds the configured byte limit"
_NO_RESOLVED_ADDRESSES = "JWKS host resolution returned no addresses"
_INVALID_RESOLVED_ADDRESS = "JWKS host resolution returned an invalid address"
_NON_PUBLIC_RESOLVED_ADDRESS = "JWKS host resolved outside the public network boundary"
_INVALID_URL = "JWKS URI must be an absolute HTTPS URL"
_UNSUPPORTED_CONTENT_ENCODING = "JWKS response encoding is not allowed"
_DEFAULT_HTTPS_PORT = 443


@dataclass(slots=True)
class HttpxJWKSFetcher:
    """HTTPX-backed async fetcher for operator-configured JWKS endpoints."""

    timeout: float = 5.0
    maximum_response_bytes: int = 1_048_576
    allow_private_hosts: bool = False
    transport: httpx.AsyncBaseTransport | None = None
    resolver: AddressResolver | None = None
    _client: httpx.AsyncClient = field(init=False, repr=False)
    _closed: bool = field(init=False, default=False, repr=False)
    _resolve: AddressResolver = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate resource limits and construct the owned HTTP client."""
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime configuration boundary
            or not isfinite(self.timeout)
            or self.timeout <= 0
        ):
            raise_config("JWKS HTTPX timeout must be finite and positive")
        if (
            isinstance(self.maximum_response_bytes, bool)
            or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime configuration boundary
                self.maximum_response_bytes, int
            )
            or self.maximum_response_bytes <= 0
        ):
            raise_config("JWKS HTTPX maximum_response_bytes must be a positive integer")
        self._resolve = self.resolver or resolve_addresses
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(float(self.timeout)),
            transport=self.transport,
            trust_env=False,
        )

    async def fetch(self, request: JWKSFetchTarget) -> JWKSFetchOutcome:
        """Return one bounded response without following redirects.

        Args:
            request: The exact configured JWKS URI and optional ETag condition.

        Returns:
            The bounded transport response, including un-followed redirect status
            codes for the provider to reject.

        Raises:
            _FetchGuardError: If the configured URI or host fails its network
                boundary, the response is encoded, or it exceeds its byte ceiling.
            httpx.HTTPError: If the outbound request fails. Any exception raised
                here becomes ``VerificationUnavailable`` at the JWKS provider.
        """
        await self._guard_host(request.jwks_uri)
        headers = {"accept-encoding": "identity"}
        if request.etag is not None:
            headers["if-none-match"] = request.etag
        async with self._client.stream("GET", request.jwks_uri, headers=headers) as response:
            body = await self._read_bounded_body(response)
            return JWKSFetchOutcome(status_code=response.status_code, body=body, headers=dict(response.headers))

    async def aclose(self) -> None:
        """Close the owned HTTP client idempotently.

        Returns:
            None.
        """
        if not self._closed:
            self._closed = True
            await self._client.aclose()

    async def _guard_host(self, url: str) -> None:
        parsed = self._parse_url(url)
        if self.allow_private_hosts:
            return
        host = parsed.host
        port = parsed.port or _DEFAULT_HTTPS_PORT
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            try:
                addresses = tuple(await self._resolve(host, port))
            except (OSError, RuntimeError) as exc:
                raise _FetchGuardError(_HOST_RESOLUTION_UNAVAILABLE) from exc
        else:
            addresses = (str(literal),)
        self._validate_resolved_addresses(addresses)

    async def _read_bounded_body(self, response: httpx.Response) -> bytes:
        content_encoding = response.headers.get("content-encoding", "identity").strip().lower()
        if content_encoding not in {"", "identity"}:
            raise _FetchGuardError(_UNSUPPORTED_CONTENT_ENCODING)
        body = bytearray()
        async for chunk in response.aiter_bytes():
            if len(chunk) > self.maximum_response_bytes - len(body):
                raise _FetchGuardError(_RESPONSE_TOO_LARGE)
            body.extend(chunk)
        return bytes(body)

    @staticmethod
    def _validate_resolved_addresses(addresses: Sequence[str]) -> None:
        if not addresses:
            raise _FetchGuardError(_NO_RESOLVED_ADDRESSES)
        try:
            parsed = tuple(ipaddress.ip_address(address) for address in addresses)
        except ValueError as exc:
            raise _FetchGuardError(_INVALID_RESOLVED_ADDRESS) from exc
        if any(not public_address(address) for address in parsed):
            raise _FetchGuardError(_NON_PUBLIC_RESOLVED_ADDRESS)

    @staticmethod
    def _parse_url(value: str) -> httpx.URL:
        if (
            not isinstance(value, str)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime request boundary
            or not value
            or value != value.strip()
        ):
            raise _FetchGuardError(_INVALID_URL)
        try:
            split = urlsplit(value)
            url = httpx.URL(value)
        except (TypeError, ValueError, httpx.InvalidURL) as exc:
            raise _FetchGuardError(_INVALID_URL) from exc
        if (
            split.scheme.lower() != "https"
            or not split.netloc
            or split.username is not None
            or split.password is not None
            or split.fragment
            or not url.host
        ):
            raise _FetchGuardError(_INVALID_URL)
        return url


class _FetchGuardError(Exception):
    """Sanitized outbound JWKS boundary failure."""
