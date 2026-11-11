"""HTTPX-backed bounded transport for exact configured JWKS sources."""

from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from litestar_security.providers._internal import (
    AddressResolutionError,
    AddressResolutionReason,
    AddressResolver,
    BoundedBodyError,
    positive_finite,
    raise_config,
    read_bounded_body,
    resolve_addresses,
    resolve_public_addresses,
)
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
_ADDRESS_ERROR_MESSAGES: dict[AddressResolutionReason, str] = {
    "unavailable": _HOST_RESOLUTION_UNAVAILABLE,
    "empty": _NO_RESOLVED_ADDRESSES,
    "invalid": _INVALID_RESOLVED_ADDRESS,
    "non_public": _NON_PUBLIC_RESOLVED_ADDRESS,
}


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
        if not positive_finite(self.timeout):
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
            try:
                body = await read_bounded_body(response, self.maximum_response_bytes)
            except BoundedBodyError as exc:
                message = _UNSUPPORTED_CONTENT_ENCODING if exc.reason == "unsupported_encoding" else _RESPONSE_TOO_LARGE
                raise _FetchGuardError(message) from exc
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
            await resolve_public_addresses(host, port, resolver=self._resolve)
        except AddressResolutionError as exc:
            raise _FetchGuardError(_ADDRESS_ERROR_MESSAGES[exc.reason]) from exc

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
