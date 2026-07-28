"""Unit tests for browser response security headers."""

from __future__ import annotations

from types import MappingProxyType

import pytest
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.headers import ContentSecurityPolicy, CSPMode, SecurityHeadersConfig


def test_csp_serializes_deterministically_with_empty_and_report_directives() -> None:
    policy = ContentSecurityPolicy(
        mode=CSPMode.REPORT_ONLY,
        directives={
            "script-src": ("https://cdn.example", "'self'"),
            "upgrade-insecure-requests": (),
            "report-uri": ("/csp-report",),
            "default-src": ("'none'",),
        },
    )

    assert policy.header_name == "Content-Security-Policy-Report-Only"
    assert policy.serialize() == (
        "default-src 'none'; report-uri /csp-report; "
        "script-src https://cdn.example 'self'; upgrade-insecure-requests"
    )


@pytest.mark.parametrize(
    ("directives", "nonce_directives"),
    [
        ({"default_src": ("'self'",)}, ()),
        ({"default-src\r\nx-owned": ("'self'",)}, ()),
        ({"default-src": ("'self'\nX-Owned: yes",)}, ()),
        ({"default-src": ("'self'; script-src *",)}, ()),
        ({"default-src": ("'self'",)}, ("script_src",)),
        ({"default-src": ("'self'",)}, ("script-src",)),
    ],
)
def test_csp_rejects_unsafe_or_inconsistent_configuration(
    directives: dict[str, tuple[str, ...]], nonce_directives: tuple[str, ...]
) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        ContentSecurityPolicy(directives=directives, nonce_directives=nonce_directives)


def test_security_headers_freeze_input_and_reject_csp_collisions() -> None:
    configured = {"X-Content-Type-Options": "nosniff"}
    headers = SecurityHeadersConfig(static=configured)
    configured["X-Content-Type-Options"] = "unsafe"

    assert headers.static == MappingProxyType({"X-Content-Type-Options": "nosniff"})

    policy = ContentSecurityPolicy(directives={"default-src": ("'self'",)})
    with pytest.raises(ImproperlyConfiguredException):
        SecurityHeadersConfig(static={"Content-Security-Policy": "default-src *"}, csp=policy)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("X Bad", "value"),
        ("X-Owned\r\n", "value"),
        ("X-Owned", "value\ninjected"),
    ],
)
def test_security_headers_reject_invalid_names_and_values(name: str, value: str) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        SecurityHeadersConfig(static={name: value})
