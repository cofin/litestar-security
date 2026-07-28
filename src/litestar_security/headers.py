"""Opt-in browser response security headers for Litestar applications."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from secrets import token_urlsafe
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, TypeAlias, cast

from litestar.datastructures import ResponseHeader
from litestar.di import NamedDependency, Provide
from litestar.exceptions import ImproperlyConfiguredException
from litestar.types import Message, Scope

if TYPE_CHECKING:
    from litestar.config.app import AppConfig

__all__ = ("CSPMode", "ContentSecurityPolicy", "SecurityHeadersConfig", "csp_nonce")

_DIRECTIVE_TOKEN = re.compile(r"^[a-z][a-z0-9-]*$")
_HEADER_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_NONCE_SCOPE_KEY = "litestar_security.csp_nonce"
_ASCII_CONTROL_LIMIT = 32
_ASCII_DELETE = 127

csp_nonce: TypeAlias = NamedDependency[str]  # noqa: PYI042 - stable dependency name intentionally matches its DI key
CSPHook: TypeAlias = Callable[[Message, Scope], Awaitable[None]]


class CSPMode(str, Enum):
    """Select the browser CSP response-header mode."""

    ENFORCE = "enforce"
    REPORT_ONLY = "report-only"


@dataclass(frozen=True, slots=True)
class ContentSecurityPolicy:
    """Define one explicit Content Security Policy.

    Args:
        mode: Whether the policy enforces or only reports violations.
        directives: Explicit directive names and their ordered source values.
        nonce_directives: Directives that receive the response-local nonce.

    Raises:
        ImproperlyConfiguredException: If a directive or source is unsafe, or
            a nonce directive is absent from ``directives``.
    """

    directives: Mapping[str, Sequence[str]]
    mode: CSPMode = CSPMode.ENFORCE
    nonce_directives: Sequence[str] = ()

    def __post_init__(self) -> None:
        """Validate and freeze the policy."""
        mode = cast("object", self.mode)
        if not isinstance(mode, CSPMode):
            message = "CSP mode must be a CSPMode"
            raise ImproperlyConfiguredException(detail=message)
        normalized: dict[str, tuple[str, ...]] = {}
        for name, sources in self.directives.items():
            _validate_directive(name)
            values: list[str] = []
            for source in sources:
                _validate_source(source)
                if source not in values:
                    values.append(source)
            normalized[name] = tuple(values)
        nonce_directives = tuple(dict.fromkeys(self.nonce_directives))
        for name in nonce_directives:
            _validate_directive(name)
            if name not in normalized:
                message = f"CSP nonce directive {name!r} must also be configured"
                raise ImproperlyConfiguredException(detail=message)
        object.__setattr__(self, "directives", MappingProxyType(dict(sorted(normalized.items()))))
        object.__setattr__(self, "nonce_directives", nonce_directives)

    @property
    def header_name(self) -> str:
        """Return the standard header name for this policy.

        Returns:
            The enforcing or report-only CSP header name.
        """
        if self.mode is CSPMode.REPORT_ONLY:
            return "Content-Security-Policy-Report-Only"
        return "Content-Security-Policy"

    def serialize(self, *, nonce: str | None = None) -> str:
        """Serialize the policy deterministically.

        Args:
            nonce: Response-local nonce to append to configured directives.

        Returns:
            A CSP header value.

        Raises:
            ImproperlyConfiguredException: If nonce directives exist but no
                response nonce was supplied.
        """
        if self.nonce_directives and nonce is None:
            message = "Nonce-enabled CSP serialization requires a response nonce"
            raise ImproperlyConfiguredException(detail=message)
        serialized: list[str] = []
        for name, sources in self.directives.items():
            values = list(sources)
            if name in self.nonce_directives:
                values.append(f"'nonce-{nonce}'")
            serialized.append(" ".join((name, *values)))
        return "; ".join(serialized)


@dataclass(frozen=True, slots=True)
class SecurityHeadersConfig:
    """Configure native static response headers and optional CSP.

    Args:
        static: Application-owned static security header values.
        csp: Optional explicit Content Security Policy.

    Raises:
        ImproperlyConfiguredException: If names or values are unsafe, or a
            configured CSP header conflicts with ``csp``.
    """

    static: Mapping[str, str] = field(default_factory=lambda: cast("Mapping[str, str]", {}))
    csp: ContentSecurityPolicy | None = None

    def __post_init__(self) -> None:
        """Validate and freeze header configuration."""
        normalized: dict[str, str] = {}
        seen: dict[str, str] = {}
        for name, value in self.static.items():
            _validate_header(name, value)
            lower_name = name.lower()
            existing_name = seen.get(lower_name)
            if existing_name is not None and normalized[existing_name] != value:
                message = f"Conflicting static response header {name!r}"
                raise ImproperlyConfiguredException(detail=message)
            if existing_name is None:
                seen[lower_name] = name
                normalized[name] = value
        if self.csp is not None:
            csp_name = self.csp.header_name.lower()
            existing_name = seen.get(csp_name)
            if existing_name is not None:
                if self.csp.nonce_directives or normalized[existing_name] != self.csp.serialize():
                    message = f"Static response header conflicts with configured {self.csp.header_name}"
                    raise ImproperlyConfiguredException(detail=message)
                normalized.pop(existing_name)
        object.__setattr__(self, "static", MappingProxyType(normalized))


def configure_security_headers(
    app_config: AppConfig, config: SecurityHeadersConfig, hook: CSPHook | None = None
) -> CSPHook | None:
    """Install validated headers through native Litestar configuration.

    Args:
        app_config: Application configuration being initialized.
        config: Validated security-header configuration.
        hook: Previously created hook when initialization is repeated.

    Returns:
        The nonce hook when dynamic CSP is configured, otherwise ``None``.

    Raises:
        ImproperlyConfiguredException: If application-owned headers or
            dependencies collide with this integration.
    """
    static = dict(config.static)
    csp = config.csp
    if csp is not None and not csp.nonce_directives:
        static[csp.header_name] = csp.serialize()
    _merge_native_headers(app_config, static)
    if csp is None or not csp.nonce_directives:
        return None
    existing_dependency = app_config.dependencies.get("csp_nonce")
    if existing_dependency is not None:
        message = "Application config already owns the reserved 'csp_nonce' dependency"
        raise ImproperlyConfiguredException(detail=message)
    app_config.dependencies["csp_nonce"] = Provide(_provide_csp_nonce, sync_to_thread=False, use_cache=False)
    app_config.signature_namespace.setdefault("csp_nonce", csp_nonce)
    nonce_hook = hook if hook is not None else _create_csp_hook(csp)
    if nonce_hook not in app_config.before_send:
        app_config.before_send.append(nonce_hook)
    return nonce_hook


def _provide_csp_nonce(scope: Scope) -> str:
    return _scope_nonce(scope)


def _scope_nonce(scope: Scope) -> str:
    state = cast("dict[str, Any]", scope)
    nonce = state.get(_NONCE_SCOPE_KEY)
    if nonce is None:
        nonce = token_urlsafe(16)
        state[_NONCE_SCOPE_KEY] = nonce
    return cast("str", nonce)


def _create_csp_hook(policy: ContentSecurityPolicy) -> CSPHook:
    async def add_csp_header(message: Message, scope: Scope) -> None:
        if message["type"] != "http.response.start":
            return
        value = policy.serialize(nonce=_scope_nonce(scope)).encode("latin-1")
        expected_name = policy.header_name.lower().encode("ascii")
        headers = cast("list[tuple[bytes, bytes]]", message.setdefault("headers", []))
        matches = [index for index, (name, _) in enumerate(headers) if name.lower() == expected_name]
        if matches:
            if any(headers[index][1] != value for index in matches):
                message_text = f"Dynamic response contains a conflicting {policy.header_name} header"
                raise ImproperlyConfiguredException(detail=message_text)
            for index in reversed(matches[1:]):
                headers.pop(index)
            return
        headers.append((expected_name, value))

    return add_csp_header


def _merge_native_headers(app_config: AppConfig, configured: Mapping[str, str]) -> None:
    current = app_config.response_headers
    headers = (
        [ResponseHeader(name=name, value=value) for name, value in current.items()]
        if isinstance(current, Mapping)
        else list(current)
    )
    by_name = {header.name.lower(): header for header in headers}
    for name, value in configured.items():
        existing = by_name.get(name.lower())
        if existing is not None:
            if existing.value != value:
                message = f"Application response header conflicts with configured {name}"
                raise ImproperlyConfiguredException(detail=message)
            continue
        header = ResponseHeader(name=name, value=value)
        headers.append(header)
        by_name[name.lower()] = header
    app_config.response_headers = headers


def _validate_directive(name: object) -> None:
    if not isinstance(name, str) or _DIRECTIVE_TOKEN.fullmatch(name) is None:
        message = f"Invalid CSP directive name {name!r}"
        raise ImproperlyConfiguredException(detail=message)


def _validate_source(source: object) -> None:
    if (
        not isinstance(source, str)
        or not source
        or ";" in source
        or any(
            character.isspace() or ord(character) < _ASCII_CONTROL_LIMIT or ord(character) == _ASCII_DELETE
            for character in source
        )
    ):
        message = f"Invalid CSP source value {source!r}"
        raise ImproperlyConfiguredException(detail=message)


def _validate_header(name: object, value: object) -> None:
    if not isinstance(name, str) or _HEADER_TOKEN.fullmatch(name) is None:
        message = f"Invalid response header name {name!r}"
        raise ImproperlyConfiguredException(detail=message)
    if not isinstance(value, str) or any(
        ord(character) < _ASCII_CONTROL_LIMIT or ord(character) == _ASCII_DELETE for character in value
    ):
        message = f"Invalid response header value for {name!r}"
        raise ImproperlyConfiguredException(detail=message)
