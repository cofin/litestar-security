"""Application-owned OpenAPI documentation metadata for generated routes.

Every generated route is filed under one tag group. A group is addressed by a
stable key rather than by its display name, so an application that renames a
group keeps addressing it by the same key. Declaration order below is display
order in the emitted document.
"""

from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

from litestar.enums import MediaType
from litestar.exceptions import ImproperlyConfiguredException
from litestar.openapi.datastructures import ResponseSpec
from litestar.openapi.spec import Tag

from litestar_security.schema import ProblemDetail, RouteError

if TYPE_CHECKING:
    from litestar import Router
    from litestar.handlers import BaseRouteHandler
    from litestar.handlers.http_handlers import HTTPRouteHandler

__all__ = (
    "LOCAL_TAG_KEYS",
    "ROUTE_TAGS",
    "RouteDocs",
    "apply_route_docs",
    "converted_denial",
    "describes_raised_denial",
    "merge_route_tags",
    "raised_denial",
    "resolve_tags",
    "restated_denial",
)


def raised_denial(description: str) -> ResponseSpec:
    """Describe a status a generated route raises rather than returns.

    A raised status never reaches the handler's return value, so its body is
    whatever the application's exception handling renders - by default
    Litestar's :class:`RouteError` shape at ``application/json``. Every
    generated route family builds its denial specs here so one edit moves all
    of them together.

    Examples are switched off deliberately. ``ResponseSpec.generate_examples``
    defaults to ``True`` and, unlike the rest of the document, is honored
    regardless of ``OpenAPIConfig.create_examples``; the values it invents are
    random, so leaving it on makes two builds of the same application publish
    different documents.

    Args:
        description: What this status means on the route documenting it.

    Returns:
        One response specification for a raised status.
    """
    return ResponseSpec(RouteError, description=description, media_type=MediaType.JSON, generate_examples=False)


def converted_denial(description: str) -> ResponseSpec:
    """Restate a raised status for an application that converts to problem details.

    Args:
        description: The description carried over from the unconverted spec.

    Returns:
        The same status described as the body and media type Litestar's
        problem-details conversion produces.
    """
    return ResponseSpec(
        ProblemDetail, description=description, media_type="application/problem+json", generate_examples=False
    )


def restated_denial(schema: type[object], media_type: str, description: str) -> ResponseSpec:
    """Restate a raised status using an application-declared error contract.

    Args:
        schema: The body type serialized by application exception handlers.
        media_type: The content type emitted for that body.
        description: The description carried over from the generated route.

    Returns:
        The raised status described by the application's declared contract.
    """
    return ResponseSpec(schema, description=description, media_type=media_type, generate_examples=False)


def describes_raised_denial(spec: ResponseSpec) -> bool:
    """Report whether one specification describes a status the route raises.

    Args:
        spec: The response specification to classify.

    Returns:
        ``True`` when the specification is one :func:`raised_denial` produced,
        which is what makes it eligible for restatement. A specification for a
        status the handler *returns* is never eligible.
    """
    container = cast("Any", spec).data_container
    return container is RouteError


ROUTE_TAGS: Mapping[str, Tag] = MappingProxyType({
    # A reader meets the two ways to log in before the flows that repair an
    # account they cannot log in to.
    "local.sessions": Tag(
        name="Local sessions",
        description=(
            "Cookie-based login for browser clients, plus the caller's own session inventory. "
            "Every route here is scoped to the authenticated caller: there is no administrative view."
        ),
    ),
    "local.tokens": Tag(
        name="Local tokens",
        description=(
            "Bearer login for non-browser clients. Refresh tokens rotate strictly, so replaying a "
            "consumed token revokes its whole family rather than returning a new pair."
        ),
    ),
    "local.registration": Tag(
        name="Local registration",
        description=(
            "Self-service account creation under the configured registration policy. The response is "
            "identical whether or not the identifier was already taken, so it never confirms an account."
        ),
    ),
    "local.passwords": Tag(
        name="Local passwords",
        description=(
            "Password change for an authenticated caller and the recovery flow for one who cannot sign in. "
            "Both raise the account security epoch, which invalidates credentials issued before the change."
        ),
    ),
    "local.verification": Tag(
        name="Local verification",
        description=(
            "Account-verification token issue and consumption. Requesting a token returns the same response "
            "for every identifier, so it never confirms an account."
        ),
    ),
    "mfa": Tag(
        name="Multi-factor authentication",
        description=(
            "Enrollment and removal of time-based codes and recovery codes. Changing how an account is "
            "protected consumes a fresh step-up grant, so a stolen session cannot weaken it silently."
        ),
    ),
    "passkeys": Tag(
        name="Passkeys",
        description=(
            "WebAuthn credential registration and assertion. Each challenge is single-use and bound to the "
            "browser that requested it, and the credential's private key never leaves the authenticator."
        ),
    ),
    "step_up": Tag(
        name="Step-up authentication",
        description=(
            "Re-proof of a strong factor immediately before a sensitive operation. A grant is bound to one "
            "purpose at one security epoch and is consumed on first use, so it cannot be replayed or reused."
        ),
    ),
    "oauth.providers": Tag(
        name="OAuth providers",
        description=(
            "Interactive provider login, account linking, scope upgrades, and token revocation. Every "
            "authorization round trip is bound to a cookie the same browser must present at the callback."
        ),
    ),
    "oidc.logout": Tag(
        name="OIDC logout",
        description=(
            "Provider-initiated front- and back-channel logout. A logout token is verified against the "
            "configured issuer and its identifier is consumed once, so a replayed notification revokes nothing."
        ),
    ),
})


def _no_overrides() -> "dict[str, str]":
    return {}


def _frozen_overrides(values: "Mapping[str, str]", *, subject: str) -> "Mapping[str, str]":
    unknown = sorted(set(values) - set(ROUTE_TAGS))
    if unknown:
        message = f"Unknown generated-route tag group: {', '.join(unknown)}"
        raise ImproperlyConfiguredException(detail=message)
    blank = sorted(key for key, value in values.items() if value.__class__ is not str or not value.strip())
    if blank:
        message = f"Generated-route tag {subject} must be a non-blank string: {', '.join(blank)}"
        raise ImproperlyConfiguredException(detail=message)
    return MappingProxyType(dict(values))


@dataclass(frozen=True, slots=True)
class RouteDocs:
    """Application-owned OpenAPI documentation for generated routes.

    Tag groups are addressed by the stable keys of :data:`ROUTE_TAGS`, never by
    their display names, so an application that renames a group keeps addressing
    it by the key it already used. None of this is security policy: an
    application cannot change what a route requires by documenting it
    differently.
    """

    tags: Mapping[str, str] = field(default_factory=_no_overrides)
    """Replacement display name per stable tag-group key."""
    tag_descriptions: Mapping[str, str] = field(default_factory=_no_overrides)
    """Replacement description per stable tag-group key."""
    operation_id: Callable[[str], str] | None = None
    """Rewrite every generated ``operation_id``, which names the generated client function."""
    route_name: Callable[[str], str] | None = None
    """Rewrite every generated route ``name``, which ``route_reverse`` resolves."""

    def __post_init__(self) -> None:
        """Freeze the supplied mappings and reject an override nothing can apply to.

        Raises:
            ImproperlyConfiguredException: If a key names no generated tag group,
                an override is blank, or a transform is not callable.
        """
        object.__setattr__(self, "tags", _frozen_overrides(self.tags, subject="display name"))
        object.__setattr__(self, "tag_descriptions", _frozen_overrides(self.tag_descriptions, subject="description"))
        for name in ("operation_id", "route_name"):
            transform: object = getattr(self, name)
            if transform is not None and not callable(transform):
                message = f"Generated-route {name} transform must be callable"
                raise ImproperlyConfiguredException(detail=message)


LOCAL_TAG_KEYS: frozenset[str] = frozenset(key for key in ROUTE_TAGS if key.startswith("local."))
"""The tag groups the generated local-auth routes are filed under."""


def resolve_tags(keys: "Iterable[str]", docs: "RouteDocs") -> "tuple[Tag, ...]":
    """Return the effective tags for one feature's groups, in registry order.

    Args:
        keys: The stable keys of the groups the feature's routes are filed under.
        docs: The application's documentation metadata for that feature.

    Returns:
        One tag per distinct effective display name. Two keys renamed to the same
        name deliberately collapse into one group, described by the first of them
        in registry order.
    """
    return merge_route_tags(((keys, docs),))


def merge_route_tags(sources: "Iterable[tuple[Iterable[str], RouteDocs]]") -> "tuple[Tag, ...]":
    """Return the effective tags for every configured feature, in registry order.

    Args:
        sources: The configured groups paired with the metadata that documents them.

    Returns:
        One tag per distinct effective display name, ordered by the registry
        rather than by the order the features were configured in.
    """
    documented: dict[str, RouteDocs] = {}
    for keys, docs in sources:
        for key in keys:
            documented.setdefault(key, docs)
    tags: dict[str, Tag] = {}
    for key, default in ROUTE_TAGS.items():
        if key not in documented:
            continue
        configured = documented[key]
        name = configured.tags.get(key, default.name)
        description = configured.tag_descriptions.get(key, default.description)
        tags.setdefault(
            name,
            default
            if name == default.name and description == default.description
            else Tag(name=name, description=description),
        )
    return tuple(tags.values())


def apply_route_docs(router: "Router", docs: "RouteDocs") -> "Router":
    """Rewrite the documentation metadata of one freshly built generated router.

    Controller tags are class attributes fixed at import, so the effective name is
    resolved here instead: every layer of a freshly built router is private to the
    configuration that built it, and Litestar deep-copies the router again when the
    application registers it.

    Args:
        router: The router the feature just built.
        docs: The application's documentation metadata for that feature.

    Returns:
        The same router.

    Raises:
        ImproperlyConfiguredException: If a transform makes two handlers share an
            operation ID or a route name.
    """
    renames = {ROUTE_TAGS[key].name: name for key, name in docs.tags.items() if ROUTE_TAGS[key].name != name}
    if not renames and docs.operation_id is None and docs.route_name is None:
        return router
    # A handler declaring several paths appears on several routes; identity keeps
    # each one rewritten exactly once, so a transform cannot collide with itself.
    handlers: dict[int, HTTPRouteHandler] = {
        id(handler): handler
        for route in router.routes
        for handler in cast("tuple[HTTPRouteHandler, ...]", getattr(route, "route_handlers", ()))
    }
    retagged: set[int] = set()
    operation_ids: set[str] = set()
    route_names: set[str] = set()
    for handler in handlers.values():
        for layer in _documentation_layers(handler, router):
            if id(layer) in retagged:
                continue
            retagged.add(id(layer))
            layer.tags = _renamed(layer.tags, renames)
        # Litestar also accepts a callable operation-id factory; every generated
        # handler declares a literal, which is what a transform is given.
        handler.operation_id = _transformed(
            cast("str | None", handler.operation_id), docs.operation_id, operation_ids, subject="operation_id"
        )
        handler.name = _transformed(handler.name, docs.route_name, route_names, subject="route name")
    return router


def _renamed(tags: "Sequence[str] | None", renames: "Mapping[str, str]") -> "tuple[str, ...] | None":
    return None if tags is None else tuple(renames.get(tag, tag) for tag in tags)


def _transformed(
    value: "str | None", transform: "Callable[[str], str] | None", seen: "set[str]", *, subject: str
) -> "str | None":
    if value is None:
        return None
    resolved = value if transform is None else transform(value)
    if resolved in seen:
        message = f"Generated routes resolve to a duplicate {subject}: {resolved}"
        raise ImproperlyConfiguredException(detail=message)
    seen.add(resolved)
    return resolved


def _documentation_layers(handler: "BaseRouteHandler", router: "Router") -> "Iterator[Any]":
    """Yield every ownership layer from one handler up to the router that owns it.

    Litestar unions tags up the ownership chain, and a controller contributes its
    class-level tags as an intermediate router, so renaming a group means visiting
    every layer rather than the handler alone.
    """
    layer: Any = handler
    while layer is not router:
        yield layer
        layer = layer.owner
    yield router
