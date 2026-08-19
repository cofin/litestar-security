"""CLI commands for Litestar Security."""

from typing import TYPE_CHECKING, Any, cast

import click
from litestar.routes import HTTPRoute

from litestar_security.__metadata__ import __project__, __version__
from litestar_security._internal import RUNTIME_PLAN_OPT_KEY
from litestar_security.authentication import is_generated_options_handler
from litestar_security.guards import AuthorizationPredicate

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from click import Group
    from litestar import Litestar
    from litestar.handlers.base import BaseRouteHandler
    from litestar.routes import BaseRoute

    from litestar_security.authentication import SecurityRuntimePlan

__all__ = ("register", "routes_command", "security_group")


@click.group(name="security", help="Litestar Security operations.", no_args_is_help=True)
@click.version_option(version=__version__, prog_name=__project__)
def security_group() -> None:
    """Manage Litestar Security integrations."""


def _policy_name(plan: "SecurityRuntimePlan | None") -> str:
    if plan is None:
        return "unknown"
    if plan.bypass_authentication:
        return "exclude"
    if not plan.authenticate:
        return "public"
    return "optional" if plan.allow_anonymous else "required"


def _inherited_guards(route_handler: "BaseRouteHandler") -> tuple[str, ...]:
    """Name every guard the handler inherits, security predicates and plain callables alike.

    Ownership is read from the layers rather than ``resolve_guards()``, which
    wraps each guard in ``ensure_async_callable`` and erases the type.
    """
    # A security predicate is a frozen dataclass whose repr names the grant it
    # checks, which is what makes the column actionable.
    return tuple(
        repr(guard) if isinstance(guard, AuthorizationPredicate) else getattr(guard, "__name__", type(guard).__name__)
        for layer in route_handler.ownership_layers
        for guard in cast("Sequence[object]", getattr(layer, "guards", None) or ())
    )


def _handlers(route: "BaseRoute") -> "list[tuple[str, BaseRouteHandler]]":
    """Pair each route with its handlers, keyed by method or scope type.

    ``route.route_handlers`` ordering is not stable, so HTTP handlers are read
    through the method map instead of by index.
    """
    if isinstance(route, HTTPRoute):
        handler_map = cast("Mapping[str, Any]", route.route_handler_map)
        # Litestar generates an OPTIONS handler per route. It is never an
        # application route and is always unauthenticated, so listing it would
        # double the table and imply a posture nobody declared.
        return [
            (method, handler_map[method][0])
            for method in sorted(handler_map)
            if not is_generated_options_handler(handler_map[method][0].fn)
        ]
    handler = getattr(route, "route_handler", None)
    return [(route.scope_type.value, cast("BaseRouteHandler", handler))] if handler is not None else []


@security_group.command(name="routes")
def routes_command(app: "Litestar") -> None:
    """Display the compiled security posture of every registered route.

    ``app`` is supplied by Litestar. This group is published as a
    ``litestar.commands`` entry point, so the root CLI group wraps its
    subcommands and injects the application. Litestar's CLI helpers are
    imported inside the body rather than at module scope, because importing
    them there would close a cycle: ``litestar.cli`` loads its entry points,
    which include this module.
    """
    from litestar.cli._utils import console  # noqa: PLC0415 - deferred to break an import cycle
    from rich.table import Table  # noqa: PLC0415 - the renderer loads only when the command runs

    table = Table(title="Litestar Security route posture", header_style="bold")
    for column in ("Path", "Method", "Policy", "Auth", "CSRF", "Guards"):
        table.add_column(column)

    excluded = 0
    excluded_with_guards = 0
    total = 0
    for route in sorted(app.routes, key=lambda value: value.path):
        for method, route_handler in _handlers(route):
            total += 1
            plan = cast("SecurityRuntimePlan | None", route_handler.opt.get(RUNTIME_PLAN_OPT_KEY))
            policy = _policy_name(plan)
            guards = _inherited_guards(route_handler)
            if policy == "exclude":
                excluded += 1
                if guards:
                    excluded_with_guards += 1
            guard_text = (
                f"{len(guards)} inherited (still denied)"
                if policy == "exclude" and guards
                else (", ".join(guards) if guards else "-")
            )
            table.add_row(
                route.path,
                method,
                policy,
                "yes" if plan is not None and plan.authenticate else "no",
                (plan.csrf_enforcement if plan is not None and plan.csrf_enforcement else "-"),
                guard_text,
            )

    console.print(table)
    console.print(f"{total} routes, {excluded} excluded")
    if excluded_with_guards:
        console.print(
            f"{excluded_with_guards} excluded route{'s' if excluded_with_guards != 1 else ''} "
            "carries inherited guards that still deny it. Guards are cumulative in Litestar and no layer can "
            "un-inherit one; scope them to the routers that need them."
        )


def register(cli: "Group") -> None:
    """Attach the security command group to a Click group once.

    Args:
        cli: The Click group to attach to. Calling this repeatedly is safe.
    """
    if security_group.name not in cli.commands:
        cli.add_command(security_group)
