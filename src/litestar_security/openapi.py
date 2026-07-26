"""Compile route security policy for runtime and native OpenAPI projection."""

# The compiler is the sole package-internal consumer of the closed policy AST.

from dataclasses import dataclass, field
from itertools import combinations
from typing import Generic, TypeVar, cast

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.authentication import (
    AuthenticationPolicy,
    AuthenticationRegistry,
    MechanismRequirement,
    SecurityRuntimePlan,
    _MechanismPolicy,  # pyright: ignore[reportPrivateUsage]
    _OptionalPolicy,  # pyright: ignore[reportPrivateUsage]
    _PublicPolicy,  # pyright: ignore[reportPrivateUsage]
    mechanism,
)

__all__ = ("PolicyCompiler",)

UserT = TypeVar("UserT")


@dataclass(slots=True)
class PolicyCompiler(Generic[UserT]):
    """Compile and cache policy plans for one immutable mechanism registry."""

    registry: AuthenticationRegistry[UserT]
    _cache: dict[tuple[AuthenticationPolicy, bool | None], SecurityRuntimePlan] = field(
        init=False, default_factory=dict[tuple[AuthenticationPolicy, bool | None], SecurityRuntimePlan], repr=False
    )
    _canonical_plans: dict[SecurityRuntimePlan, SecurityRuntimePlan] = field(
        init=False, default_factory=dict[SecurityRuntimePlan, SecurityRuntimePlan], repr=False
    )

    def compile(self, policy: AuthenticationPolicy, *, csrf_required: bool | None = None) -> SecurityRuntimePlan:
        """Return the identity-stable plan for a normalized policy."""
        key = (policy, csrf_required)
        if cached := self._cache.get(key):
            return cached
        plan = self._compile(policy, csrf_required=csrf_required)
        plan = self._canonical_plans.setdefault(plan, plan)
        self._cache[key] = plan
        return plan

    def _compile(self, policy: AuthenticationPolicy, *, csrf_required: bool | None) -> SecurityRuntimePlan:
        if isinstance(policy, _PublicPolicy):
            return SecurityRuntimePlan(authenticate=False, csrf_required=csrf_required)
        if isinstance(policy, _OptionalPolicy):
            allow_anonymous = True
            expression = policy.policy
        else:
            allow_anonymous = False
            expression = policy
        if not isinstance(expression, _MechanismPolicy):
            message = "Authentication policy must be created by a Litestar Security policy helper"
            raise ImproperlyConfiguredException(detail=message)
        requirements = self._requirements(expression)
        alternatives: tuple[tuple[MechanismRequirement, ...], ...]
        if expression.operator == "any_of":
            alternatives = tuple((requirement,) for requirement in requirements)
        elif expression.operator == "all_of":
            alternatives = (requirements,)
        else:
            count = cast("int", expression.count)
            alternatives = tuple(combinations(requirements, count))
        return SecurityRuntimePlan(
            authenticate=True,
            required=not allow_anonymous,
            alternatives=alternatives,
            allow_anonymous=allow_anonymous,
            csrf_required=csrf_required,
        )

    def _requirements(self, policy: _MechanismPolicy) -> tuple[MechanismRequirement, ...]:
        if policy.implicit:
            if not self.registry.default_mechanism_names:
                message = "Implicit required authentication needs at least one default-participating mechanism"
                raise ImproperlyConfiguredException(detail=message)
            return tuple(mechanism(name) for name in self.registry.default_mechanism_names)

        by_name = {requirement.name: requirement for requirement in policy.requirements}
        undefined = tuple(name for name in by_name if name not in self.registry.mechanism_names)
        if undefined:
            message = f"Policy references undefined authentication mechanism: {undefined[0]}"
            raise ImproperlyConfiguredException(detail=message)
        return tuple(by_name[name] for name in self.registry.mechanism_names if name in by_name)
