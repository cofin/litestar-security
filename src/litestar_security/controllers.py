"""Typed controller base classes that populate the authentication policy opt key."""

from collections.abc import Mapping
from typing import ClassVar, cast

from litestar import Controller
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.authentication import AUTH_POLICY_OPT_KEY, AuthenticationPolicy, public, required

__all__ = ("PublicController", "SecureController")


class SecureController(Controller):
    """Controller base whose typed ``auth`` attribute compiles into ``opt``."""

    auth: ClassVar[AuthenticationPolicy] = required()

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Merge the resolved ``auth`` policy into this subclass's ``opt``.

        Args:
            **kwargs: Forwarded to the next class in the MRO.

        Raises:
            ImproperlyConfiguredException: If this class's own body also declares an
                ``opt`` mapping containing an ``"auth"`` key.
        """
        super().__init_subclass__(**kwargs)
        declared_opt = cls.__dict__.get("opt")
        if isinstance(declared_opt, Mapping) and AUTH_POLICY_OPT_KEY in declared_opt:
            message = (
                f"{cls.__name__} declares both the typed 'auth' attribute and its own "
                f"opt[{AUTH_POLICY_OPT_KEY!r}]; remove one"
            )
            raise ImproperlyConfiguredException(detail=message)
        inherited_opt = cls.opt
        opt_base: Mapping[str, object] = (
            cast("Mapping[str, object]", inherited_opt) if isinstance(inherited_opt, Mapping) else {}
        )
        cls.opt = {**opt_base, AUTH_POLICY_OPT_KEY: cls.auth}


class PublicController(SecureController):
    """``SecureController`` whose default policy skips authentication."""

    auth: ClassVar[AuthenticationPolicy] = public()
