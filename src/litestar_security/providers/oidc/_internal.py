"""Discovery errors and bounded JSON loading local to OIDC.

Discovery failures are their own error type so that a caller can distinguish a
misconfigured issuer from an unreachable one without inspecting messages.
"""

import json
import math
from typing import NoReturn, TypeAlias, cast

from litestar_security.providers._internal import JSONValue, reject_non_finite, unique_object, validate_depth

__all__ = ("OIDCDiscoveryError",)

JSONObject: TypeAlias = dict[str, object]
_MAXIMUM_JSON_DEPTH = 64


def raise_discovery(detail: str) -> NoReturn:
    raise OIDCDiscoveryError(detail) from None


class OIDCDiscoveryError(RuntimeError):
    """Sanitized operational or remote-metadata discovery failure."""


def load_document(value: bytes) -> JSONObject:
    decoded = json.loads(value, object_pairs_hook=unique_object, parse_constant=reject_non_finite)
    if not isinstance(decoded, dict):
        raise TypeError
    validate_depth(cast("JSONValue", decoded), maximum=_MAXIMUM_JSON_DEPTH)
    return cast("JSONObject", decoded)


def positive_finite(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0
