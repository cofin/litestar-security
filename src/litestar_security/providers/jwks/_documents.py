"""Parsing and validation of remote JWKS documents.

A document is fully validated into an immutable entry before it can replace a live
snapshot, which is what keeps a malformed refresh from evicting good keys.
"""

import json
from collections.abc import Mapping
from types import MappingProxyType
from typing import TypeAlias, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jwt import PyJWK

from litestar_security.providers._internal import JSONValue, reject_non_finite, unique_object, validate_depth
from litestar_security.providers.jwks._cache import JWKSCacheEntry, JWKSCachePolicy
from litestar_security.providers.jwks._internal import valid_selection_value
from litestar_security.providers.jwt import JWTAlgorithm, VerificationKey

_SelectionKey: TypeAlias = tuple[str, str]


_MAXIMUM_JSON_DEPTH = 64


_SUPPORTED_REMOTE_ALGORITHMS = frozenset({"EdDSA", "ES256", "RS256"})


_PRIVATE_JWK_MEMBERS = frozenset({"d", "dp", "dq", "k", "oth", "p", "q", "qi"})


def parse_document(
    body: bytes, entry: JWKSCacheEntry, policy: JWKSCachePolicy
) -> Mapping[_SelectionKey, VerificationKey]:
    if len(body) > policy.maximum_document_bytes:
        raise ValueError
    decoded = cast("object", json.loads(body, object_pairs_hook=unique_object, parse_constant=reject_non_finite))
    if not isinstance(decoded, dict):
        raise TypeError
    document = cast("dict[str, object]", decoded)
    validate_depth(cast("JSONValue", document), maximum=_MAXIMUM_JSON_DEPTH)
    raw_keys: object = document.get("keys")
    if not isinstance(raw_keys, list) or not raw_keys:
        raise ValueError
    raw_key_values = cast("list[object]", raw_keys)
    if len(raw_key_values) > policy.maximum_keys:
        raise ValueError
    keys: dict[_SelectionKey, VerificationKey] = {}
    for raw_key in raw_key_values:
        if not isinstance(raw_key, Mapping):
            raise TypeError
        key = _parse_key(cast("Mapping[str, JSONValue]", raw_key), entry)
        selection = (key.key_id, key.algorithm)
        if selection in keys:
            raise ValueError
        keys[selection] = key
    return MappingProxyType(keys)


def _parse_key(value: Mapping[str, JSONValue], entry: JWKSCacheEntry) -> VerificationKey:
    if _PRIVATE_JWK_MEMBERS.intersection(value):
        raise ValueError
    algorithm = value.get("alg")
    key_id = value.get("kid")
    if (
        not isinstance(algorithm, str)
        or algorithm not in entry.algorithms
        or algorithm not in _SUPPORTED_REMOTE_ALGORITHMS
        or not isinstance(key_id, str)
        or not valid_selection_value(key_id)
        or value.get("use") not in {None, "sig"}
    ):
        raise ValueError
    key_ops = value.get("key_ops")
    if key_ops is not None and (
        not isinstance(key_ops, list)
        or "verify" not in key_ops
        or any(not isinstance(operation, str) for operation in cast("list[object]", key_ops))
    ):
        raise ValueError
    canonical = dict(value)
    canonical["alg"] = algorithm
    canonical["kid"] = key_id
    canonical["use"] = "sig"
    canonical["key_ops"] = ["verify"]
    pyjwk = PyJWK.from_dict(cast("dict[str, object]", canonical), algorithm=algorithm)
    prepared = pyjwk.key
    if not isinstance(prepared, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey)):
        raise TypeError
    pem = prepared.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return VerificationKey(key_id=key_id, algorithm=cast("JWTAlgorithm", algorithm), key=pem, public_jwk=canonical)
