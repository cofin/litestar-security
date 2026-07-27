"""Signing and verification key material and its canonical public JWK form.

Key preparation is separated from the key ring so that publishing a JWKS document
cannot accidentally reach private members: only the canonical public fields are
reachable from the prepared JWK types below.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal, TypeAlias, TypedDict, cast

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jwt import PyJWK
from jwt.exceptions import PyJWTError
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.providers._internal import JSONValue, raise_config
from litestar_security.providers.jwt._claims import JWTAlgorithm
from litestar_security.providers.jwt._internal import freeze_json, reject, strict_key_id

__all__ = ("SigningKey", "VerificationKey")


VerificationKeyInput: TypeAlias = bytes | str | PyJWK | Mapping[str, JSONValue]


PreparedVerificationKey: TypeAlias = (
    bytes | str | PyJWK | rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey
)


PreparedSigningKey: TypeAlias = bytes | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey


_SUPPORTED_ALGORITHMS = frozenset({"EdDSA", "ES256", "RS256", "HS256"})


_PRIVATE_JWK_MEMBERS = frozenset({"d", "dp", "dq", "k", "oth", "p", "q", "qi"})


_MINIMUM_HMAC_BYTES = 32


_MINIMUM_RSA_BITS = 2048


@dataclass(frozen=True, slots=True)
class SigningKey:
    """One explicit local signing key and its public verification metadata."""

    key_id: str
    algorithm: JWTAlgorithm
    private_key: bytes = field(repr=False)
    public_jwk: Mapping[str, JSONValue] | None = None
    _prepared_key: PreparedSigningKey = field(init=False, repr=False, compare=False)
    _verification_key: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate key strength, purpose, and public/private correspondence."""
        key_id = strict_key_id(self.key_id)
        prepared, verification_key = _prepare_signing_material(self.private_key, self.algorithm)
        public_jwk = _prepare_public_jwk(self.public_jwk, prepared, self.algorithm, key_id)
        object.__setattr__(self, "key_id", key_id)
        object.__setattr__(self, "public_jwk", public_jwk)
        object.__setattr__(self, "_prepared_key", prepared)
        object.__setattr__(self, "_verification_key", verification_key)

    def as_verification_key(self) -> "VerificationKey":
        """Return the active key's verification-only representation."""
        return VerificationKey(
            key_id=self.key_id, algorithm=self.algorithm, key=self._verification_key, public_jwk=self.public_jwk
        )


@dataclass(frozen=True, slots=True)
class VerificationKey:
    """One explicit verification-only key retained for local rotation."""

    key_id: str
    algorithm: JWTAlgorithm
    key: bytes = field(repr=False)
    public_jwk: Mapping[str, JSONValue] | None = None
    _prepared_key: PreparedVerificationKey = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Reject private, weak, mismatched, or publication-unsafe material."""
        key_id = strict_key_id(self.key_id)
        prepared = _prepare_retained_verification_key(self.key, self.algorithm)
        public_jwk = _prepare_public_jwk(self.public_jwk, prepared, self.algorithm, key_id)
        object.__setattr__(self, "key_id", key_id)
        object.__setattr__(self, "public_jwk", public_jwk)
        object.__setattr__(self, "_prepared_key", prepared)


def prepare_key(key: VerificationKeyInput, algorithm: JWTAlgorithm) -> PreparedVerificationKey:
    try:
        prepared_input: object = key
        if isinstance(key, Mapping):
            _validate_public_jwk(key, algorithm)
            prepared_input = PyJWK.from_dict(cast("dict[str, object]", dict(key)), algorithm=algorithm).key
        prepared = jwt.get_algorithm_by_name(algorithm).prepare_key(prepared_input)
        return _validate_prepared_key(prepared, algorithm)
    except (NotImplementedError, PyJWTError, TypeError, ValueError):
        raise_config(f"Invalid {algorithm} JWT verification key")


class _RSAPublicJWK(TypedDict):
    alg: Literal["RS256"]
    e: str
    key_ops: list[Literal["verify"]]
    kid: str
    kty: Literal["RSA"]
    n: str
    use: Literal["sig"]


class _ECPublicJWK(TypedDict):
    alg: Literal["ES256"]
    crv: Literal["P-256"]
    key_ops: list[Literal["verify"]]
    kid: str
    kty: Literal["EC"]
    use: Literal["sig"]
    x: str
    y: str


class _OKPPublicJWK(TypedDict):
    alg: Literal["EdDSA"]
    crv: Literal["Ed25519"]
    key_ops: list[Literal["verify"]]
    kid: str
    kty: Literal["OKP"]
    use: Literal["sig"]
    x: str


class LocalJWKSDocument(TypedDict):
    keys: list[_RSAPublicJWK | _ECPublicJWK | _OKPPublicJWK]


def _prepare_signing_material(private_key: bytes, algorithm: JWTAlgorithm) -> tuple[PreparedSigningKey, bytes]:
    if algorithm not in _SUPPORTED_ALGORITHMS:
        raise_config(f"Unsupported local signing algorithm: {algorithm}")
    try:
        key_value: object = private_key
        if not isinstance(key_value, bytes):  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
            reject()
        if algorithm == "HS256":
            if len(key_value) < _MINIMUM_HMAC_BYTES:
                reject()
            return key_value, key_value
        loaded_key = serialization.load_pem_private_key(key_value, password=None)
        prepared = _validate_prepared_signing_key(loaded_key, algorithm)
        asymmetric_key = cast("rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey", prepared)
        verification_key = asymmetric_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except (TypeError, ValueError):
        raise_config(f"Invalid {algorithm} JWT signing key")
    else:
        return prepared, verification_key


def _validate_prepared_signing_key(key: object, algorithm: JWTAlgorithm) -> PreparedSigningKey:
    if algorithm == "RS256" and (not isinstance(key, rsa.RSAPrivateKey) or key.key_size < _MINIMUM_RSA_BITS):
        reject()
    if algorithm == "ES256" and (
        not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1)
    ):
        reject()
    if algorithm == "EdDSA" and not isinstance(key, ed25519.Ed25519PrivateKey):
        reject()
    return cast("PreparedSigningKey", key)


def _prepare_retained_verification_key(key: bytes, algorithm: JWTAlgorithm) -> PreparedVerificationKey:
    if algorithm not in _SUPPORTED_ALGORITHMS:
        raise_config(f"Unsupported local verification algorithm: {algorithm}")
    try:
        key_value: object = key
        if not isinstance(key_value, bytes):  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
            reject()
        if algorithm == "HS256":
            if len(key_value) < _MINIMUM_HMAC_BYTES:
                reject()
            return key_value
        prepared = serialization.load_pem_public_key(key_value)
        expected_type: type[object]
        if algorithm == "RS256":
            expected_type = rsa.RSAPublicKey
        elif algorithm == "ES256":
            expected_type = ec.EllipticCurvePublicKey
        else:
            expected_type = ed25519.Ed25519PublicKey
        if not isinstance(prepared, expected_type):
            reject()
        return _validate_prepared_key(prepared, algorithm)
    except (TypeError, ValueError):
        raise_config(f"Invalid {algorithm} JWT verification key")


def _prepare_public_jwk(
    value: Mapping[str, JSONValue] | None,
    key: PreparedSigningKey | PreparedVerificationKey,
    algorithm: JWTAlgorithm,
    key_id: str,
) -> Mapping[str, JSONValue] | None:
    if algorithm == "HS256":
        if value is not None:
            raise_config("HS256 signing and verification keys cannot have a public JWK")
        return None
    public_key = _as_public_key(key)
    if value is None:
        raw = cast("dict[str, JSONValue]", jwt.get_algorithm_by_name(algorithm).to_jwk(public_key, as_dict=True))
        raw.update({"alg": algorithm, "kid": key_id, "key_ops": ["verify"], "use": "sig"})
    else:
        raw = dict(value)
        try:
            _validate_public_jwk(raw, algorithm)
            if raw.get("kid") not in {None, key_id}:
                reject()
            jwk_key = prepare_key(raw, algorithm)
        except (ImproperlyConfiguredException, PyJWTError, TypeError, ValueError):
            raise_config(f"Invalid {algorithm} public JWK")
        if _public_key_bytes(jwk_key) != _public_key_bytes(public_key):
            raise_config(f"{algorithm} public JWK does not correspond to key material")
        raw["kid"] = key_id
        raw["alg"] = algorithm
        raw["use"] = "sig"
        raw["key_ops"] = ["verify"]
    return cast("Mapping[str, JSONValue]", freeze_json(cast("JSONValue", raw)))


def _as_public_key(
    key: PreparedSigningKey | PreparedVerificationKey,
) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey:
    if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey)):
        return key.public_key()
    return cast("rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey", key)


def _public_key_bytes(key: object) -> bytes:
    public_key = _as_public_key(cast("PreparedVerificationKey", key))
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _validate_prepared_key(key: object, algorithm: JWTAlgorithm) -> PreparedVerificationKey:
    if algorithm == "HS256":
        if not isinstance(key, bytes) or len(key) < _MINIMUM_HMAC_BYTES:
            raise ValueError
        return key
    if algorithm == "RS256":
        if not isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)) or key.key_size < _MINIMUM_RSA_BITS:
            raise ValueError
        return key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    if algorithm == "ES256":
        if not isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise ValueError
        return key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    if not isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        raise TypeError
    return key.public_key() if isinstance(key, ed25519.Ed25519PrivateKey) else key


def _validate_public_jwk(value: Mapping[str, JSONValue], algorithm: JWTAlgorithm) -> None:
    if _PRIVATE_JWK_MEMBERS.intersection(value):
        raise ValueError
    if value.get("alg") not in {None, algorithm} or value.get("use") not in {None, "sig"}:
        raise ValueError
    key_ops = value.get("key_ops")
    if key_ops is not None and (
        not isinstance(key_ops, (list, tuple))
        or any(not isinstance(operation, str) for operation in key_ops)
        or tuple(key_ops) != ("verify",)
    ):
        raise ValueError
    expected = {"EdDSA": ("OKP", "Ed25519"), "ES256": ("EC", "P-256"), "RS256": ("RSA", None), "HS256": ("oct", None)}[
        algorithm
    ]
    if value.get("kty") != expected[0] or (expected[1] is not None and value.get("crv") != expected[1]):
        raise ValueError
    if algorithm == "HS256":
        raise ValueError
