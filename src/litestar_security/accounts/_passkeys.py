"""Project-owned WebAuthn challenge, credential, and service boundary."""

from base64 import urlsafe_b64encode
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from hashlib import sha256
from secrets import token_bytes
from typing import Protocol, cast, runtime_checkable

from litestar.exceptions import ImproperlyConfiguredException
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    parse_authentication_credential_json,
    parse_client_data_json,
    parse_registration_credential_json,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    CredentialDeviceType,
    UserVerificationRequirement,
)

from litestar_security.accounts._internal import aware_utc_time, new_event_id, strict_context_text, utc_now
from litestar_security.accounts._operations import OUTCOME_CLONE_RISK, OUTCOME_REVOKED, PASSKEY_ASSERT, PASSKEY_REMOVE
from litestar_security.accounts._records import (
    NoOpSecurityEventSink,
    RevokeLoginMethodResult,
    SecurityEvent,
    SecurityEventSink,
)
from litestar_security.accounts._stores import LoginMethodStore
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.context import AuthenticationEvidence

__all__ = (
    "AssertionRecordResult",
    "AuthenticationVerification",
    "CloneRiskPolicy",
    "InvalidWebAuthnResponseError",
    "PasskeyCredential",
    "PasskeyService",
    "PasskeyStore",
    "PasskeySummary",
    "PyWebAuthnVerifier",
    "RegistrationVerification",
    "UserVerification",
    "WebAuthnChallenge",
    "WebAuthnChallengeStore",
    "WebAuthnOptions",
    "WebAuthnVerifier",
)

_CHALLENGE_BYTES = 32
_MAXIMUM_CHALLENGE_TTL = timedelta(minutes=10)
_DEFAULT_CHALLENGE_TTL = timedelta(minutes=5)
_DEFAULT_ALGORITHMS = (-8, -7, -257)


class UserVerification(str, Enum):
    """WebAuthn user-verification policy."""

    REQUIRED = "required"
    PREFERRED = "preferred"
    DISCOURAGED = "discouraged"


class AssertionRecordResult(str, Enum):
    """Atomic assertion-recording outcome."""

    RECORDED = "recorded"
    CONFLICT = "conflict"
    CLONE_RISK = "clone_risk"


class CloneRiskPolicy(str, Enum):
    """Response to a suspicious non-increasing non-zero counter."""

    REJECT = "reject"
    AUDIT_ONLY = "audit_only"


class InvalidWebAuthnResponseError(ValueError):
    """Sanitized dependency-boundary rejection."""


@dataclass(frozen=True, slots=True)
class WebAuthnChallenge:
    """Digest-only one-time ceremony record."""

    challenge_digest: bytes = field(repr=False)
    binding_digest: bytes = field(repr=False)
    purpose: str
    account_id: str
    rp_id: str
    origins: tuple[str, ...]
    user_verification: UserVerification
    algorithms: tuple[int, ...]
    expires_at: datetime

    def __post_init__(self) -> None:
        """Validate fixed digests, exact relying-party values, and UTC expiry."""
        challenge_digest = cast("object", self.challenge_digest)
        binding_digest = cast("object", self.binding_digest)
        expires_at = aware_utc_time(self.expires_at)
        if (
            not isinstance(challenge_digest, bytes)
            or len(challenge_digest) != sha256().digest_size
            or not isinstance(binding_digest, bytes)
            or len(binding_digest) != sha256().digest_size
            or not strict_context_text(self.purpose)
            or not strict_context_text(self.account_id)
            or not strict_context_text(self.rp_id)
            or not self.origins
            or not all(strict_context_text(origin) for origin in self.origins)
        ):
            message = "WebAuthn challenge requires exact digest and relying-party bindings"
            raise ValueError(message)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "origins", tuple(self.origins))
        object.__setattr__(self, "algorithms", tuple(self.algorithms))


@dataclass(frozen=True, slots=True)
class WebAuthnOptions:
    """Project-owned JSON ceremony options with reveal-once challenge."""

    challenge: str
    json: str = field(repr=False)
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class RegistrationVerification:
    """Dependency-neutral verified registration result."""

    credential_id: bytes
    public_key: bytes = field(repr=False)
    sign_count: int
    backup_eligible: bool
    backup_state: bool
    user_verified: bool
    aaguid: str
    attestation_format: str


@dataclass(frozen=True, slots=True)
class AuthenticationVerification:
    """Dependency-neutral verified assertion result."""

    credential_id: bytes
    sign_count: int
    backup_eligible: bool
    backup_state: bool
    user_verified: bool


@dataclass(frozen=True, slots=True)
class PasskeyCredential:
    """Stored passkey metadata and opaque public verification key."""

    credential_id: bytes
    account_id: str
    public_key: bytes = field(repr=False)
    sign_count: int
    backup_eligible: bool
    backup_state: bool
    user_verified: bool
    aaguid: str
    attestation_format: str
    created_at: datetime
    version: int = 0
    display_name: str | None = None
    suspect: bool = False
    last_used_at: datetime | None = None

    def __post_init__(self) -> None:
        """Validate strict ownership, flags, counters, and metadata."""
        credential_id = cast("object", self.credential_id)
        public_key = cast("object", self.public_key)
        created_at = aware_utc_time(self.created_at)
        last_used_at = aware_utc_time(self.last_used_at) if self.last_used_at is not None else None
        if (
            not isinstance(credential_id, bytes)
            or not credential_id
            or not isinstance(public_key, bytes)
            or not public_key
            or not strict_context_text(self.account_id)
            or self.sign_count.__class__ is not int
            or self.sign_count < 0
            or self.version.__class__ is not int
            or self.version < 0
            or self.backup_eligible.__class__ is not bool
            or self.backup_state.__class__ is not bool
            or self.user_verified.__class__ is not bool
            or self.suspect.__class__ is not bool
            or (not self.backup_eligible and self.backup_state)
        ):
            message = "Passkey credential requires valid ownership, key, counter, and backup flags"
            raise ValueError(message)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "last_used_at", last_used_at)


@dataclass(frozen=True, slots=True)
class PasskeySummary:
    """Safe credential metadata for account-management responses."""

    credential_id: str
    display_name: str | None
    backup_eligible: bool
    backup_state: bool
    suspect: bool
    created_at: datetime
    last_used_at: datetime | None


@runtime_checkable
class WebAuthnChallengeStore(Protocol):
    """Persist digest-only one-time WebAuthn challenges."""

    async def put(self, challenge: WebAuthnChallenge) -> None:
        """Store a challenge.

        Args:
            challenge: The digest-only bound challenge.
        """
        ...  # pragma: no cover

    async def consume(
        self, challenge_digest: bytes, *, binding_digest: bytes, purpose: str, now: datetime
    ) -> WebAuthnChallenge | None:
        """Atomically consume one exact unexpired challenge.

        Args:
            challenge_digest: Digest of the browser-returned challenge.
            binding_digest: Digest of the current transport binding.
            purpose: Expected ceremony type.
            now: Expiry comparison time.

        Returns:
            The consumed record only for one exact winning call.
        """
        ...  # pragma: no cover


@runtime_checkable
class PasskeyStore(Protocol):
    """Persist credentials and assertion state through atomic operations."""

    async def add_credential(self, credential: PasskeyCredential) -> bool:
        """Atomically add a globally unique credential for its owner.

        Args:
            credential: The fully verified credential.

        Returns:
            ``True`` when inserted, ``False`` on any ownership conflict.
        """
        ...  # pragma: no cover

    async def get_credential(self, credential_id: bytes) -> PasskeyCredential | None:
        """Load one credential by its opaque identifier.

        Args:
            credential_id: The browser-returned identifier.

        Returns:
            The credential, or ``None``.
        """
        ...  # pragma: no cover

    async def record_assertion(  # noqa: PLR0913 - atomic port carries every compared assertion field
        self,
        credential_id: bytes,
        *,
        expected_version: int,
        sign_count: int,
        backup_eligible: bool,
        backup_state: bool,
        clone_risk: bool,
        now: datetime,
    ) -> AssertionRecordResult:
        """Atomically persist a verified assertion against an optimistic version.

        Args:
            credential_id: The asserted credential.
            expected_version: The exact version loaded before verification.
            sign_count: The verified new signature counter.
            backup_eligible: The immutable BE flag.
            backup_state: The current BS flag.
            clone_risk: Whether counter behavior is suspicious.
            now: The commit timestamp.

        Returns:
            Structured recording status.
        """
        ...  # pragma: no cover

    async def list_credentials(self, account_id: str) -> tuple[PasskeyCredential, ...]:
        """List credentials owned by one account.

        Args:
            account_id: The owning account.

        Returns:
            Immutable credential records for projection to safe summaries.
        """
        ...  # pragma: no cover

    async def rename_credential(
        self, account_id: str, credential_id: bytes, display_name: str
    ) -> PasskeyCredential | None:
        """Atomically rename one credential only for its owner.

        Args:
            account_id: The expected owner.
            credential_id: The credential to rename.
            display_name: The replacement safe metadata.

        Returns:
            The updated credential, or ``None``.
        """
        ...  # pragma: no cover


@runtime_checkable
class WebAuthnVerifier(Protocol):
    """Synchronous cryptographic adapter used outside guards and request policy."""

    def registration_options(self, **kwargs: object) -> str:
        """Build browser registration JSON."""
        ...  # pragma: no cover

    def authentication_options(self, **kwargs: object) -> str:
        """Build browser authentication JSON."""
        ...  # pragma: no cover

    def registration_challenge(self, response: str) -> bytes:
        """Extract the client challenge before one-time consumption."""
        ...  # pragma: no cover

    def authentication_challenge(self, response: str) -> bytes:
        """Extract the assertion challenge before one-time consumption."""
        ...  # pragma: no cover

    def credential_id(self, response: str) -> bytes:
        """Extract an assertion credential identifier."""
        ...  # pragma: no cover

    def verify_registration(self, **kwargs: object) -> RegistrationVerification:
        """Perform exact registration verification."""
        ...  # pragma: no cover

    def verify_authentication(self, **kwargs: object) -> AuthenticationVerification:
        """Perform exact assertion verification."""
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class PyWebAuthnVerifier:
    """Private adapter over the pinned py-webauthn API."""

    def registration_options(self, **kwargs: object) -> str:
        """Build registration options with project-validated arguments."""
        try:
            options = generate_registration_options(
                rp_id=cast("str", kwargs["rp_id"]),
                rp_name=cast("str", kwargs["rp_name"]),
                user_name=cast("str", kwargs["user_name"]),
                user_id=cast("str", kwargs["account_id"]).encode(),
                challenge=cast("bytes", kwargs["challenge"]),
                timeout=cast("int", kwargs["timeout_ms"]),
                attestation=AttestationConveyancePreference.NONE,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    user_verification=UserVerificationRequirement(cast("str", kwargs["user_verification"]))
                ),
                supported_pub_key_algs=[
                    COSEAlgorithmIdentifier(value) for value in cast("Sequence[int]", kwargs["algorithms"])
                ],
            )
            return options_to_json(options)
        except Exception as exc:
            raise InvalidWebAuthnResponseError from exc

    def authentication_options(self, **kwargs: object) -> str:
        """Build authentication options with project-validated arguments."""
        try:
            options = generate_authentication_options(
                rp_id=cast("str", kwargs["rp_id"]),
                challenge=cast("bytes", kwargs["challenge"]),
                timeout=cast("int", kwargs["timeout_ms"]),
                user_verification=UserVerificationRequirement(cast("str", kwargs["user_verification"])),
            )
            return options_to_json(options)
        except Exception as exc:
            raise InvalidWebAuthnResponseError from exc

    def registration_challenge(self, response: str) -> bytes:
        """Extract registration client data through the pinned parser."""
        try:
            parsed = parse_registration_credential_json(response)
            return parse_client_data_json(bytes(parsed.response.client_data_json)).challenge
        except Exception as exc:
            raise InvalidWebAuthnResponseError from exc

    def authentication_challenge(self, response: str) -> bytes:
        """Extract authentication client data through the pinned parser."""
        try:
            parsed = parse_authentication_credential_json(response)
            return parse_client_data_json(bytes(parsed.response.client_data_json)).challenge
        except Exception as exc:
            raise InvalidWebAuthnResponseError from exc

    def credential_id(self, response: str) -> bytes:
        """Extract the raw assertion credential identifier."""
        try:
            return bytes(parse_authentication_credential_json(response).raw_id)
        except Exception as exc:
            raise InvalidWebAuthnResponseError from exc

    def verify_registration(self, **kwargs: object) -> RegistrationVerification:
        """Verify registration and project the dependency result."""
        try:
            verified = verify_registration_response(
                credential=cast("str", kwargs["response"]),
                expected_challenge=cast("bytes", kwargs["challenge"]),
                expected_rp_id=cast("str", kwargs["rp_id"]),
                expected_origin=list(cast("Sequence[str]", kwargs["origins"])),
                require_user_presence=True,
                require_user_verification=cast("bool", kwargs["require_user_verification"]),
                supported_pub_key_algs=[
                    COSEAlgorithmIdentifier(value) for value in cast("Sequence[int]", kwargs["algorithms"])
                ],
            )
        except Exception as exc:
            raise InvalidWebAuthnResponseError from exc
        return RegistrationVerification(
            credential_id=bytes(verified.credential_id),
            public_key=bytes(verified.credential_public_key),
            sign_count=verified.sign_count,
            backup_eligible=verified.credential_device_type is CredentialDeviceType.MULTI_DEVICE,
            backup_state=verified.credential_backed_up,
            user_verified=verified.user_verified,
            aaguid=verified.aaguid,
            attestation_format=verified.fmt.value,
        )

    def verify_authentication(self, **kwargs: object) -> AuthenticationVerification:
        """Verify assertion and project the dependency result."""
        try:
            verified = verify_authentication_response(
                credential=cast("str", kwargs["response"]),
                expected_challenge=cast("bytes", kwargs["challenge"]),
                expected_rp_id=cast("str", kwargs["rp_id"]),
                expected_origin=list(cast("Sequence[str]", kwargs["origins"])),
                credential_public_key=cast("bytes", kwargs["public_key"]),
                credential_current_sign_count=0,
                require_user_verification=cast("bool", kwargs["require_user_verification"]),
            )
        except Exception as exc:
            raise InvalidWebAuthnResponseError from exc
        return AuthenticationVerification(
            credential_id=bytes(verified.credential_id),
            sign_count=verified.new_sign_count,
            backup_eligible=verified.credential_device_type is CredentialDeviceType.MULTI_DEVICE,
            backup_state=verified.credential_backed_up,
            user_verified=verified.user_verified,
        )


@dataclass(slots=True)
class PasskeyService:
    """Run bound one-time WebAuthn registration and authentication ceremonies."""

    store: PasskeyStore
    challenge_store: WebAuthnChallengeStore
    rp_id: str
    rp_name: str
    origins: tuple[str, ...]
    user_verification: UserVerification = UserVerification.REQUIRED
    algorithms: tuple[int, ...] = _DEFAULT_ALGORITHMS
    challenge_ttl: timedelta = _DEFAULT_CHALLENGE_TTL
    verifier: WebAuthnVerifier = field(default_factory=PyWebAuthnVerifier, repr=False)
    clock: Callable[[], datetime] = field(default=utc_now, repr=False, compare=False)
    challenge_entropy: Callable[[int], bytes] = field(default=token_bytes, repr=False, compare=False)
    clone_risk_policy: CloneRiskPolicy = CloneRiskPolicy.REJECT
    login_methods: LoginMethodStore | None = field(default=None, repr=False, compare=False)
    events: SecurityEventSink = field(default_factory=NoOpSecurityEventSink, repr=False, compare=False)
    event_ids: Callable[[], str] = field(default=new_event_id, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate structural capabilities and exact relying-party configuration."""
        store = cast("object", self.store)
        challenge_store = cast("object", self.challenge_store)
        verifier = cast("object", self.verifier)
        self.origins = tuple(self.origins)
        self.algorithms = tuple(self.algorithms)
        if not isinstance(store, PasskeyStore) or not isinstance(challenge_store, WebAuthnChallengeStore):
            message = "Passkey service requires PasskeyStore and WebAuthnChallengeStore"
            raise ImproperlyConfiguredException(detail=message)
        if not isinstance(verifier, WebAuthnVerifier):
            message = "Passkey service verifier must implement WebAuthnVerifier"
            raise ImproperlyConfiguredException(detail=message)
        if (
            not strict_context_text(self.rp_id)
            or not strict_context_text(self.rp_name)
            or not self.origins
            or not all(strict_context_text(origin) for origin in self.origins)
            or not timedelta() < self.challenge_ttl <= _MAXIMUM_CHALLENGE_TTL
            or not self.algorithms
        ):
            message = "Passkey service requires exact relying-party, origin, algorithm, and expiry configuration"
            raise ImproperlyConfiguredException(detail=message)

    async def begin_registration(
        self, account_id: str, *, user_name: str, binding: bytes
    ) -> WebAuthnOptions | VerificationUnavailable:
        """Create bound registration options and persist only the challenge digest."""
        return await self._begin(
            account_id=account_id,
            binding=binding,
            purpose="registration",
            options=lambda challenge: self.verifier.registration_options(
                challenge=challenge,
                rp_id=self.rp_id,
                rp_name=self.rp_name,
                account_id=account_id,
                user_name=user_name,
                timeout_ms=int(self.challenge_ttl.total_seconds() * 1000),
                user_verification=self.user_verification.value,
                algorithms=self.algorithms,
            ),
        )

    async def begin_authentication(
        self, account_id: str, *, binding: bytes
    ) -> WebAuthnOptions | VerificationUnavailable:
        """Create bound authentication options and persist only the challenge digest."""
        return await self._begin(
            account_id=account_id,
            binding=binding,
            purpose="authentication",
            options=lambda challenge: self.verifier.authentication_options(
                challenge=challenge,
                rp_id=self.rp_id,
                timeout_ms=int(self.challenge_ttl.total_seconds() * 1000),
                user_verification=self.user_verification.value,
            ),
        )

    async def verify_registration(
        self, account_id: str, *, binding: bytes, response: str
    ) -> PasskeyCredential | InvalidCredentials | VerificationUnavailable:
        """Consume, verify, and atomically register one credential."""
        try:
            challenge = self.verifier.registration_challenge(response)
            now = aware_utc_time(self.clock())
            record = await self.challenge_store.consume(
                sha256(challenge).digest(), binding_digest=_binding_digest(binding), purpose="registration", now=now
            )
            if record is None or record.account_id != account_id:
                return InvalidCredentials()
            verified = self.verifier.verify_registration(
                response=response,
                challenge=challenge,
                rp_id=record.rp_id,
                origins=record.origins,
                require_user_verification=record.user_verification is UserVerification.REQUIRED,
                algorithms=record.algorithms,
            )
            if verified.attestation_format != "none" or (not verified.backup_eligible and verified.backup_state):
                return InvalidCredentials()
            credential = PasskeyCredential(
                credential_id=verified.credential_id,
                account_id=account_id,
                public_key=verified.public_key,
                sign_count=verified.sign_count,
                backup_eligible=verified.backup_eligible,
                backup_state=verified.backup_state,
                user_verified=verified.user_verified,
                aaguid=verified.aaguid,
                attestation_format=verified.attestation_format,
                created_at=now,
            )
            if not await self.store.add_credential(credential):
                return InvalidCredentials()
        except InvalidWebAuthnResponseError:
            return InvalidCredentials()
        except Exception:  # noqa: BLE001 - sanitize application stores and dependency failures
            return VerificationUnavailable()
        return credential

    async def verify_authentication(  # noqa: PLR0911 - each protocol or persistence rejection has a distinct safe outcome
        self, account_id: str, *, binding: bytes, response: str
    ) -> AuthenticationEvidence | InvalidCredentials | VerificationUnavailable:
        """Consume, verify, and atomically record one assertion."""
        try:
            challenge = self.verifier.authentication_challenge(response)
            credential_id = self.verifier.credential_id(response)
            now = aware_utc_time(self.clock())
            record = await self.challenge_store.consume(
                sha256(challenge).digest(), binding_digest=_binding_digest(binding), purpose="authentication", now=now
            )
            credential = await self.store.get_credential(credential_id)
            if (
                record is None
                or credential is None
                or record.account_id != account_id
                or credential.account_id != account_id
            ):
                return InvalidCredentials()
            verified = self.verifier.verify_authentication(
                response=response,
                challenge=challenge,
                rp_id=record.rp_id,
                origins=record.origins,
                public_key=credential.public_key,
                require_user_verification=record.user_verification is UserVerification.REQUIRED,
            )
            if (
                verified.credential_id != credential.credential_id
                or verified.backup_eligible != credential.backup_eligible
                or (not verified.backup_eligible and verified.backup_state)
            ):
                return InvalidCredentials()
            clone_risk = (
                credential.sign_count > 0
                and verified.sign_count > 0
                and verified.sign_count <= credential.sign_count
            )
            result = await self.store.record_assertion(
                credential.credential_id,
                expected_version=credential.version,
                sign_count=verified.sign_count,
                backup_eligible=verified.backup_eligible,
                backup_state=verified.backup_state,
                clone_risk=clone_risk,
                now=now,
            )
            if result is AssertionRecordResult.CONFLICT:
                return InvalidCredentials()
        except InvalidWebAuthnResponseError:
            return InvalidCredentials()
        except Exception:  # noqa: BLE001 - sanitize application stores and dependency failures
            return VerificationUnavailable()
        if result is AssertionRecordResult.CLONE_RISK:
            await self._emit_event(
                operation=PASSKEY_ASSERT,
                outcome=OUTCOME_CLONE_RISK,
                account_id=account_id,
                occurred_at=now,
            )
            if self.clone_risk_policy is CloneRiskPolicy.REJECT:
                return InvalidCredentials()
        traits = {"phishing-resistant"}
        if verified.user_verified and record.user_verification is UserVerification.REQUIRED:
            traits.add("user-verified")
        return AuthenticationEvidence(
            mechanism="passkey",
            slot="mfa",
            authenticated_at=now,
            methods=frozenset({"passkey"}),
            traits=frozenset(traits),
        )

    async def list_credentials(
        self, account_id: str
    ) -> tuple[PasskeySummary, ...] | VerificationUnavailable:
        """List safe credential metadata for one owner."""
        try:
            credentials = await self.store.list_credentials(account_id)
            return tuple(
                _credential_summary(credential)
                for credential in credentials
                if credential.account_id == account_id
            )
        except Exception:  # noqa: BLE001 - sanitize application store failures
            return VerificationUnavailable()

    async def rename_credential(
        self, account_id: str, credential_id: bytes, display_name: str
    ) -> PasskeySummary | None | VerificationUnavailable:
        """Rename one credential through its owner-checked store operation."""
        if not strict_context_text(display_name):
            return None
        try:
            credential = await self.store.rename_credential(account_id, credential_id, display_name.strip())
        except Exception:  # noqa: BLE001 - sanitize application store failures
            return VerificationUnavailable()
        return _credential_summary(credential) if credential is not None else None

    async def remove_credential(
        self, account_id: str, credential_id: bytes
    ) -> RevokeLoginMethodResult | VerificationUnavailable:
        """Remove one credential through the shared final-method-safe operation."""
        login_methods = self.login_methods
        if login_methods is None:
            return VerificationUnavailable()
        try:
            now = aware_utc_time(self.clock())
            method_id = f"pk_{urlsafe_b64encode(credential_id).rstrip(b'=').decode('ascii')}"
            event = SecurityEvent(
                event_id=self.event_ids(),
                occurred_at=now,
                operation=PASSKEY_REMOVE,
                outcome=OUTCOME_REVOKED,
                account_id=account_id,
            )
            return await login_methods.revoke_login_method(
                account_id, method_id, require_remaining=True, event=event
            )
        except Exception:  # noqa: BLE001 - sanitize application login-method store failures
            return VerificationUnavailable()

    async def _emit_event(
        self, *, operation: str, outcome: str, account_id: str, occurred_at: datetime
    ) -> None:
        try:
            await self.events.emit(
                SecurityEvent(
                    event_id=self.event_ids(),
                    occurred_at=occurred_at,
                    operation=operation,
                    outcome=outcome,
                    account_id=account_id,
                )
            )
        except Exception:  # noqa: BLE001 - observational audit failure cannot change a settled decision
            return

    async def _begin(
        self, *, account_id: str, binding: bytes, purpose: str, options: Callable[[bytes], str]
    ) -> WebAuthnOptions | VerificationUnavailable:
        try:
            now = aware_utc_time(self.clock())
            challenge = self.challenge_entropy(_CHALLENGE_BYTES)
            challenge_value = cast("object", challenge)
            if not isinstance(challenge_value, bytes) or len(challenge_value) < _CHALLENGE_BYTES:
                return VerificationUnavailable()
            expires_at = now + self.challenge_ttl
            json_options = options(challenge)
            record = WebAuthnChallenge(
                challenge_digest=sha256(challenge).digest(),
                binding_digest=_binding_digest(binding),
                purpose=purpose,
                account_id=account_id,
                rp_id=self.rp_id,
                origins=self.origins,
                user_verification=self.user_verification,
                algorithms=self.algorithms,
                expires_at=expires_at,
            )
            await self.challenge_store.put(record)
        except Exception:  # noqa: BLE001 - sanitize application store, entropy, and dependency failures
            return VerificationUnavailable()
        encoded = urlsafe_b64encode(challenge).rstrip(b"=").decode("ascii")
        return WebAuthnOptions(challenge=encoded, json=json_options, expires_at=expires_at)


def _binding_digest(binding: bytes) -> bytes:
    value = cast("object", binding)
    if not isinstance(value, bytes) or not value:
        raise ValueError
    return sha256(value).digest()


def _credential_summary(credential: PasskeyCredential) -> PasskeySummary:
    identifier = urlsafe_b64encode(credential.credential_id).rstrip(b"=").decode("ascii")
    return PasskeySummary(
        credential_id=identifier,
        display_name=credential.display_name,
        backup_eligible=credential.backup_eligible,
        backup_state=credential.backup_state,
        suspect=credential.suspect,
        created_at=credential.created_at,
        last_used_at=credential.last_used_at,
    )
