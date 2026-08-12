"""Deterministic builders for the public wire layer.

Only ``msgspec.Struct`` types get factories: 33 of the 34 concrete public wire
structs build from a bare ``MsgspecFactory``, while only 55 of 186 public frozen
dataclasses do -- their ``__post_init__`` validators reject generated values and
their deferred annotations defeat ``get_type_hints``. Domain value types get
explicit builders instead, in ``collaborators.py``.

``TokenPair`` is the one wire struct with no factory here. Its ``__post_init__``
demands three structurally-generated values at once -- a compact JWT access
token, an ``rt_<identifier>.<secret>`` refresh token, and an ``expires_in``
inside the configured bounds -- so ``collaborators.build_token_pair`` constructs
it from real key material instead.

Generated values are arbitrary. ``__random_seed__`` seeds the generator once, at
class definition, which buys run-to-run reproducibility only while the number
and order of ``build()`` calls stays identical -- and ``-n auto`` and a shuffled
run both change that order per worker. So a factory supplies "some valid
instance whose exact field values do not matter", and any value a test asserts
on is passed in explicitly::

    account = LocalAccountFactory.build(account_id="acct-1")  # correct
    assert account.account_id == "acct-1"

    account = LocalAccountFactory.build()  # wrong
    assert account.account_id == "mIDbfZheIDDtVbuzYOfy"  # breaks under -n auto

Registered as a pytest plugin through ``pytest_plugins`` in
``src/tests/conftest.py``; every factory is also available as a fixture under
the snake-case name shown in its ``register_fixture`` call.
"""

from polyfactory.factories.msgspec_factory import MsgspecFactory
from polyfactory.pytest_plugin import register_fixture

from litestar_security.accounts import (
    LifecycleAccepted,
    LocalAccount,
    LocalCredentials,
    LocalIdentifier,
    LocalInvitationRegistration,
    LocalMFAChallenge,
    LocalMFACompletion,
    LocalPasswordChange,
    LocalPasswordReset,
    LocalRegistration,
    LocalSession,
    LocalSessionList,
    LocalToken,
    OperationMessage,
    PasskeyAuthenticationStart,
    PasskeyOptions,
    PasskeyRegistrationStart,
    PasskeySummary,
    PasskeyVerification,
    RecoveryCodes,
    StepUpAuthorization,
    StepUpGrant,
    StepUpVerification,
    TOTPEnrollment,
    TOTPProvisioning,
    TOTPVerification,
)
from litestar_security.providers.oauth import (
    OAuthAuthorization,
    OAuthLink,
    OAuthLogout,
    OAuthOperationSummary,
    OAuthScopeUpgrade,
    OAuthStepUp,
    OIDCBackchannelLogout,
)

# Fixed so a rerun of the same test file in the same order regenerates the same
# values; see the module docstring for why that is not the same as idempotence.
SEED = 20260804


@register_fixture(name="lifecycle_accepted_factory")
class LifecycleAcceptedFactory(MsgspecFactory[LifecycleAccepted]):
    __model__ = LifecycleAccepted
    __random_seed__ = SEED


@register_fixture(name="local_account_factory")
class LocalAccountFactory(MsgspecFactory[LocalAccount]):
    __model__ = LocalAccount
    __random_seed__ = SEED


@register_fixture(name="local_credentials_factory")
class LocalCredentialsFactory(MsgspecFactory[LocalCredentials]):
    __model__ = LocalCredentials
    __random_seed__ = SEED


@register_fixture(name="local_identifier_factory")
class LocalIdentifierFactory(MsgspecFactory[LocalIdentifier]):
    __model__ = LocalIdentifier
    __random_seed__ = SEED


@register_fixture(name="local_invitation_registration_factory")
class LocalInvitationRegistrationFactory(MsgspecFactory[LocalInvitationRegistration]):
    __model__ = LocalInvitationRegistration
    __random_seed__ = SEED


@register_fixture(name="local_mfa_challenge_factory")
class LocalMFAChallengeFactory(MsgspecFactory[LocalMFAChallenge]):
    __model__ = LocalMFAChallenge
    __random_seed__ = SEED


@register_fixture(name="local_mfa_completion_factory")
class LocalMFACompletionFactory(MsgspecFactory[LocalMFACompletion]):
    __model__ = LocalMFACompletion
    __random_seed__ = SEED


@register_fixture(name="local_password_change_factory")
class LocalPasswordChangeFactory(MsgspecFactory[LocalPasswordChange]):
    __model__ = LocalPasswordChange
    __random_seed__ = SEED


@register_fixture(name="local_password_reset_factory")
class LocalPasswordResetFactory(MsgspecFactory[LocalPasswordReset]):
    __model__ = LocalPasswordReset
    __random_seed__ = SEED


@register_fixture(name="local_registration_factory")
class LocalRegistrationFactory(MsgspecFactory[LocalRegistration]):
    __model__ = LocalRegistration
    __random_seed__ = SEED


@register_fixture(name="local_session_factory")
class LocalSessionFactory(MsgspecFactory[LocalSession]):
    __model__ = LocalSession
    __random_seed__ = SEED


@register_fixture(name="local_session_list_factory")
class LocalSessionListFactory(MsgspecFactory[LocalSessionList]):
    __model__ = LocalSessionList
    __random_seed__ = SEED


@register_fixture(name="local_token_factory")
class LocalTokenFactory(MsgspecFactory[LocalToken]):
    __model__ = LocalToken
    __random_seed__ = SEED


@register_fixture(name="passkey_authentication_start_factory")
class PasskeyAuthenticationStartFactory(MsgspecFactory[PasskeyAuthenticationStart]):
    __model__ = PasskeyAuthenticationStart
    __random_seed__ = SEED


@register_fixture(name="passkey_options_factory")
class PasskeyOptionsFactory(MsgspecFactory[PasskeyOptions]):
    __model__ = PasskeyOptions
    __random_seed__ = SEED


@register_fixture(name="passkey_registration_start_factory")
class PasskeyRegistrationStartFactory(MsgspecFactory[PasskeyRegistrationStart]):
    __model__ = PasskeyRegistrationStart
    __random_seed__ = SEED


@register_fixture(name="passkey_summary_factory")
class PasskeySummaryFactory(MsgspecFactory[PasskeySummary]):
    __model__ = PasskeySummary
    __random_seed__ = SEED


@register_fixture(name="passkey_verification_factory")
class PasskeyVerificationFactory(MsgspecFactory[PasskeyVerification]):
    __model__ = PasskeyVerification
    __random_seed__ = SEED


@register_fixture(name="recovery_codes_factory")
class RecoveryCodesFactory(MsgspecFactory[RecoveryCodes]):
    __model__ = RecoveryCodes
    __random_seed__ = SEED


@register_fixture(name="route_status_factory")
class OperationMessageFactory(MsgspecFactory[OperationMessage]):
    __model__ = OperationMessage
    __random_seed__ = SEED


@register_fixture(name="step_up_authorization_factory")
class StepUpAuthorizationFactory(MsgspecFactory[StepUpAuthorization]):
    __model__ = StepUpAuthorization
    __random_seed__ = SEED


@register_fixture(name="step_up_grant_factory")
class StepUpGrantFactory(MsgspecFactory[StepUpGrant]):
    __model__ = StepUpGrant
    __random_seed__ = SEED


@register_fixture(name="step_up_verification_factory")
class StepUpVerificationFactory(MsgspecFactory[StepUpVerification]):
    __model__ = StepUpVerification
    __random_seed__ = SEED


@register_fixture(name="totp_enrollment_factory")
class TOTPEnrollmentFactory(MsgspecFactory[TOTPEnrollment]):
    __model__ = TOTPEnrollment
    __random_seed__ = SEED


@register_fixture(name="totp_provisioning_factory")
class TOTPProvisioningFactory(MsgspecFactory[TOTPProvisioning]):
    __model__ = TOTPProvisioning
    __random_seed__ = SEED


@register_fixture(name="totp_verification_factory")
class TOTPVerificationFactory(MsgspecFactory[TOTPVerification]):
    __model__ = TOTPVerification
    __random_seed__ = SEED


@register_fixture(name="oauth_authorization_factory")
class OAuthAuthorizationFactory(MsgspecFactory[OAuthAuthorization]):
    __model__ = OAuthAuthorization
    __random_seed__ = SEED


@register_fixture(name="oauth_link_factory")
class OAuthLinkFactory(MsgspecFactory[OAuthLink]):
    __model__ = OAuthLink
    __random_seed__ = SEED


@register_fixture(name="oauth_logout_factory")
class OAuthLogoutFactory(MsgspecFactory[OAuthLogout]):
    __model__ = OAuthLogout
    __random_seed__ = SEED


@register_fixture(name="oauth_route_status_factory")
class OAuthOperationSummaryFactory(MsgspecFactory[OAuthOperationSummary]):
    __model__ = OAuthOperationSummary
    __random_seed__ = SEED


@register_fixture(name="oauth_scope_upgrade_factory")
class OAuthScopeUpgradeFactory(MsgspecFactory[OAuthScopeUpgrade]):
    __model__ = OAuthScopeUpgrade
    __random_seed__ = SEED


@register_fixture(name="oauth_step_up_factory")
class OAuthStepUpFactory(MsgspecFactory[OAuthStepUp]):
    __model__ = OAuthStepUp
    __random_seed__ = SEED


@register_fixture(name="oidc_backchannel_logout_factory")
class OIDCBackchannelLogoutFactory(MsgspecFactory[OIDCBackchannelLogout]):
    __model__ = OIDCBackchannelLogout
    __random_seed__ = SEED
