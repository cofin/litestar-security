# Litestar Security

Litestar Security is a typed, backend-agnostic authentication and authorization
plugin for [Litestar](https://litestar.dev/) applications. Version 1.0 provides
explicit local session, token, and hybrid authentication; policy and guard
algebra; OAuth/OIDC, IAP, API-key, workload-JWT, MFA, passkey, WebSocket, CSP,
JWKS, and testing/conformance boundaries.

## Installation

Install the package:

```console
pip install litestar-security
```

For repository development, use `make install`.

## Choose the transport

Local authentication never infers transport from installed middleware. Choose
one profile explicitly and pass the application-owned stores and secrets:

```python
from litestar import Litestar
from litestar.config.csrf import CSRFConfig
from litestar.middleware.session.client_side import CookieBackendConfig

from litestar_security import SecurityConfig, SecurityPlugin
from litestar_security.accounts import LocalAuth, LocalAuthSecrets, SessionBindingConfig

local_auth = LocalAuth.session(
    accounts=accounts,
    secrets=LocalAuthSecrets.session(purpose_token_pepper=purpose_token_pepper),
    csrf=CSRFConfig(secret=csrf_secret),
    binding=SessionBindingConfig(pepper=binding_pepper),
)
session_backend = CookieBackendConfig(secret=session_secret).middleware.kwargs["backend"]

app = Litestar(
    plugins=[SecurityPlugin(SecurityConfig(local_auth=local_auth, session_backend=session_backend))]
)
```

For APIs, use `LocalAuth.tokens(...)` with a `LocalKeyRing`, rotating opaque
refresh-token secrets, and no Litestar session backend. `LocalAuth.hybrid(...)`
registers distinct browser-session and token endpoints; it does not
auto-detect a transport.

Every request gets typed `principal` and `security_context` dependencies.
Authentication policies are declared with `public()`, `required()`, `any_of()`,
`all_of()`, and `at_least()`. Authorization stays separate through typed guards
for scopes, roles, capabilities, assurance, teams, and tenants.

## Run the complete examples

```console
LITESTAR_SECURITY_EXAMPLE=local-session uv run litestar --app examples.app:create_app run
LITESTAR_SECURITY_EXAMPLE=local-token uv run litestar --app examples.app:create_app run
LITESTAR_SECURITY_EXAMPLE=google-oauth uv run litestar --app examples.app:create_app run
LITESTAR_SECURITY_EXAMPLE=websocket uv run litestar --app examples.app:create_app run
```

See [examples/README.md](examples/README.md) for all modes and their production
boundaries. The examples use ephemeral keys, deterministic stores, and
loopback-only settings; they are not production secret or persistence
configuration.

## Security boundaries

- Applications own users, databases, atomic store implementations, key
  custody, provider HTTP clients, delivery, administrator controllers, and
  deployment trust.
- Presented invalid credentials are terminal. Multiple successful credentials
  must resolve to one subject, and their restrictions intersect.
- Native session authentication requires explicit CSRF configuration.
- Blocking application ports must be wrapped with `BlockingIntegration`; the
  runtime dispatches them through bounded workers.
- Static browser headers use Litestar response headers. Nonce CSP uses one
  native send hook and never accepts a client nonce.

## Development

```console
make check-all
make release-check
```

See [CONTRIBUTING.rst](CONTRIBUTING.rst) for setup, testing, documentation, and
contribution guidance.

## License

The `litestar security --version` command reports the installed distribution
version. Litestar Security is distributed under the MIT license.
