<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/litestar-org/branding/main/assets/projects/litestar-security/svg/banner-inline-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/litestar-org/branding/main/assets/projects/litestar-security/svg/banner-inline-light.svg">
  <img alt="Litestar Security" src="https://raw.githubusercontent.com/litestar-org/branding/main/assets/projects/litestar-security/svg/banner-inline-light.svg" width="620">
</picture>

<p><strong>Storage-agnostic authentication, authorization, local account lifecycle, external identity providers, and WebSocket security for <a href="https://litestar.dev/">Litestar</a>.</strong></p>

<p>
  <a href="https://pypi.org/project/litestar-security/"><img alt="PyPI Version" src="https://img.shields.io/pypi/v/litestar-security?color=202235&labelColor=0b0d14"></a>
  <a href="https://pypi.org/project/litestar-security/"><img alt="Python Versions" src="https://img.shields.io/pypi/pyversions/litestar-security?color=202235&labelColor=0b0d14"></a>
  <a href="https://github.com/cofin/litestar-security/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/cofin/litestar-security/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://cofin.github.io/litestar-security/"><img alt="Documentation" src="https://img.shields.io/badge/docs-cofin.github.io%2Flitestar--security-EDB641?labelColor=0b0d14"></a>
  <a href="https://github.com/cofin/litestar-security/blob/main/LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-202235?labelColor=0b0d14"></a>
  <a href="https://discord.gg/litestar"><img alt="Discord" src="https://img.shields.io/badge/discord-Litestar-5865F2?labelColor=0b0d14&logo=discord&logoColor=white"></a>
</p>

<p>
  <a href="https://cofin.github.io/litestar-security/getting-started.html">Getting Started</a>
  &middot;
  <a href="https://cofin.github.io/litestar-security/authentication.html">Authentication &amp; Guards</a>
  &middot;
  <a href="https://cofin.github.io/litestar-security/accounts.html">Local Accounts</a>
  &middot;
  <a href="https://cofin.github.io/litestar-security/providers.html">Providers</a>
  &middot;
  <a href="https://cofin.github.io/litestar-security/jwt-and-jwks.html">JWT &amp; JWKS</a>
  &middot;
  <a href="https://cofin.github.io/litestar-security/websockets.html">WebSockets</a>
  &middot;
  <a href="https://cofin.github.io/litestar-security/reference.html">API Reference</a>
</p>

</div>

---

`litestar-security` connects local accounts, OAuth 2.0 and OIDC providers, Google Cloud IAP assertions, prefixed API keys, and workload JWTs to Litestar's ASGI middleware, dependency injection, guards, OpenAPI schema, and WebSocket lifecycle. Every persistence, cache, secret-custody, and rate-limit boundary is modeled as a narrow `Protocol` port with zero runtime ORM, database driver, or cache SDK dependencies.

## Capability Matrix

| Capability | Primary Symbols | Documentation |
| :--- | :--- | :--- |
| **Plugin, Policy & Context** | `SecurityPlugin`, `SecurityConfig`, `SecurityContext`, `Principal`, `CurrentUser`, `SecureController`, `PublicController`, `public`, `optional`, `required`, `exclude` | [Authentication & Guards](https://cofin.github.io/litestar-security/authentication.html) |
| **Authorization Guards** | `requires_authenticated`, `requires_role`, `requires_scope`, `requires_tenant`, `requires_tenant_role`, `requires_capability`, `requires_assurance`, `requires_all_of`, `requires_any_of` | [Authentication & Guards](https://cofin.github.io/litestar-security/authentication.html) |
| **Local Accounts, MFA & Passkeys** | `LocalAuth`, `LocalAuthConfig`, `Argon2PasswordHasher`, `MFAConfig`, `MFAService`, `PasskeyConfig`, `PyWebAuthnVerifier`, `AESGCMSecretProtector`, `StepUpService` | [Local Accounts](https://cofin.github.io/litestar-security/accounts.html) |
| **OAuth 2.0, OIDC & Google IAP** | `OAuthConfig`, `OIDCProvider`, `google_oidc_provider`, `keycloak_oidc_provider`, `GitHubOAuthProvider`, `OIDCDiscoveryClient`, `GoogleIAPConfig`, `GoogleIAPClaims` | [External Providers](https://cofin.github.io/litestar-security/providers.html) |
| **JWT Signing, JWKS & API Keys** | `CompositeBearerConfig`, `ServiceTokenConfig`, `LocalKeyRing`, `CachedJWKSProvider`, `HttpxJWKSFetcher`, `APIKeyConfig`, `ProtectedResourceConfig` | [JWT & JWKS](https://cofin.github.io/litestar-security/jwt-and-jwks.html) |
| **WebSocket Security** | `WebSocketSecurityConfig`, `WebSocketConnectTokenIssuer`, `issue_websocket_connect_token`, `supervise_websocket_lifetime`, `WebSocketRevocationSource` | [WebSocket Security](https://cofin.github.io/litestar-security/websockets.html) |
| **Hardening & Rate Limiting** | `SecurityHeadersConfig`, `ContentSecurityPolicy`, `csp_nonce`, `StoreRateLimiter`, `forwarded_client_key`, `litestar security routes` | [Hardening](https://cofin.github.io/litestar-security/hardening.html) |
| **Storage Ports & Test Kit** | `InMemorySecurityBackend`, `FakeClock`, `StoreConformanceFactories`, `assert_security_backend_conformance` | [Custom Stores & Testing](https://cofin.github.io/litestar-security/customization.html) |

## Installation

```bash
uv add litestar-security
```

### Optional Extras

JWT and JWKS verification, OIDC token validation, Google IAP assertions, and API-key authentication ship in the core package. Install optional extras only for the local-account or OAuth capabilities a deployment uses:

| Extra | Install Command | Purpose |
| :--- | :--- | :--- |
| `argon2` | `uv add "litestar-security[argon2]"` | Argon2id password hashing via `Argon2PasswordHasher` |
| `mfa` | `uv add "litestar-security[mfa]"` | TOTP provisioning and login challenges (`MFAService`, `MFALoginService`), recovery codes, and step-up flows |
| `passkeys` | `uv add "litestar-security[passkeys]"` | WebAuthn passkey registration and assertion verification (`PyWebAuthnVerifier`) |
| `oauth` | `uv add "litestar-security[oauth]"` | OAuth 2.0 and OIDC lifecycle feature marker (zero extra third-party dependencies) |

Extras compose cleanly in a single install command:

```bash
uv add "litestar-security[argon2,mfa,passkeys]"
```

## Quickstart

Public routes must be explicit once an authentication mechanism is registered; unannotated routes compile to `required()` at startup and project their security schemes directly into OpenAPI:

```python
from litestar import Litestar, get
from litestar.di import NamedDependency

from litestar_security import (
    Principal,
    SecurityConfig,
    SecurityContext,
    SecurityPlugin,
    public,
    required,
    requires_tenant_role,
)


@get("/health", auth=public(), sync_to_thread=False)
def health(security_context: NamedDependency[SecurityContext]) -> dict[str, bool]:
    """Report request authentication state on an explicitly public route."""
    return {"authenticated": security_context.evidence is not None}


@get(
    "/tenants/{tenant_id:str}",
    auth=required(),
    guards=[requires_tenant_role(tenant_parameter="tenant_id", roles={"owner"})],
)
async def tenant_settings(
    tenant_id: str,
    principal: NamedDependency[Principal[object]],
) -> dict[str, str]:
    """Enforce authentication and tenant-scoped owner membership."""
    return {"tenant_id": tenant_id, "principal_id": principal.id or ""}


app = Litestar(
    route_handlers=[health, tenant_settings],
    plugins=[SecurityPlugin(SecurityConfig())],
)
```

Inspect the compiled policy, CSRF posture, and inherited guards for every registered route with the CLI plugin:

```bash
uv run litestar --app app:app security routes
```

Try the repository's runnable local session, token, hybrid, OAuth, IAP, and multi-tenant example applications:

```bash
LITESTAR_SECURITY_EXAMPLE=local-hybrid uv run litestar --app examples.app:create_app run
```

## Documentation

Full guides and API reference are published at **[https://cofin.github.io/litestar-security/](https://cofin.github.io/litestar-security/)**:

- **[Getting Started](https://cofin.github.io/litestar-security/getting-started.html)** — Installation, optional extras, session vs. token vs. hybrid local profiles, and runnable examples.
- **[Authentication & Guards](https://cofin.github.io/litestar-security/authentication.html)** — Compile-time route plans, `SecureController` and `PublicController`, authorization snapshots, and composable `requires_*` guards.
- **[Local Accounts, MFA & Passkeys](https://cofin.github.io/litestar-security/accounts.html)** — Account registration, password policy, rotating refresh families, TOTP, recovery codes, WebAuthn passkeys, step-up grants, and [generated `/auth` routes](https://cofin.github.io/litestar-security/generated-routes.html).
- **[External Identity Providers](https://cofin.github.io/litestar-security/providers.html)** — OAuth 2.0 and OIDC flows, Google Cloud IAP workload/human assertions, prefixed API keys, [JWT & JWKS](https://cofin.github.io/litestar-security/jwt-and-jwks.html), and [OAuth 2.1 resource-server metadata](https://cofin.github.io/litestar-security/resource-server.html).
- **[WebSocket Security](https://cofin.github.io/litestar-security/websockets.html)** — Policy-bound connect tokens, strict `Origin` checks, and live connection expiry/revocation supervision.
- **[Operations & Extending](https://cofin.github.io/litestar-security/hardening.html)** — [Plugin composition](https://cofin.github.io/litestar-security/composition.html), [rate limiting](https://cofin.github.io/litestar-security/rate-limiting.html), CSRF and CSP hardening, and [custom storage conformance testing](https://cofin.github.io/litestar-security/customization.html).
- **[API Reference](https://cofin.github.io/litestar-security/reference.html)** — Complete typed public API reference and [Changelog](https://cofin.github.io/litestar-security/changelog.html).

## Contributing & License

Contributions are welcome; see the [Contributing Guide](https://cofin.github.io/litestar-security/contributing.html) for local setup, boundary gates, and backend conformance testing. `litestar-security` supports Python 3.10 through 3.14 and is released under the [MIT License](LICENSE).
