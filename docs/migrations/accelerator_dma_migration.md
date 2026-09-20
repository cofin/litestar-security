# Accelerator DMA Migration Guide: Litestar Security & Litestar MCP Modernization

This guide documents the changes necessary for **Database Migration Accelerator (DMA)** (`dma`) to adopt the modernized architecture of `litestar-security` (v0.6.0+) and `litestar-mcp` (v0.14.0+).

A companion unified patch is available at [`docs/migrations/accelerator_dma.patch`](file:///home/cody/code/litestar/litestar-security/docs/migrations/accelerator_dma.patch).

---

## Overview of Changes

1. **Elimination of Bespoke Route Policy (`MCPRoutePolicy`)**:
   In previous versions of `litestar-mcp`, endpoint route options could not be configured directly on `MCPConfig`. DMA worked around this by implementing an `InitPluginProtocol` (`MCPRoutePolicy` in `dma/server/core.py`) to monkey-patch `handler.opt[AUTH_POLICY_OPT_KEY] = policy` onto every route under `/mcp`.
   With `litestar-mcp` v0.14.0+, `MCPConfig` natively accepts `route_opt`, which merges directly into the mounted MCP router. This makes `MCPRoutePolicy` obsolete.

2. **Removal of Obsolete `litestar_mcp.auth` Settings**:
   `litestar_mcp` v0.14.0 removed the bespoke `MCPAuthConfig` and `MCPAuthBackend` in favor of standard Litestar authentication middleware and route policies. `MCPSettings.get_auth_config()` in `dma/lib/settings.py` is removed.

3. **Consolidation of Internal `litestar-security` Imports**:
   DMA previously imported internal modules:
   - `from litestar_security.accounts._mfa import RecoveryCodePepper`
   - `from litestar_security.accounts._profiles import trusted_client_key`
   Both symbols are now curated and officially exported directly from `litestar_security.accounts`.

4. **Test Suite Modernization**:
   Unit tests in `tests/unit/server/mcp/test_config.py` are updated to assert on `cfg.route_opt[AUTH_POLICY_OPT_KEY]` rather than the removed `cfg.auth` object.

---

## Detailed Modifications

### 1. `src/py/dma/config.py`

In `_build_mcp_config`, configure `route_opt` with the Litestar Security authentication policy:

```python
from litestar_mcp import MCPConfig
from litestar_security.authentication import AUTH_POLICY_OPT_KEY, required

from dma.server.mcp.audit import mcp_audit_after_tool_call

policy = required("api-key", "google-iap") if settings.auth.IAP_ENABLED else required("api-key")

return MCPConfig(
    base_path=settings.mcp.BASE_PATH,
    include_in_schema=False,
    name="DMA MCP Server",
    allowed_origins=settings.mcp.ALLOWED_ORIGINS or None,
    route_opt={AUTH_POLICY_OPT_KEY: policy},
    cache_ttl_ms=settings.mcp.CACHE_TTL_MS,
    cache_scope=settings.mcp.CACHE_SCOPE,
    subscription_max_streams=settings.mcp.SUBSCRIPTION_MAX_STREAMS,
    subscription_keepalive_seconds=settings.mcp.SUBSCRIPTION_KEEPALIVE_SECONDS,
    subscription_channels=channels,
    after_tool_call=mcp_audit_after_tool_call,
    instructions=...,
)
```

### 2. `src/py/dma/server/core.py`

- Remove `from litestar_security.authentication import AUTH_POLICY_OPT_KEY, required`
- Remove the `MCPRoutePolicy` plugin class
- Remove `MCPRoutePolicy(...)` from the `core_plugins` list

### 3. `src/py/dma/lib/settings.py`

- Remove `from litestar_mcp.auth import MCPAuthConfig`
- Remove the `get_auth_config(self, auth: "AuthSettings") -> "MCPAuthConfig"` method from `MCPSettings`

### 4. `src/py/dma/domain/iam/_config.py`

Consolidate the accounts import block:

```python
from litestar_security.accounts import (
    AESGCMSecretProtector,
    LocalAuth,
    LocalAuthSecrets,
    RecoveryCodePepper,
    RegistrationMode,
    RegistrationPolicy,
    SecretProtectorKey,
    SessionBindingConfig,
    forwarded_client_key,
    trusted_client_key,
)
```

### 5. `src/py/tests/unit/server/mcp/test_config.py`

Update configuration tests to verify `route_opt`:

```python
from litestar_security.authentication import AUTH_POLICY_OPT_KEY

assert cfg.route_opt is not None
policy = cfg.route_opt[AUTH_POLICY_OPT_KEY]
mechanisms = {req.name for req in policy.requirements}
assert "api-key" in mechanisms
```

---

## Applying the Migration Patch

To apply the changes automatically to DMA Accelerator:

```bash
cd /path/to/dma/accelerator
git apply /path/to/litestar-security/docs/migrations/accelerator_dma.patch
```

### Verification Commands

Verify that tests and static type checking pass:

```bash
uv run pytest src/py/tests/unit/server/mcp/test_config.py
uv run pyright src/py/dma/config.py src/py/dma/domain/iam/_config.py src/py/dma/lib/settings.py src/py/dma/server/core.py src/py/tests/unit/server/mcp/test_config.py
```
