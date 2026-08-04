"""WebSocket-specific transport policy.

Content Security Policy ``connect-src`` is complementary browser hardening. It
does not replace exact server-side Origin validation or credential policy.
"""

from litestar_security.websocket._bindings import (
    AuthorizationSnapshotRefresher,
    WebSocketBinding,
    WebSocketHandshake,
    WebSocketRevocationSource,
)
from litestar_security.websocket._config import WebSocketCloseCodes, WebSocketSecurityConfig
from litestar_security.websocket._connect_tokens import (
    InMemoryWebSocketConnectTokenStore,
    IssuedWebSocketConnectToken,
    WebSocketConnectTokenIssuer,
    WebSocketConnectTokenRecord,
    WebSocketConnectTokenService,
    WebSocketConnectTokenStore,
    issue_websocket_connect_token,
)
from litestar_security.websocket._connect_tokens import (
    WebSocketConnectTokenUnavailableError as WebSocketConnectTokenUnavailableError,
)
from litestar_security.websocket._handshake import extract_websocket_handshake
from litestar_security.websocket._lifecycle import WebSocketCloseCoordinator as WebSocketCloseCoordinator
from litestar_security.websocket._lifecycle import close_websocket as close_websocket
from litestar_security.websocket._lifecycle import supervise_websocket_lifetime as supervise_websocket_lifetime
from litestar_security.websocket._lifecycle import websocket_policy_fingerprint

__all__ = (
    "AuthorizationSnapshotRefresher",
    "InMemoryWebSocketConnectTokenStore",
    "IssuedWebSocketConnectToken",
    "WebSocketBinding",
    "WebSocketCloseCodes",
    "WebSocketConnectTokenIssuer",
    "WebSocketConnectTokenRecord",
    "WebSocketConnectTokenService",
    "WebSocketConnectTokenStore",
    "WebSocketHandshake",
    "WebSocketRevocationSource",
    "WebSocketSecurityConfig",
    "extract_websocket_handshake",
    "issue_websocket_connect_token",
    "websocket_policy_fingerprint",
)
