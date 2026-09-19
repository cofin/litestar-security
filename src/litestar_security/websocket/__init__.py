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
    WebSocketConnectAuthorization,
    WebSocketConnectTokenIssuer,
    WebSocketConnectTokenService,
    WebSocketConnectTokenStore,
    authenticate_connect_token,
    issue_websocket_connect_token,
    merge_connect_token,
)
from litestar_security.websocket._connect_tokens import (
    WebSocketConnectTokenUnavailableError as WebSocketConnectTokenUnavailableError,
)
from litestar_security.websocket._handshake import extract_websocket_handshake
from litestar_security.websocket._lifecycle import WebSocketCloseCoordinator as WebSocketCloseCoordinator
from litestar_security.websocket._lifecycle import close_websocket as close_websocket
from litestar_security.websocket._lifecycle import (
    create_websocket_binding,
    handle_websocket,
    websocket_policy_fingerprint,
    websocket_route_name,
)
from litestar_security.websocket._lifecycle import supervise_websocket_lifetime as supervise_websocket_lifetime

__all__ = (
    "AuthorizationSnapshotRefresher",
    "InMemoryWebSocketConnectTokenStore",
    "IssuedWebSocketConnectToken",
    "WebSocketBinding",
    "WebSocketCloseCodes",
    "WebSocketConnectAuthorization",
    "WebSocketConnectTokenIssuer",
    "WebSocketConnectTokenService",
    "WebSocketConnectTokenStore",
    "WebSocketHandshake",
    "WebSocketRevocationSource",
    "WebSocketSecurityConfig",
    "authenticate_connect_token",
    "create_websocket_binding",
    "extract_websocket_handshake",
    "handle_websocket",
    "issue_websocket_connect_token",
    "merge_connect_token",
    "websocket_policy_fingerprint",
    "websocket_route_name",
)
