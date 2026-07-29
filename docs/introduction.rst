Introduction
============

Litestar Security provides typed, backend-agnostic authentication and
authorization for Litestar applications. The plugin owns framework integration;
the application owns identity, persistence, key custody, delivery, and
deployment trust.

Stable 1.0 model
----------------

The current runtime provides:

``Principal[UserT]`` is always present. Anonymous callers receive an anonymous
principal; authenticated service principals may intentionally have no
application ``UserT``. ``SecurityContext`` always carries evidence,
authorization, credential restrictions, and either a native
``LitestarSessionHandle`` or ``NullSessionHandle``.

Authentication answers who presented acceptable evidence. Route policy decides
which evidence combinations are admitted. Guards evaluate application
authorization snapshots. Session persistence, CSRF, OpenAPI, exceptions, and
WebSocket close outcomes are composed through native Litestar boundaries.

Applications implement small atomic protocols. They may use async ports
directly, explicitly normalize complete synchronous integrations with
``BlockingIntegration``, and validate stores with the public conformance kit.
No adapter dependency or application database leaks into core.
