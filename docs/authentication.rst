Authentication and authorization
================================

Credential slots own physical transport locations. A presented malformed or
invalid credential is terminal; it is never treated as absence to unlock a
weaker alternative. Successful credentials must resolve to the same subject,
and credential-granted scopes, teams, roles, capabilities, tenants, and
resource permissions intersect.

Use ``public()``, ``required()``, ``any_of()``, ``all_of()``, or ``at_least()``
in route ``security(...)`` metadata. Runtime admission and native OpenAPI
security projection compile from the same normalized policy. Authentication
failure is ``401``, guard denial is ``403``, and unavailable verification fails
closed as ``503``.

Authorization guards compose separately:

* ``requires_scope`` and ``requires_capability``;
* ``requires_role`` and ``requires_team_role``;
* ``requires_tenant``; and
* ``requires_assurance`` for recent or stronger evidence.

The ``principal`` and ``security_context`` dependencies remain typed on public
and protected routes. ``current_user`` is the explicit narrowing dependency
that rejects anonymous and userless service principals.

See :doc:`providers` to choose and configure an authentication source.
