.. title:: Litestar Security

.. meta::
   :description: Typed authentication, authorization, and provider integration for Litestar.
   :keywords: Litestar, security, authentication, authorization, plugin

Litestar Security
=================

Litestar Security 1.0 provides typed, backend-agnostic security integration for
Litestar: explicit local transports, provider authentication, policy and guard
algebra, account lifecycle, WebSockets, browser headers, and conformance tools.

.. toctree::
   :hidden:
   :titlesonly:

   introduction
   getting-started
   authentication
   accounts
   websockets
   customization
   hardening
   examples
   development-installation
   jwt-and-jwks
   generated-routes
   rate-limiting
   contributing
   reference
   changelog

.. grid:: 1 1 2 2
   :gutter: 2

   .. grid-item-card:: Choose a transport
      :link: getting-started
      :link-type: doc

      Configure an explicit session, token, hybrid, or provider boundary.

   .. grid-item-card:: Authentication and policy
      :link: authentication
      :link-type: doc

      Compose strict credential handling, route policy, guards, and OpenAPI.

   .. grid-item-card:: Accounts and factors
      :link: accounts
      :link-type: doc

      Build local lifecycle, refresh, MFA, passkey, and step-up workflows.

   .. grid-item-card:: Hardening
      :link: hardening
      :link-type: doc

      Operate CSRF, CSP, JWKS, secrets, workers, and revocation safely.

   .. grid-item-card:: Runnable examples
      :link: examples
      :link-type: doc

      Boot every supported example mode with deterministic local dependencies.

   .. grid-item-card:: JWT and JWKS
      :link: jwt-and-jwks
      :link-type: doc

      Configure explicit local keys, strict discovery, and bounded rotation.

   .. grid-item-card:: API reference
      :link: reference
      :link-type: doc

      Browse the package metadata, configuration, and plugin classes.
