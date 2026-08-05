.. title:: Litestar Security

.. meta::
   :description: Authentication and authorization for Litestar applications.
   :keywords: Litestar, security, authentication, authorization, plugin

Litestar Security
=================

Authentication and authorization for Litestar applications.

Litestar Security connects local accounts, external identity providers, API
keys, and workload tokens to Litestar's middleware, dependency injection,
guards, OpenAPI schema, and WebSocket lifecycle.

.. toctree::
   :hidden:
   :titlesonly:

   introduction
   getting-started
   authentication
   accounts
   providers
   generated-routes
   composition
   rate-limiting
   jwt-and-jwks
   resource-server
   websockets
   hardening
   customization
   examples
   reference
   contributing
   changelog

.. grid:: 1 1 2 2
   :gutter: 2

   .. grid-item-card:: Get started
      :link: getting-started
      :link-type: doc

      Install the plugin and choose an authentication method.

   .. grid-item-card:: Choose a provider
      :link: providers
      :link-type: doc

      Use local accounts, OAuth, OIDC, IAP, API keys, or workload JWTs.

   .. grid-item-card:: Protect routes
      :link: authentication
      :link-type: doc

      Declare public routes and enforce scopes, roles, teams, and tenants.

   .. grid-item-card:: Run an example
      :link: examples
      :link-type: doc

      Try each supported authentication method with local dependencies.

   .. grid-item-card:: API reference
      :link: reference
      :link-type: doc

      Browse the public packages and types.
