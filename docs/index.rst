:layout: landing
:description: Storage-agnostic authentication, authorization, local account lifecycle, external identity providers, and WebSocket security for Litestar.

.. title:: Litestar Security

.. meta::
   :keywords: Litestar, security, authentication, authorization, OAuth2, OIDC, JWT, JWKS, passkeys, WebAuthn, MFA, API keys, WebSockets

.. container::
   :name: home-head

   .. raw:: html

      <div class="ls-hero">
          <img src="_static/banner-inline-light.svg" alt="Litestar Security" class="ls-hero-banner ls-hero-banner--light" width="760" height="184" />
          <img src="_static/banner-inline-dark.svg" alt="Litestar Security" class="ls-hero-banner ls-hero-banner--dark" width="760" height="184" />
      </div>

   .. container:: badges
      :name: badges

      .. image:: https://img.shields.io/github/actions/workflow/status/cofin/litestar-security/ci.yml?labelColor=202235&logo=github&logoColor=edb641&label=CI
         :alt: GitHub Actions CI Workflow Status
         :target: https://github.com/cofin/litestar-security/actions/workflows/ci.yml

      .. image:: https://img.shields.io/github/actions/workflow/status/cofin/litestar-security/docs.yml?labelColor=202235&logo=github&logoColor=edb641&label=Docs
         :alt: Documentation Build Workflow Status
         :target: https://github.com/cofin/litestar-security/actions/workflows/docs.yml

      .. image:: https://img.shields.io/pypi/v/litestar-security?labelColor=202235&color=edb641&logo=python&logoColor=edb641
         :alt: PyPI Version
         :target: https://pypi.org/project/litestar-security/

      .. image:: https://img.shields.io/pypi/pyversions/litestar-security?labelColor=202235&color=edb641&logo=python&logoColor=edb641
         :alt: Supported Python Versions
         :target: https://pypi.org/project/litestar-security/

      .. image:: https://img.shields.io/pypi/l/litestar-security?labelColor=202235&color=edb641
         :alt: MIT License
         :target: https://github.com/cofin/litestar-security/blob/main/LICENSE

.. rst-class:: lead

   Storage-agnostic authentication, authorization, account lifecycle, and WebSocket security for `Litestar <https://litestar.dev/>`_.

Litestar Security connects :doc:`local accounts <accounts>`, :doc:`external identity providers <providers>`, API keys, and workload JWTs to Litestar's middleware, dependency injection, :doc:`authorization guards <authentication>`, OpenAPI schema, and :doc:`WebSocket lifecycle <websockets>` without coupling your application to an ORM, database driver, or cache SDK.

.. container:: buttons wrap

   .. raw:: html

      <a href="getting-started.html" class="ls-btn ls-btn--primary btn-no-wrap">Get Started</a>
      <a href="providers.html" class="ls-btn ls-btn--secondary btn-no-wrap">Choose a Provider</a>
      <a href="accounts.html" class="ls-btn ls-btn--secondary btn-no-wrap">Local Accounts</a>
      <a href="reference.html" class="ls-btn ls-btn--secondary btn-no-wrap">API Reference</a>

.. grid:: 1 1 2 2
   :padding: 0
   :gutter: 3

   .. grid-item-card:: Getting Started
      :link: getting-started
      :link-type: doc

      Install the core package with only the optional extras your deployment uses and mount ``SecurityPlugin`` in minutes.

   .. grid-item-card:: Authentication & Guards
      :link: authentication
      :link-type: doc

      Compile route policies at startup and enforce roles, scopes, tenant memberships, capabilities, and fresh step-up assurance.

   .. grid-item-card:: Local Accounts, MFA & Passkeys
      :link: accounts
      :link-type: doc

      Run browser sessions, rotating refresh-token families, or hybrid profiles with TOTP, recovery codes, WebAuthn passkeys, and step-up grants.

   .. grid-item-card:: External Identity Providers
      :link: providers
      :link-type: doc

      Verify OAuth 2.0 and OIDC callbacks, Google Cloud IAP assertions, workload JWTs backed by bounded JWKS caches, and prefixed API keys.

   .. grid-item-card:: WebSockets & Resource Servers
      :link: websockets
      :link-type: doc

      Issue policy-bound connect tokens, supervise open socket expiry and revocation, and publish RFC 9728 protected-resource metadata.

   .. grid-item-card:: Custom Stores & Conformance
      :link: customization
      :link-type: doc

      Implement narrow persistence protocols against any database or cache and validate adapters with ``assert_security_backend_conformance``.

.. toctree::
   :hidden:
   :titlesonly:
   :caption: Getting Started

   Introduction <introduction>
   Getting Started <getting-started>
   Authentication & Guards <authentication>
   Runnable Examples <examples>

.. toctree::
   :hidden:
   :titlesonly:
   :caption: Accounts & Providers

   Local Accounts, MFA & Passkeys <accounts>
   Generated Routes <generated-routes>
   External Providers <providers>
   JWT Signing & JWKS <jwt-and-jwks>
   OAuth 2.1 Resource Server <resource-server>
   WebSocket Security <websockets>

.. toctree::
   :hidden:
   :titlesonly:
   :caption: Operations & Extending

   Composing Plugins <composition>
   Rate Limiting <rate-limiting>
   Hardening & Headers <hardening>
   Custom Stores & Testing <customization>

.. toctree::
   :hidden:
   :titlesonly:
   :caption: Reference & Project

   API Reference <reference>
   Contributing <contributing>
   Changelog <changelog>
