.. title:: Litestar Security

.. meta::
   :description: A typed, pre-alpha security integration scaffold for Litestar.
   :keywords: Litestar, security, authentication, authorization, plugin

Litestar Security
=================

Litestar Security is a pre-alpha plugin library for typed security integrations
in Litestar applications. Its initial runtime includes authentication policy,
guards, local JWT signing, strict OIDC discovery, and bounded JWKS rotation.

.. toctree::
   :hidden:
   :titlesonly:

   introduction
   development-installation
   plugin-scaffold
   jwt-and-jwks
   contributing
   reference
   changelog

.. grid:: 1 1 2 2
   :gutter: 2

   .. grid-item-card:: Introduction
      :link: introduction
      :link-type: doc

      Learn what the initial scaffold includes and what remains out of scope.

   .. grid-item-card:: Development installation
      :link: development-installation
      :link-type: doc

      Install the locked environment and run the local validation commands.

   .. grid-item-card:: Plugin scaffold
      :link: plugin-scaffold
      :link-type: doc

      Add the typed security plugin to a Litestar application.

   .. grid-item-card:: JWT and JWKS
      :link: jwt-and-jwks
      :link-type: doc

      Configure explicit local keys, strict discovery, and bounded rotation.

   .. grid-item-card:: API reference
      :link: reference
      :link-type: doc

      Browse the package metadata, configuration, and plugin classes.
