---
title: AuthEndpoints.OpenIddict 4.0.0-preview.3
description: Onboarding AI assistants and other OAuth clients: client ID metadata documents, readable scopes on the consent card, and a guide to exposing an MCP server with per-user OAuth.
date: 2026-11-20
badge: Preview
tag: openiddict-v4.0.0-preview.3
---

Builds on [4.0.0-preview.2](/versions/openiddict-v4.0.0-preview.2). Work in progress: each change adds its entry below.

### Breaking changes

- None yet.

### AuthEndpoints.OpenIddict

- Client ID metadata documents: pending.

- Scope descriptions on the consent card: pending.

- **No cookie redirects for token callers.** A request with `Authorization: Bearer` now gets `401` or `403` where the Identity application cookie would redirect to its login or access-denied page, so a token caller refused on a route that also reads the cookie gets a status code it can act on. The host's cookie events (and `EventsType`) still run for every other request. On by default; `BearerRequestsSkipCookieRedirects = false` turns it off.

### Documentation

- **Guide: [Expose an MCP server with per-user OAuth](/guides/mcp-server-oauth).** One walk through the whole flow: protected resource metadata and the `401` challenge, client ID metadata documents or dynamic registration, the consent page with `clientHost` and `scopeDetails`, resource indicators, `AccessTokenClaims`, `RequireOAuthAudience`, the scope helpers, and disconnecting. The package README has a short version, and the skill has a new `references/mcp-server.md`.

### Packages

- **AuthEndpoints.OpenIddict** `4.0.0-preview.3`
- **AuthEndpoints** `4.2.0` or later required
- **AuthEndpoints.External.OAuth**, **AuthEndpoints.OAuth.GitHub**, and **AuthEndpoints.OAuth.Google** unchanged at `4.0.1`

### Links

- [GitHub release](https://github.com/madeyoga/AuthEndpoints/releases/tag/openiddict-v4.0.0-preview.3)
- [OAuth server docs](/modules/openiddict/)
