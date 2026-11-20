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

- **Scope descriptions on the consent card.** `ScopeDefinitions` gives each scope a display name and description, optionally per culture (`DisplayNames`, `Descriptions`), in code or `appsettings`. `GET /oauth/requests/{id}` keeps `scopes` as a list of names and adds `scopeDetails: [{ name, displayName, description }]` in the same order, resolved for the request culture with parent-culture fallback. `OAuthPendingRequest.ScopeDetails` carries the same list (#448).

### Documentation

- MCP server guide: pending.

### Packages

- **AuthEndpoints.OpenIddict** `4.0.0-preview.3`
- **AuthEndpoints** `4.2.0` or later required
- **AuthEndpoints.External.OAuth**, **AuthEndpoints.OAuth.GitHub**, and **AuthEndpoints.OAuth.Google** unchanged at `4.0.1`

### Links

- [GitHub release](https://github.com/madeyoga/AuthEndpoints/releases/tag/openiddict-v4.0.0-preview.3)
- [OAuth server docs](/modules/openiddict/)
