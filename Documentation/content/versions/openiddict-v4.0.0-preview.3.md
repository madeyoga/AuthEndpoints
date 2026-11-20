---
title: AuthEndpoints.OpenIddict 4.0.0-preview.3
description: Onboarding AI assistants and other OAuth clients: client ID metadata documents, readable scopes on the consent card, and a guide to exposing an MCP server with per-user OAuth.
date: 2026-11-20
badge: Preview
tag: openiddict-v4.0.0-preview.3
---

Builds on [4.0.0-preview.2](/versions/openiddict-v4.0.0-preview.2). Work in progress: each change adds its entry below.

### Breaking changes

- `OpenIddictApplications.ClientId` and `OAuthRequests.ClientId` are now 255 characters wide (were 100 and 64), so a client ID metadata document URL fits. Add a migration after upgrading.

### AuthEndpoints.OpenIddict

- **Client ID metadata documents (opt-in).** With `ClientMetadataDocuments.Enabled`, a client can use an `https` URL as its `client_id`, as the MCP authorization spec prefers. `/connect/authorize` fetches the document with SSRF protection (public addresses only, checked after DNS resolution and pinned for the connection; no redirects; a timeout; a 5 KB limit), caches it within `MinCacheDuration` and `MaxCacheDuration`, accepts only public clients under the dynamic registration redirect URI rules and `DynamicRegistration.AllowedScopes`, and stores the client in OpenIddict's application store. `AllowedHosts`, `DeniedHosts`, and `AddClientMetadataHostFilter<T>()` control which hosts are accepted. The metadata advertises `client_id_metadata_document_supported`, and the consent card has `clientHost` (#428).

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
