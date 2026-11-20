---
title: AuthEndpoints.OpenIddict 4.0.0-preview.3
description: Onboarding AI assistants and other OAuth clients: client ID metadata documents, readable scopes on the consent card, and a guide to exposing an MCP server with per-user OAuth.
date: 2026-11-20
badge: Preview
tag: openiddict-v4.0.0-preview.3
---

Builds on 4.0.0-preview.2.

### Breaking changes

- `OpenIddictApplications.ClientId` and `OAuthRequests.ClientId` are now 255 characters wide (were 100 and 64), so a client ID metadata document URL fits. Add a migration after upgrading, then apply it as you apply your other migrations:

  ```bash
  dotnet ef migrations add WidenOAuthClientId
  dotnet ef database update
  ```

### AuthEndpoints.OpenIddict

- **Client ID metadata documents (opt-in).** With `ClientMetadataDocuments.Enabled`, a client can use an `https` URL as its `client_id`, as the MCP authorization spec prefers. `/connect/authorize` fetches the document with SSRF protection (public addresses only, checked after DNS resolution and pinned for the connection; no redirects; a timeout; a 5 KB limit), caches it within `MinCacheDuration` and `MaxCacheDuration`, accepts only public clients under the dynamic registration redirect URI rules and `DynamicRegistration.AllowedScopes`, and stores the client in OpenIddict's application store. `AllowedHosts`, `DeniedHosts`, and `AddClientMetadataHostFilter<T>()` control which hosts are accepted. A re-fetched document whose `client_id` no longer matches revokes the client's authorizations and tokens; turning the option off also refuses code exchange and refresh for these clients. `FetchesPerMinute` (20 per caller IP) limits fetches. `private_key_jwt` is not supported yet. The metadata advertises `client_id_metadata_document_supported`, and the consent card has `clientHost` (#428).

- **Scope descriptions on the consent card.** `ScopeDefinitions` gives each scope a display name and description, optionally per culture (`DisplayNames`, `Descriptions`), in code or `appsettings`. `GET /oauth/requests/{id}` keeps `scopes` as a list of names and adds `scopeDetails: [{ name, displayName, description }]` in the same order, resolved for the request culture with parent-culture fallback. `OAuthPendingRequest.ScopeDetails` carries the same list. The text comes from a replaceable `IOAuthScopeDescriptions` (default: `ScopeDefinitions`; replace it with `AddScopeDescriptions<T>()`), so it can also come from a database or resource files. `scopes_supported` is unchanged (#448).

- **No cookie redirects for token callers.** A request with `Authorization: Bearer` now gets `401` or `403` where the Identity application cookie would redirect to its login or access-denied page, so a token caller refused on a route that also reads the cookie gets a status code it can act on. The host's cookie events (and `EventsType`) still run for every other request. On by default; `BearerRequestsSkipCookieRedirects = false` turns it off.

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
