---
title: AuthEndpoints.OpenIddict 4.0.0-preview.4
description: Per-user OAuth for APIs and MCP servers, with roles on access tokens, scope checks, per-resource metadata, client ID metadata documents, readable scopes on the consent card, connected apps, audit events, and token endpoint rate limits.
date: 2026-11-20
badge: Preview
tag: openiddict-v4.0.0-preview.4
---

The first preview since 4.0.0-preview.1. Previews 2 and 3 were not published; their changes are all listed here.

### Breaking changes

- **AuthEndpoints 4.2.0 or later is required**, `[4.2.0, 5.0.0)`, because the package uses `AuthEndpointsAntiforgeryOptions.BearerSchemes` and `RequireAntiforgery(allowBearer:)`.
- **Access tokens are read only from the `Authorization: Bearer` header.** Earlier builds also accepted the `access_token` query parameter and form field on every route. SignalR and WebSocket hosts list their path prefixes in `QueryStringTokenPaths` to keep `?access_token=` there (#418).
- **Wider client id columns.** `OpenIddictApplications.ClientId` and `OAuthRequests.ClientId` are now 255 characters wide (were 100 and 64), so a client ID metadata document URL fits. Add a migration after upgrading, then apply it as you apply your other migrations:

  ```bash
  dotnet ef migrations add WidenOAuthClientId
  dotnet ef database update
  ```

- **No cookie redirects for token callers.** A request with `Authorization: Bearer` now gets `401` or `403` where the Identity application cookie would redirect to its login or access-denied page, so a token caller refused on a route that also reads the cookie gets a status code it can act on. The host's cookie events (and `EventsType`) still run for every other request. On by default; `BearerRequestsSkipCookieRedirects = false` turns it off.

### Tokens and authorization

- **Roles and the user id on access tokens (opt-in).** `AccessTokenClaims.Roles` and `AccessTokenClaims.UserId` put the approving user's Identity roles and `ClaimTypes.NameIdentifier` (plus `UserIdClaimType`) on the access token only, so `RequireRole` and `UserManager.GetUserId` work for token callers. Roles are read again on every refresh. Both are off by default (#439).
- **Scope checks.** `RequireOAuthScope(...)` requires scopes on routes that only take tokens. `RequireOAuthScopeWhenDelegated(...)` sits next to an existing role policy on routes that cookie users share. `ClaimsPrincipal` helpers `IsOAuthDelegated()`, `GetOAuthScopes()` and `HasOAuthScope()` are for checks inside services (#440).
- **More than one resource on one host.** `AcceptedAudiences` lets this host accept tokens for some `AdditionalResources`, and `RequireOAuthAudience(...)` keeps each token on its own routes (#417).
- **CSRF and tokens.** The validation scheme is added to `AuthEndpointsAntiforgeryOptions.BearerSchemes`, so `RequireAntiforgery()` lets an access token in the header skip the CSRF check. The package's own consent, developer app and connected app writes use `RequireAntiforgery(allowBearer: false)` (#429).

### Clients and discovery

- **Protected resource metadata per resource.** `Audience` and accepted resources with a path get RFC 9728 path-suffixed documents, such as `/.well-known/oauth-protected-resource/mcp`. `ProtectedResource.Resources` sets each one's name, scopes and challenge paths, and the `401` challenge points at the matching document (#441).
- **Client ID metadata documents (opt-in).** With `ClientMetadataDocuments.Enabled`, a client can use an `https` URL as its `client_id`, as the MCP authorization spec prefers. `/connect/authorize` fetches the document with SSRF protection (public addresses only, checked after DNS resolution and pinned for the connection; no redirects; a timeout; a 5 KB limit), caches it within `MinCacheDuration` and `MaxCacheDuration`, accepts only public clients under the dynamic registration redirect URI rules and `DynamicRegistration.AllowedScopes`, and stores the client in OpenIddict's application store. `AllowedHosts`, `DeniedHosts`, and `AddClientMetadataHostFilter<T>()` control which hosts are accepted. A re-fetched document whose `client_id` no longer matches revokes the client's authorizations and tokens; turning the option off also refuses code exchange and refresh for these clients. `FetchesPerMinute` (20 per caller IP) limits fetches. `private_key_jwt` is not supported yet. The metadata advertises `client_id_metadata_document_supported`, and the consent card has `clientHost` (#428).
- **Scopes for registered clients.** `DynamicRegistration.AllowedScopes` limits the scopes a dynamically registered client may hold (#416).

### Consent and connected apps

- **Scope descriptions on the consent card.** `ScopeDefinitions` gives each scope a display name and description, optionally per culture (`DisplayNames`, `Descriptions`), in code or `appsettings`. `GET /oauth/requests/{id}` keeps `scopes` as a list of names and adds `scopeDetails: [{ name, displayName, description }]` in the same order, resolved for the request culture with parent-culture fallback. `OAuthPendingRequest.ScopeDetails` carries the same list. The text comes from a replaceable `IOAuthScopeDescriptions` (default: `ScopeDefinitions`; replace it with `AddScopeDescriptions<T>()`), so it can also come from a database or resource files. `scopes_supported` is unchanged (#448).
- **Connected apps.** `GET /oauth/authorizations` lists the signed-in user's live grants (`authorizationId`, `clientId`, `clientName`, `clientKind`, `clientHost`, `scopes`, `scopeDetails`, `resource`, `createdAt`, `lastUsedAt`), and `DELETE /oauth/authorizations/{id}` disconnects one after an ownership check. Mapped by `MapOAuthServer` (`parts.ConnectedApps`, `parts.ConnectedAppsPrefix`) or `MapOAuthConnectedAppEndpoints`; cookie only, and the `DELETE` needs a CSRF token. `IOAuthConnectedAppService` lists and revokes for any user id, for admin pages (#455).

### Operations

- **Audit events.** `IOAuthServerEvents` subscribers, registered with `AddServerEvents<T>()`, hear about consent approved or denied, code exchanged, token refreshed, a grant refused by user revalidation, a grant revoked (`RevokedBy`: user, admin, cleanup, or a deleted client), and a client registered (dynamic registration, metadata document, or developer app). Each `OAuthServerEvent` has the user id, client id, client kind (`OAuthClientKinds`), authorization id, scopes and resource, and never a token or secret. A subscriber that throws is logged and skipped. The approving user's id and the resource are now stored on every authorization, not only with OpenID Connect (#451).
- **Last used (opt-in).** `RecordLastUsed` writes when each grant was last used, at the code exchange and at a refresh, at most once per `LastUsedInterval` (default 1 hour) (#451).
- **Rate limits on the token and revocation endpoints (opt-in).** `TokenRateLimit` limits `/connect/token` and `/connect/revoke` per endpoint, client id, and IP address (default 60 per minute when enabled), inside OpenIddict before client authentication or any database read. A rejected request gets `429` with `{"error":"temporarily_unavailable"}` and `Retry-After`. `AddTokenRateLimiter(...)` takes any `PartitionedRateLimiter<OAuthRateLimitContext>` (endpoint, client id, `HttpContext`) instead (#458).

### Documentation

- **Guide: [Expose an MCP server with per-user OAuth](/guides/mcp-server-oauth).** One walk through the whole flow: protected resource metadata and the `401` challenge, client ID metadata documents or dynamic registration, the consent page with `clientHost` and `scopeDetails`, resource indicators, `AccessTokenClaims`, `RequireOAuthAudience`, the scope helpers, and disconnecting. The package README has a short version, and the skill has a new `references/mcp-server.md`.
- **Guide: [Bind a host context to an OAuth grant](/guides/oauth-grant-context).** Bind an organization, workspace, or region chosen at consent to the grant with `ApproveAsync(…, createPrincipal)`, read it from the token instead of the person's current context, and re-check membership at every refresh with a validator that wraps `IdentityOAuthUserValidator<TUser>`. The package tests run the guide's code (#460).

### Known limitations

- Per-resource metadata is not reachable when the app runs under a `PathBase` (#463).
- Consent and revoke events fire before a host's own transaction commits (#464).
- The default token rate limit can be bypassed by rotating `client_id` values; use `AddTokenRateLimiter` for a strict per-IP limit until #466 lands.

### Packages

- **AuthEndpoints.OpenIddict** `4.0.0-preview.4`
- **AuthEndpoints** `4.2.0` or later required
- **AuthEndpoints.External.OAuth**, **AuthEndpoints.OAuth.GitHub**, and **AuthEndpoints.OAuth.Google** unchanged at `4.0.1`

### Links

- [GitHub release](https://github.com/madeyoga/AuthEndpoints/releases/tag/openiddict-v4.0.0-preview.4)
- [OAuth server docs](/modules/openiddict/)
