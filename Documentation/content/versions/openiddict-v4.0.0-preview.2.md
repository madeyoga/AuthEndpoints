---
title: AuthEndpoints.OpenIddict 4.0.0-preview.2
description: Per-user OAuth for APIs and MCP servers on the same host, with roles on access tokens, scope checks, per-resource metadata, and a breaking change to where access tokens are read from.
date: 2026-11-20
badge: Preview
tag: openiddict-v4.0.0-preview.2
---

### Breaking changes

- Access tokens are read only from the `Authorization: Bearer` header. Earlier builds also accepted the `access_token` query parameter and form field on every route. SignalR and WebSocket hosts list their path prefixes in `QueryStringTokenPaths` to keep `?access_token=` there (#418).
- The package now requires AuthEndpoints `4.2.0` or later, `[4.2.0, 5.0.0)`, because it uses `AuthEndpointsAntiforgeryOptions.BearerSchemes` and `RequireAntiforgery(allowBearer:)`.

### AuthEndpoints.OpenIddict

- **Roles and the user id on access tokens (opt-in).** `AccessTokenClaims.Roles` and `AccessTokenClaims.UserId` put the approving user's Identity roles and `ClaimTypes.NameIdentifier` (plus `UserIdClaimType`) on the access token only, so `RequireRole` and `UserManager.GetUserId` work for token callers. Roles are read again on every refresh. Both are off by default (#439).
- **Scope checks.** `RequireOAuthScope(...)` requires scopes on routes that only take tokens. `RequireOAuthScopeWhenDelegated(...)` sits next to an existing role policy on routes that cookie users share. `ClaimsPrincipal` helpers `IsOAuthDelegated()`, `GetOAuthScopes()` and `HasOAuthScope()` are for checks inside services (#440).
- **Protected resource metadata per resource.** `Audience` and accepted resources with a path get RFC 9728 path-suffixed documents, such as `/.well-known/oauth-protected-resource/mcp`. `ProtectedResource.Resources` sets each one's name, scopes and challenge paths, and the `401` challenge points at the matching document (#441).
- **More than one resource on one host.** `AcceptedAudiences` lets this host accept tokens for some `AdditionalResources`, and `RequireOAuthAudience(...)` keeps each token on its own routes (#417).
- **Scopes for registered clients.** `DynamicRegistration.AllowedScopes` limits the scopes a dynamically registered client may hold (#416).
- **CSRF and tokens.** The validation scheme is added to `AuthEndpointsAntiforgeryOptions.BearerSchemes`, so `RequireAntiforgery()` lets an access token in the header skip the CSRF check. The package's own consent and developer app writes use `RequireAntiforgery(allowBearer: false)` (#429).

### Packages

- **AuthEndpoints.OpenIddict** `4.0.0-preview.2`
- **AuthEndpoints** `4.2.0` or later required
- **AuthEndpoints.External.OAuth**, **AuthEndpoints.OAuth.GitHub**, and **AuthEndpoints.OAuth.Google** unchanged at `4.0.1`

### Links

- [GitHub release](https://github.com/madeyoga/AuthEndpoints/releases/tag/openiddict-v4.0.0-preview.2)
- [OAuth server docs](/modules/openiddict/)
