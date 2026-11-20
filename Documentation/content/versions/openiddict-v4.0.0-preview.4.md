---
title: AuthEndpoints.OpenIddict 4.0.0-preview.4
description: User control and operations for the OAuth server: connected apps, rate limits on the token and revocation endpoints, audit events, and binding a host context to a grant.
date: 2026-11-20
badge: Preview
tag: openiddict-v4.0.0-preview.4
---

Builds on 4.0.0-preview.3. Work in progress: each change adds its entry below.

### AuthEndpoints.OpenIddict

- **Connected apps.** `GET /oauth/authorizations` lists the signed-in user's live grants (`authorizationId`, `clientId`, `clientName`, `clientKind`, `clientHost`, `scopes`, `scopeDetails`, `resource`, `createdAt`, `lastUsedAt`), and `DELETE /oauth/authorizations/{id}` disconnects one after an ownership check. Mapped by `MapOAuthServer` (`parts.ConnectedApps`, `parts.ConnectedAppsPrefix`) or `MapOAuthConnectedAppEndpoints`; cookie only, and the `DELETE` needs a CSRF token. `IOAuthConnectedAppService` lists and revokes for any user id, for admin pages (#455).
- **Audit events.** `IOAuthServerEvents` subscribers, registered with `AddServerEvents<T>()`, hear about consent approved or denied, code exchanged, token refreshed, a grant refused by user revalidation, a grant revoked (`RevokedBy`: user, admin, cleanup, or a deleted client), and a client registered (dynamic registration, metadata document, or developer app). Each `OAuthServerEvent` has the user id, client id, client kind (`OAuthClientKinds`), authorization id, scopes and resource, and never a token or secret. A subscriber that throws is logged and skipped. The approving user's id and the resource are now stored on every authorization, not only with OpenID Connect (#451).
- **Last used (opt-in).** `RecordLastUsed` writes when each grant was last used, at the code exchange and at a refresh, at most once per `LastUsedInterval` (default 1 hour) (#451).
- **Rate limits on the token and revocation endpoints (opt-in).** `TokenRateLimit` limits `/connect/token` and `/connect/revoke` per endpoint, client id, and IP address (default 60 per minute when enabled), inside OpenIddict before client authentication or any database read. A rejected request gets `429` with `{"error":"temporarily_unavailable"}` and `Retry-After`. `AddTokenRateLimiter(...)` takes any `PartitionedRateLimiter<OAuthRateLimitContext>` (endpoint, client id, `HttpContext`) instead (#458).
### Documentation

- **Guide: [Bind a host context to an OAuth grant](/guides/oauth-grant-context).** Bind an organization, workspace, or region chosen at consent to the grant with `ApproveAsync(…, createPrincipal)`, read it from the token instead of the person's current context, and re-check membership at every refresh with a validator that wraps `IdentityOAuthUserValidator<TUser>`. The package tests run the guide's code (#460).

### Packages

- **AuthEndpoints.OpenIddict** `4.0.0-preview.4`
- **AuthEndpoints** `4.2.0` or later required
- **AuthEndpoints.External.OAuth**, **AuthEndpoints.OAuth.GitHub**, and **AuthEndpoints.OAuth.Google** unchanged at `4.0.1`

### Links

- [GitHub release](https://github.com/madeyoga/AuthEndpoints/releases/tag/openiddict-v4.0.0-preview.4)
- [OAuth server docs](/modules/openiddict/)
