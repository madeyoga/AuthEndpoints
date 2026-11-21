---
title: AuthEndpoints.OpenIddict 4.0.0-preview.5
description: Delegated tokens are marked as agents, person-only APIs refuse them, metadata works under a PathBase, audit events follow the host's transaction, a per-address token rate limit, and validators that read the grant.
date: 2026-11-21
badge: Preview
tag: openiddict-v4.0.0-preview.5
---

### Breaking changes

- **AuthEndpoints 4.3.0 or later is required**, `[4.3.0, 5.0.0)`, because the package uses `CallerKinds` and `GetCallerKind` (#423).
- **Person-only APIs refuse tokens.** The consent API, the connected apps API, and the developer app API answer `403` to an OAuth access token or an API key, even when `AuthenticationScheme` is a host scheme that forwards tokens. A connected apps `DELETE` with a forwarded token now gets `403` instead of the antiforgery `400` (#423).

### People and agents

- **Delegated callers.** Every validated access token gets `ae:caller = delegated` and the RFC 8693 `act` claim, `{"client_id":"…"}`, on the validated principal, so tokens issued before this release are covered. `User.GetCallerKind()` and `User.GetActingClientId()` from AuthEndpoints 4.3.0 read them, and `RequireDirectPerson()` keeps a route for people. Set `AddAnyCallerScheme(o => o.BearerScheme = ValidationScheme)` to read each request with exactly one handler (#423).

### Fixes and changes

- **Protected resource metadata under a `PathBase`.** With `Issuer` `https://host/app/`, the document for `https://host/app/mcp` is served at the RFC 9728 location forwarded unchanged (`/.well-known/oauth-protected-resource/app/mcp`) and at the app-relative location (`/app/.well-known/oauth-protected-resource/mcp`). The `401` challenge keeps the RFC location; route it to the app at the reverse proxy. Startup logs a warning for accepted resources on the issuer's host outside the issuer path (#463).
- **Audit events follow the host's transaction.** Events raised while a transaction is open on the server's DbContext reach subscribers after it commits, and never if it rolls back. Without a transaction, events are raised at once, as before (#464).
- **Skipped last-used writes.** A last-used write that loses a concurrency race now reloads the grant, so a later update of the same grant in the token request succeeds (#465).
- **Per-address token rate limit.** With `TokenRateLimit.Enabled`, a request also needs a permit from a per-endpoint, per-IP limit, `PermitLimitPerAddress` (default 4 × `PermitLimit`), so made-up `client_id` values no longer get a fresh window each time (#466).
- **Validators can read the grant.** `IOAuthUserValidator.ValidateAsync(OAuthUserValidationContext, …)` gets the code or refresh token claims in `Grant` (internal and `oi_*` claims removed), with `UserId`, `SecurityStamp`, `GrantType`, `ClientId`, `AuthorizationId`, and `Scopes`. It defaults to `IsValidAsync`, so existing validators keep working. The [grant-context guide](/guides/oauth-grant-context) now reads the organization from `context.Grant` (#467).

This release adds no database migration.

### Packages

- **AuthEndpoints.OpenIddict** `4.0.0-preview.5`
- **AuthEndpoints** `4.3.0` or later required
- **AuthEndpoints.External.OAuth**, **AuthEndpoints.OAuth.GitHub**, and **AuthEndpoints.OAuth.Google** unchanged at `4.0.1`

### Links

- [GitHub release](https://github.com/madeyoga/AuthEndpoints/releases/tag/openiddict-v4.0.0-preview.5)
- [OAuth server docs](/modules/openiddict/)
- [People and agents](/modules/callers)
