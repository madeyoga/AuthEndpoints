---
title: AuthEndpoints.OpenIddict 4.0.0-preview.4
description: User control and operations for the OAuth server: connected apps, rate limits on the token and revocation endpoints, audit events, and binding a host context to a grant.
date: 2026-11-20
badge: Preview
tag: openiddict-v4.0.0-preview.4
---

Builds on [4.0.0-preview.3](/versions/openiddict-v4.0.0-preview.3). Work in progress: each change adds its entry below.

### AuthEndpoints.OpenIddict

- **Rate limits on the token and revocation endpoints (opt-in).** `TokenRateLimit` limits `/connect/token` and `/connect/revoke` per endpoint, client id, and IP address (default 60 per minute when enabled), inside OpenIddict before client authentication or any database read. A rejected request gets `429` with `{"error":"temporarily_unavailable"}` and `Retry-After`. `AddTokenRateLimiter(...)` takes any `PartitionedRateLimiter<OAuthRateLimitContext>` (endpoint, client id, `HttpContext`) instead (#458).
### Documentation

### Packages

- **AuthEndpoints.OpenIddict** `4.0.0-preview.4`
- **AuthEndpoints** `4.2.0` or later required
- **AuthEndpoints.External.OAuth**, **AuthEndpoints.OAuth.GitHub**, and **AuthEndpoints.OAuth.Google** unchanged at `4.0.1`

### Links

- [GitHub release](https://github.com/madeyoga/AuthEndpoints/releases/tag/openiddict-v4.0.0-preview.4)
- [OAuth server docs](/modules/openiddict/)
