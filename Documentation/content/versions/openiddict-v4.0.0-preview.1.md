---
title: AuthEndpoints.OpenIddict 4.0.0-preview.1
description: New opt-in OAuth 2.0 authorization server for AuthEndpoints 4 apps, built on OpenIddict 7.7.
date: 2026-11-04
badge: Preview
tag: openiddict-v4.0.0-preview.1
---

### AuthEndpoints.OpenIddict

- New package. `AddAuthEndpointsOpenIddict<TUser, TContext, TKey>()`, `modelBuilder.UseAuthEndpointsOpenIddict<TUser, TKey>()`, and `MapAuthEndpointsOpenIddict()` turn an AuthEndpoints app into an OAuth 2.0 authorization server. It depends on AuthEndpoints `[4.0.0, 5.0.0)` and OpenIddict 7.7.2.
- Authorization code flow with PKCE (S256 only). Refresh tokens rotate on every use with no reuse leeway. Access tokens are reference tokens that last 15 minutes. `POST /connect/revoke` revokes tokens, and `GET /.well-known/oauth-authorization-server` serves RFC 8414 metadata.
- `/connect/authorize` sends signed-out users to `LoginUrl` with a `returnUrl` on this server, and signed-in users to `ConsentUrl?request={id}`. The host's consent page approves or denies through `MapOAuthConsentEndpoints()` or `IOAuthConsentService`. `IOAuthPrincipalFactory` sets the token subject; the default is the Identity user id.
- Dynamic client registration (RFC 7591) and protected resource metadata (RFC 9728) are off by default. Registration accepts public clients only, validates redirect URIs, and is rate limited per client IP.
- Every code exchange and refresh checks the approving user again: the user must still exist, be able to sign in, not be locked out, and have the same security stamp. A failed check returns `invalid_grant` and revokes the grant. Changing the password, resetting the authenticator, or calling `UpdateSecurityStampAsync` ends the user's OAuth grants.
- The issuer, endpoint URLs, and audience come from configuration, never from the request `Host` header. HTTPS, resource validation, and per-client resource permissions are on by default.
- Clients can be defined in configuration and created with `SeedOAuthClientsAsync()`. Signing and encryption keys come from a persisted self-signed pair (`Certificates.Path`), certificates you supply, or ephemeral keys for tests.

Enabling the package needs a migration that adds the OpenIddict tables and the `OAuthRequests` table. OpenID Connect (ID tokens, `userinfo`, logout, and the `email`, `email_verified`, and `amr` claims) is not in this preview, and the `openid` scope is rejected. See the package README's Limitations section for the other known gaps.

### Packages

- **AuthEndpoints.OpenIddict** `4.0.0-preview.1` (new)
- **AuthEndpoints** unchanged at `4.1.0`
- **AuthEndpoints.External.OAuth**, **AuthEndpoints.OAuth.GitHub**, and **AuthEndpoints.OAuth.Google** unchanged at `4.0.1`

### Links

- [GitHub release](https://github.com/madeyoga/AuthEndpoints/releases/tag/openiddict-v4.0.0-preview.1)
- [OAuth server docs](/modules/openiddict/)
