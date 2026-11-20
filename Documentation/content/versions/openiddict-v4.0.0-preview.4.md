---
title: AuthEndpoints.OpenIddict 4.0.0-preview.4
description: User control and operations for the OAuth server: connected apps, rate limits on the token and revocation endpoints, audit events, and binding a host context to a grant.
date: 2026-11-20
badge: Preview
tag: openiddict-v4.0.0-preview.4
---

Builds on 4.0.0-preview.3. Work in progress: each change adds its entry below.

### AuthEndpoints.OpenIddict

### Documentation

- **Guide: [Bind a host context to an OAuth grant](/guides/oauth-grant-context).** Bind an organization, workspace, or region chosen at consent to the grant with `ApproveAsync(…, createPrincipal)`, read it from the token instead of the person's current context, and re-check membership at every refresh with a validator that wraps `IdentityOAuthUserValidator<TUser>`. The package tests run the guide's code (#460).

### Packages

- **AuthEndpoints.OpenIddict** `4.0.0-preview.4`
- **AuthEndpoints** `4.2.0` or later required
- **AuthEndpoints.External.OAuth**, **AuthEndpoints.OAuth.GitHub**, and **AuthEndpoints.OAuth.Google** unchanged at `4.0.1`

### Links

- [GitHub release](https://github.com/madeyoga/AuthEndpoints/releases/tag/openiddict-v4.0.0-preview.4)
- [OAuth server docs](/modules/openiddict/)
