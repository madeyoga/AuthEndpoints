---
title: AuthEndpoints.OpenIddict 4.0.0-preview.6
description: Access-token validation has a short scheme name. ValidationScheme is obsolete and keeps the same value.
date: 2026-11-28
badge: Preview
tag: openiddict-v4.0.0-preview.6
---

### AuthEndpoints.OpenIddict

**Access-token scheme name.** `OAuthServerConstants.AccessTokenScheme` is the scheme that validates access tokens issued by this server. Use it on a policy, for example `AddAuthenticationSchemes(IdentityConstants.ApplicationScheme, OAuthServerConstants.AccessTokenScheme)`. `OAuthServerServiceCollectionExtensions.ValidationScheme` is obsolete and keeps the same value, so existing policies still authenticate the same tokens.

No host change is required. This release adds no database migration. AuthEndpoints 4.3.0 or later is still required, `[4.3.0, 5.0.0)`.

### Packages

- **AuthEndpoints.OpenIddict** `4.0.0-preview.6`
- **AuthEndpoints** `4.3.0` or later required
- **AuthEndpoints.External.OAuth**, **AuthEndpoints.OAuth.GitHub**, and **AuthEndpoints.OAuth.Google** unchanged at `4.0.1`

### Links

- [GitHub release](https://github.com/madeyoga/AuthEndpoints/releases/tag/openiddict-v4.0.0-preview.6)
- [OAuth server docs](/modules/openiddict/)
- [People and agents](/modules/callers)
