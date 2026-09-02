---
title: AuthEndpoints.External.OAuth 3.0.0-preview.2
description: Production hardening — verified email, safer linking, error redirects, JWT completer, account link/unlink.
date: 2026-07-30
badge: Preview
tag: external-oauth-v3.0.0-preview.2
---

### AuthEndpoints.External.OAuth

- Require verified email by default; auto-link by email only when verified
- Clear `Identity.External` cookie after successful sign-in / link
- Stricter `returnUrl` (relative-only by default; optional origin allowlist)
- Options validation for External settings and provider ClientId/Secret
- Browser error redirects to `ErrorPath` (JSON Problem when client prefers JSON)
- `AddLoginRateLimiting` registered from `AddExternalAuthEndpoints`
- `JwtExternalLoginCompleter` for JWT refresh-cookie completion
- `MapExternalAccountEndpoints` for list / link / unlink while signed in

### Links

- [GitHub release](https://github.com/madeyoga/AuthEndpoints/releases/tag/external-oauth-v3.0.0-preview.2)
- [External OAuth docs](/modules/external-oauth/)
