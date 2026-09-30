---
title: AuthEndpoints.External.OAuth 3.0.0-preview.4
description: Verified GitHub and Google email, safe auto-link, link and unlink hardening, and a package split.
date: 2026-09-30
badge: Preview
tag: external-oauth-v3.0.0-preview.4
---

### AuthEndpoints.External.OAuth

- GitHub and Google handlers moved to their own packages. This nupkg no longer references either handler.
- `AutoLinkByEmail` defaults to false. When enabled, auto-link requires a verified provider email and a confirmed local email.
- Login and link failures, including remote failure, clear the `Identity.External` cookie.
- `returnUrl` accepts rooted local paths and allowlists absolute origins the same way email-confirmation redirects do.
- Unlink requires authorization, antiforgery, and ReAuth, and refuses the last sign-in method.
- JWT completion writes only the refresh cookie.

### AuthEndpoints.External.OAuth.GitHub

- New package. `AddGitHub` loads a verified address from the GitHub emails API (verified primary, otherwise any verified address) and drops an unverified profile email.

### AuthEndpoints.External.OAuth.Google

- New package. `AddGoogle` sets `email_verified` from the Google userinfo payload after host configuration.

### Links

- [Compare](https://github.com/madeyoga/AuthEndpoints/compare/external-oauth-v3.0.0-preview.3...external-oauth-v3.0.0-preview.4)
- [External OAuth docs](/modules/external-oauth/)
