---
title: AuthEndpoints.External.OAuth 3.0.0-preview.1
description: First preview of modular GitHub/Google OAuth endpoints.
date: 2026-07-29
badge: Preview
tag: external-oauth-v3.0.0-preview.1
---

### AuthEndpoints.External.OAuth

- Added `AuthEndpoints.External.OAuth` as a separate preview NuGet package
- Shared Core: `AddExternalAuthEndpoints`, provisioning service, pluggable cookie completer, shared login/callback handlers
- GitHub and Google provider modules (`AddGitHub` / `MapGitHubAuthEndpoints`, `AddGoogle` / `MapGoogleAuthEndpoints`)
- Default completion issues an Identity application cookie; `AddCompleter<T>` for future JWT (or other) modes
- Compose-only — not wired into the `AddAuthEndpoints` facade

### Links

- [GitHub release](https://github.com/madeyoga/AuthEndpoints/releases/tag/external-oauth-v3.0.0-preview.1)
- [External OAuth docs](https://madeyoga.github.io/AuthEndpoints/modules/external-oauth)
