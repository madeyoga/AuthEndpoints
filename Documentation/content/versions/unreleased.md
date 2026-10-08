---
title: Unreleased
description: Step-up is an extra proof on top of a sign-in, not a sign-in by itself.
date: 2026-10-08
---

### AuthEndpoints

A signed-in user without step-up now gets `403` on passkey mutations, `POST /manage/2fa`, `POST /manage/info`, and external login unlink. The step-up credential is never a sign-in and never replaces `HttpContext.User`. `ReAuthPolicy` adds no authentication schemes. The requirement succeeds only when the route's sign-in user matches a ReAuth proof with `Reauth=true` and the same user id.

`.RequireReauth()` must be paired with a sign-in authorization. It does not authenticate the application cookie, Identity bearer, or JWT. A route that omits that authorization fails. A request that presents only a step-up cookie or header is rejected.

CSRF is skipped only when a non-empty `Authorization: Bearer` header is present, Identity bearer or JWT authenticates, and the application cookie does not. Hosts that read the access token from a cookie still send the CSRF token. The filter does not call `OnMessageReceived`.

### Packages

- **AuthEndpoints** `3.1.1` (version unchanged)
- **AuthEndpoints.External.OAuth**, **AuthEndpoints.OAuth.GitHub**, and **AuthEndpoints.OAuth.Google** unchanged at `3.0.0-preview.4`
