---
title: Unreleased
description: Step-up is an extra proof on top of a sign-in, not a sign-in by itself.
date: 2026-10-07
---

### AuthEndpoints

`ReAuthPolicy` no longer authenticates the ReAuth cookie or `X-AuthEndpoints-Reauth` header as sign-in schemes. The policy name and `.RequireReauth()` are unchanged. The requirement checks those credentials itself and succeeds only when the proof has `Reauth=true` and the same user id as the signed-in user. The ReAuth principal is not merged into `HttpContext.User`.

A request that presents only a step-up cookie or header is not signed in (`401`) on passkey management, `POST /manage/2fa`, or `POST /manage/info`. A signed-in user without a matching proof is rejected (`403`). A proof issued to a different user is rejected. External login unlink uses the same policy, so a signed-in user without step-up gets `403`.

`.RequireReauth()` alone still requires a sign-in. The host's default authenticate scheme supplies that user when it succeeds. Otherwise the requirement authenticates the registered application cookie, Identity bearer, and JWT bearer schemes.

### Packages

- **AuthEndpoints** `3.1.1` (version unchanged)
- **AuthEndpoints.External.OAuth**, **AuthEndpoints.OAuth.GitHub**, and **AuthEndpoints.OAuth.Google** unchanged at `3.0.0-preview.4`
