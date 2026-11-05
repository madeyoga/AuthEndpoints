# Require step-up

`POST /manage/info`, `POST /manage/2fa`, signed-in passkey changes, and external unlink require a sign-in plus ReAuth for that same user, and CSRF where the route attaches the filter. `POST /confirmIdentity` accepts one proof: password, authenticator code, recovery code, passkey assertion, or `emailCode` when email-code step-up is available.

Success returns `reauthToken`. Cookie sign-in also sets the `AuthEndpoints.ReAuth` cookie. An `Authorization: Bearer` confirm returns the token only. Keep the token in memory. Send it as `X-AuthEndpoints-Reauth`. The proof carries the user's security stamp. A password change, reset, or `UpdateSecurityStampAsync` cancels it. Only `POST /manage/2fa` renews the proof after a stamp change (see the `POST /auth/manage/2fa` note in [routes.md](routes.md)). A password change on `POST /manage/info`, `POST /manage/password`, and external unlink do not, so the client completes step-up again.

Pair `.RequireReauth()` with an authorization requirement that signs the user in. `ReAuthPolicy` adds no authentication schemes. A signed-in caller without step-up gets `403`.

Module: [ReAuth](https://authendpoints.harten.id/modules/reauth).
