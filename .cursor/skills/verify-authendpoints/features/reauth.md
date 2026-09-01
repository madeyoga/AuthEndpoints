# ReAuth step-up

A signed-in user must prove their identity again before changing password or other sensitive account fields. The client lists available methods, posts one proof, then sends the issued token on the mutation.

## Sub-features

- `auth-methods` reports `password: true` from `GET /identity/manage/authMethods` after cookie login.
- `confirm-password` returns `reauthToken` from `POST /identity/confirmIdentity` with `{ "password" }` and CSRF.
- `confirm-wrong` does not issue a token for the wrong password.
- `manage-without-reauth` rejects `POST /identity/manage/info` password change without ReAuth.
- `manage-with-reauth` changes the password when CSRF and `X-AuthEndpoints-Reauth` are present, after which the new password can log in.

## How to get to it (user POV)

- Cookie (or bearer) session first.
- `GET /identity/manage/authMethods`.
- `POST /identity/confirmIdentity` JSON with **exactly one** of `password`, `twoFactorCode`, `twoFactorRecoveryCode`, `credentialJson`. Cookie clients also send CSRF.
- Send `X-AuthEndpoints-Reauth: <reauthToken>` on `POST /identity/manage/info` and `POST /identity/manage/2fa`. Cookie clients still send CSRF.
- Cookie clients also receive cookie `AuthEndpoints.ReAuth`.

## Driving it with ae-http

Preconditions:

- Host is healthy.
- Cookie session for `EMAIL` / `PASS` (register + `/identity/login`).
- Cookie jar still has the application cookie.

- **Methods.** Run `ae-http.sh get /identity/manage/authMethods --out auth-methods`. Status is `200`. `password` is `true`.
- **Confirm.** Run `ae-http.sh post --csrf /identity/confirmIdentity "{\"password\":\"${PASS}\"}" --out confirm`. Status is `200`. Body has `reauthToken`.
- **Wrong password.** Run `ae-http.sh post --csrf /identity/confirmIdentity '{"password":"WrongPass1!"}' --out confirm-wrong`. Status is not 200.
- **Mutation without ReAuth.** Unset `AE_REAUTH`. Run `ae-http.sh post --csrf /identity/manage/info "{\"oldPassword\":\"${PASS}\",\"newPassword\":\"ChangedPass1!\"}" --out info-no-reauth`. Status is `401` or `403`.
- **Mutation with ReAuth.** `export AE_REAUTH` from the successful confirm. Run `ae-http.sh post --csrf /identity/manage/info "{\"oldPassword\":\"${PASS}\",\"newPassword\":\"ChangedPass1!\"}" --out info-reauth`. Status is `200`.
- **New password works.** New jar. Run `ae-http.sh post /identity/login "{\"email\":\"${EMAIL}\",\"password\":\"ChangedPass1!\"}" --out login-new`. Status is `200` or `204`. Then `ae-http.sh get /identity/manage/info --out info-new` is `200`.
- **Proof.** Keep `auth-methods.body`, `confirm.body` (`reauthToken`), `info-no-reauth.status` (401/403), `info-reauth.status` (`200`), and `login-new.status`.

## Gotchas

- Confirm requires **exactly one** proof field. Sending password plus another field is 400.
- Cookie confirm and manage POSTs need CSRF **and** ReAuth. Bearer-only clients skip CSRF when no application cookie is present.
- ReAuth tokens are short-lived. Confirm immediately before the mutation.
- `/test/reauth` only checks the ReAuth cookie. Prefer `manage/info` as the library-facing proof.
- Confirm is rate-limited (fixed window). Do not loop failed confirms.
