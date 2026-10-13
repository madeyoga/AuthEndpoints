# Email code

`POST /identity/emailCode/send` and `POST /identity/emailCode/verify` sign a user in with a numeric code. The routes exist only when `AE_EMAIL_CODE=true` before `launch`. Sign-up and the magic link stay off unless their own variables are set.

## Sub-features

- `send-known` returns `200` `{ expiresInSeconds, resendAfterSeconds }` and a mailbox item `kind` `email-code`
- `send-unknown` returns the same `200` body and no mailbox item while `AE_EMAIL_CODE_SIGNUP` is unset
- `verify-bearer` with no query flag returns `200` JSON `accessToken`
- `verify-cookie` with `useSessionCookies=true` sets a session `.AspNetCore.Identity.Application` cookie. `useCookies=true` sets a persistent application cookie. The drive below runs the session-cookie form.
- `verify-replay` of the same code returns `401` detail `Invalid or expired code.`
- `signup` with `AE_EMAIL_CODE_SIGNUP=true` creates a confirmed user from an unknown address and sets no password
- `magic-link` with `AE_EMAIL_CODE_LINK` puts the token in `linkUrl` after `#token=` and accepts a token-only POST
- `get-verify` returns `405`

## How to get to it (user POV)

- `POST /identity/emailCode/send` JSON `{ "email" }`
- `POST /identity/emailCode/verify` JSON `{ "email", "code" }`
- `POST /identity/emailCode/verify?useSessionCookies=true` for a session application cookie
- `POST /identity/emailCode/verify?useCookies=true` for a persistent application cookie
- `POST /identity/emailCode/verify` JSON `{ "token" }` when the magic link is on
- `GET /test/mailbox` lists `{ email, kind, body, linkUrl, purpose }`. `body` is the raw code. `purpose` is `0` (`SignIn`) or `1` (`SignUp`)

## Driving it with ae-http

Preconditions:

- Launch with `AE_EMAIL_CODE=true`. Add `AE_EMAIL_CODE_SIGNUP=true` only for the sign-up case. Add `AE_EMAIL_CODE_LINK` (an absolute `http(s)` URI with no `#`) only for the magic-link case.
- Host is healthy (`ae-http.sh doctor`).
- Cookie jar is empty.
- `EMAIL` is unused. This host's `RequireConfirmedAccount` is false unless `AE_REQUIRE_CONFIRMED_ACCOUNT=true`.
- Send is limited to 5 requests per minute per IP (`429`, empty body). Verify shares the login token bucket.
- A successful verify of an **unconfirmed** user who already has a password removes that password (`UnconfirmedAccounts` defaults to `ConfirmAndResetCredentials`). Confirm the email first when the password must remain.

- **Register a known user (sign-in case).** Run `ae-http.sh post /identity/register "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out register`. Status is `200`. Confirm the email before verify if a later password login must still succeed (see [confirm-email.md](./confirm-email.md)).
- **Send.** Run `ae-http.sh post /identity/emailCode/send "{\"email\":\"${EMAIL}\"}" --out send`. Status is `200`. Body has `expiresInSeconds` and `resendAfterSeconds`.
- **Mailbox.** Run `ae-http.sh get /test/mailbox --out mailbox`. One `email-code` item for `EMAIL`. `body` is the code. `purpose` is `0`. `linkUrl` is null unless `AE_EMAIL_CODE_LINK` was set.
- **Verify (bearer).** Run `ae-http.sh post /identity/emailCode/verify "{\"email\":\"${EMAIL}\",\"code\":\"CODE\"}" --out verify`. Status is `200`. Body has `accessToken`.
- **Proof.** `GET /identity/manage/info` with `AE_BEARER` set to that access token. Status is `200` and the body contains `EMAIL`.
- **Replay.** POST the same email and code again. Status is `401`. Body detail is `Invalid or expired code.`
- **Cookie.** On a new email, send, then `ae-http.sh post "/identity/emailCode/verify?useSessionCookies=true" "{\"email\":\"${EMAIL}\",\"code\":\"CODE\"}" --out verify-cookie`. Status is `200`. `Set-Cookie` contains `.AspNetCore.Identity.Application`. A later `GET /identity/manage/info` is `200`.
- **Unknown address, sign-up off.** POST send for an address that was never registered. Status is `200`. Mailbox has no `email-code` item for it. Verify of any code is `401`.
- **Sign-up.** Relaunch with `AE_EMAIL_CODE=true` and `AE_EMAIL_CODE_SIGNUP=true`. Send to an unused address. Mailbox `purpose` is `1`. Verify that code with no query flag. Status is `200` with `accessToken`. `GET /identity/manage/info` shows the address and `isEmailConfirmed` true. `POST /identity/login` with a password for that address is `401` (no password was set).
- **Magic link.** Relaunch with `AE_EMAIL_CODE=true` and `AE_EMAIL_CODE_LINK` set. After send, read the token after `#token=` in `linkUrl`. POST `/identity/emailCode/verify` with JSON `{ "token" }` only. Status is `200`. A second POST of that token is `401`. `GET /identity/emailCode/verify?token=` is `405` and does not sign in.
- **Disabled token.** With `AE_EMAIL_CODE_LINK` unset, POST `{ "token" }` . Status is `400`. Body contains `InvalidEmailCodeRequest`.
- **Traces.** Run `ae-http.sh traces` after a successful verify. The HTTP 200 `POST /identity/emailCode/verify` trace must show exactly one conditional `UPDATE` of `AuthEndpointsEmailCodes` that sets `ConsumedAt` and whose `WHERE` includes `ConsumedAt IS NULL`. The only other write to that table is one `Attempts` reservation `UPDATE`. No `INSERT`, `DELETE`, unconsume, or second consume. `ae-http.sh traces sql` prints those `db.statement` lines. A repeated identical statement in that trace is an N+1 flag; the consume `UPDATE` must appear once. `ae-http.sh traces probe` compares `POST /identity/emailCode/send` for an existing user vs an unknown address (two runs each, under the 5/minute cap).
- **Proof.** Keep the verify status, the bearer or cookie follow-up, and `traces-summary.txt` with `email-code verify: pass`.

## Gotchas

- The compose host maps email-code verify with `IdentityEmailCodeSignInCompleter`. No query flag returns a bearer token, not the application cookie. Cookie login's `useCookies` flag is a different route.
- This host still maps password register and login when email code is on. The email-code-only recipe (no password routes) is not this process.
- Verifying an unconfirmed account that has a password, an external login, or a passkey removes those credentials and then confirms the email. Confirm the address first when that credential must stay. Those user-row writes are not email-code consumes; the trace assert counts only `AuthEndpointsEmailCodes`.
- `GET /test/mailbox` is not a library route. Cite `/identity/emailCode/send` and `/identity/emailCode/verify` as the product proof.
- Do not log or commit the code, the token, or `linkUrl`.
- A second send inside 60 seconds returns `200` and does not add a mailbox item. Send is also limited to 5/minute per IP. `traces probe` uses two different existing users and two unknown addresses, one send each.
- `AE_EMAIL_CODE`, `AE_EMAIL_CODE_SIGNUP`, and `AE_EMAIL_CODE_LINK` are read at process start. Set them before `launch`.
