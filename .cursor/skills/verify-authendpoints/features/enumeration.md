# Enumeration-safe responses

Register, forgot password, resend confirmation, email-code send, and passkey register options return the same status, body shape, and headers for an email that has an account and an email that does not. Password register answers a taken email with an empty 200 and emails that owner.

## Sub-features

- `register-duplicate` returns empty 200 for a new email and for that same email again, and `/test/mailbox` records `registration-attempt` for the owner.
- `register-invalid-password` returns the same 400 body for a known email and an unknown email.
- `forgot-match` returns empty 200 for a confirmed account and for an unknown email. Only the confirmed account gets reset mail.
- `resend-match` returns empty 200 for the signed-in email and for another email. The body email is ignored.
- `email-code-match` returns the same 200 body for a known email and an unknown email when `AE_EMAIL_CODE=true`.
- `passkey-options-match` returns 200 creation-options JSON for a known email and an unknown email.

## How to get to it (user POV)

- `POST /identity/register` JSON `{ "email", "password" }`.
- `POST /identity/forgotPassword` JSON `{ "email" }`.
- `POST /identity/resendConfirmationEmail` JSON `{ "email" }` with the application cookie and CSRF header.
- `POST /identity/emailCode/send` JSON `{ "email" }` when email code is mapped.
- `POST /account/passkeys/register/options` JSON `{ "email" }` with CSRF.
- `GET /test/mailbox` lists `{ email, kind, body }`.

## Driving it with ae-http

Preconditions:

- Host is healthy (`ae-http.sh doctor`).
- Cookie jar is empty.
- `EMAIL` is unused. `PASS` is `Passw0rd!`.
- For email-code send, launch with `AE_EMAIL_CODE=true`.
- Aspire is up on `http://localhost:18888` and the host exports OTLP, so span durations can be read after the calls.

- **Register new.** Run `ae-http.sh post /identity/register "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out register-new`. Status is `200`. Body is empty.
- **Register same email.** Run the same POST again with `--out register-known`. Status is `200`. Body matches `register-new`. Headers match aside from `Date`.
- **Mailbox.** Run `ae-http.sh get /test/mailbox --out mailbox-register`. Body contains `confirm` for the first registration and `registration-attempt` for the second. It does not contain `DuplicateUserName`.
- **Short password.** POST `/identity/register` with password `abc` for `EMAIL` and for a new address. Both statuses are `400`. Bodies match. Neither adds `registration-attempt`.
- **Confirm, then forgot.** GET the HTML-decoded confirm link so the account is confirmed. POST `/identity/forgotPassword` for `EMAIL` (`--out forgot-known`) and for `nobody-${AE_RUN_ID}@test.local` (`--out forgot-unknown`). Both statuses are `200` and bodies match. Mailbox gains `reset` only for `EMAIL`.
- **Resend.** Login at `POST /identity/login`, then POST `--csrf /identity/resendConfirmationEmail` with `EMAIL` and with the nobody address. Both statuses are `200` and bodies match.
- **Email code.** With `AE_EMAIL_CODE=true`, POST `/identity/emailCode/send` for `EMAIL` and for the nobody address. Both statuses are `200`. Bodies match (`expiresInSeconds`, `resendAfterSeconds`).
- **Passkey options.** POST `--csrf /account/passkeys/register/options` for `EMAIL` and for the nobody address. Both statuses are `200`. Both bodies are creation-options JSON with the same property names.
- **Proof.** Keep each pair's status, body, and headers, the mailbox after the duplicate register, and the Aspire span durations for the known and unknown call of each route.

## Gotchas

- A duplicate register 200 is not a second account. Login still reaches the first user.
- `registration-attempt` is the test mailbox kind for `SendRegistrationAttemptedAsync`. The default logging sender only writes a log line.
- `POST /identity/resendConfirmationEmail` ignores the JSON email and mails the signed-in user. An unknown address in the body does not change the response.
- `POST /identity/forgotPassword` sends reset mail only when the account exists and the email is confirmed. The HTTP response stays empty 200.
- Passkey register options JSON differs by `challenge` and `user.id`. Compare the shape, not the bytes. `Set-Cookie` values differ for the same reason.
- Account-abuse and passkey option routes are rate-limited. One known call and one unknown call per route stays inside the window. A 429 is not a product failure.
- There is no option to turn enumeration-safe responses off.
