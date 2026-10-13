# Password reset

A client asks for a reset code, reads it from mail, and sets a new password. The routes are `MapPasswordEndpoints` on `/identity`. Mail is sent only when that address belongs to an email-confirmed user. Unknown and unconfirmed addresses still get `200`.

## Sub-features

- `forgot-unconfirmed` returns `200` from `POST /identity/forgotPassword` and does not send a `reset` mail.
- `forgot-confirmed` returns `200` and a mailbox item `kind` `reset` whose `body` is the reset code.
- `forgot-unknown` returns the same `200` and no `reset` mail for that address.
- `reset-ok` returns `200` from `POST /identity/resetPassword` and the new password can log in.
- `reset-bad-code` returns `400` for a code that does not decode to a valid reset token.

## How to get to it (user POV)

- `POST /identity/register` JSON `{ "email", "password" }`.
- `GET /identity/confirmEmail?userId=&code=` from the confirmation mail. Forgot-password mail is sent only after this succeeds.
- `POST /identity/forgotPassword` JSON `{ "email" }`.
- `GET /test/mailbox`. A `reset` item's `body` is the code (HTML-encoded).
- `POST /identity/resetPassword` JSON `{ "email", "resetCode", "newPassword" }`.
- `POST /identity/login` with the new password.

## Driving it with ae-http

Preconditions:

- Host is healthy (`ae-http.sh doctor`). Compose or cookie-facade. `RequireConfirmedAccount` may stay false; the user still has to confirm before a reset code is mailed.
- Cookie jar is empty.
- `EMAIL` is unused. `PASS` is `Passw0rd!`. New password is `ChangedPass1!`.
- Register, forgot-password, and reset-password share the account-abuse limit (10 per minute).

- **Register.** Run `ae-http.sh post /identity/register "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out register`. Status is `200`.
- **Forgot before confirm.** Run `ae-http.sh post /identity/forgotPassword "{\"email\":\"${EMAIL}\"}" --out forgot-unconfirmed`. Status is `200`. Run `ae-http.sh get /test/mailbox --out mailbox-unconfirmed`. There is no `reset` item for `EMAIL`.
- **Confirm.** `GET /test/mailbox`, HTML-decode the `confirm` link, and GET it. Status is `200`. Body is `Thank you for confirming your email.`
- **Forgot after confirm.** Run `ae-http.sh post /identity/forgotPassword "{\"email\":\"${EMAIL}\"}" --out forgot`. Status is `200`. Run `ae-http.sh get /test/mailbox --out mailbox-reset`. One `reset` item for `EMAIL`. `body` is the code.
- **Unknown address.** Run `ae-http.sh post /identity/forgotPassword "{\"email\":\"nobody-${AE_RUN_ID}@test.local\"}" --out forgot-unknown`. Status is `200`. Mailbox has no `reset` item for that address.
- **Bad code.** Run `ae-http.sh post /identity/resetPassword "{\"email\":\"${EMAIL}\",\"resetCode\":\"not-a-valid-code\",\"newPassword\":\"ChangedPass1!\"}" --out reset-bad`. Status is `400`.
- **Reset.** HTML-decode the mailbox `body` and POST it as `resetCode`. Run `ae-http.sh post /identity/resetPassword "{\"email\":\"${EMAIL}\",\"resetCode\":\"CODE\",\"newPassword\":\"ChangedPass1!\"}" --out reset`. Status is `200`.
- **New password.** Run `ae-http.sh post /identity/login "{\"email\":\"${EMAIL}\",\"password\":\"ChangedPass1!\"}" --out login-new`. Status is `200` or `204`. Then `ae-http.sh get /identity/manage/info --out info-new` is `200`.
- **Traces.** Run `ae-http.sh traces`. Error spans and exception events are both zero. `ae-http.sh traces sql` lists `db.statement` for `POST /identity/forgotPassword` and flags a repeated identical statement in one trace. On a fresh host, `ae-http.sh traces probe` compares forgot-password for a confirmed user vs an unknown address.
- **Proof.** Keep `forgot-unconfirmed` plus mailbox with no reset item, the confirm GET, `mailbox-reset.body` (do not commit the code), `reset.status` (`200`), `login-new.status`, and `traces-summary.txt`.

## Gotchas

- Forgot-password always returns `200`. The mailbox, not the status, shows whether a code was sent.
- The reset code in `body` is HTML-encoded. Decode it before `resetCode`. Do not log or commit the code.
- `/test/mailbox` is not a library route. Cite `/identity/forgotPassword` and `/identity/resetPassword`.
- An unconfirmed user cannot be reset. Confirm first.
- Account-abuse is shared with `POST /identity/register` and `POST /identity/resendConfirmationEmail`. A 429 is the limiter, not a missing user.
