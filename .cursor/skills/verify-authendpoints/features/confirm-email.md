# Confirm email

Browser `GET /identity/confirmEmail` confirms the account (or change-email) from the mailed link. Unset hosts return plain text or `401`. When `AE_CONFIRM_EMAIL_REDIRECT_URI` is set, the same GET returns `302` with `status` and `flow`.

## Sub-features

- `unset-success` returns `200` and `Thank you for confirming your email.`
- `unset-failure` returns `401` for a bad code or unknown user
- `redirect-success` returns `302` with `status=confirmed` and `flow=confirm` (or `change-email`)
- `redirect-failure` returns `302` with `status=failed` and the same `flow`

## How to get to it (user POV)

- `POST /identity/register` JSON `{ "email", "password" }`
- `GET /test/mailbox` lists captured mail. Confirmation `body` is the HTML-encoded confirm URL
- `GET /identity/confirmEmail?userId=&code=` from that URL. Optional `changedEmail` uses the same route

## Driving it with ae-http

Preconditions:

- Host is healthy (`ae-http.sh doctor`).
- For redirect cases, launch with `AE_CONFIRM_EMAIL_REDIRECT_URI=/auth/email-confirmed`. For an absolute URI, also set `AE_CONFIRM_EMAIL_ALLOWED_ORIGINS`.
- Cookie jar is empty.
- `EMAIL` is unused.

- **Register.** Run `ae-http.sh post /identity/register "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out register`. Status is `200`.
- **Mailbox.** Run `ae-http.sh get /test/mailbox --out mailbox`. Body contains a `confirm` item for `EMAIL` whose `body` includes `/identity/confirmEmail`.
- **Confirm (unset host).** GET the HTML-decoded confirm URL. Status is `200`. Body contains `confirming`.
- **Confirm (redirect host).** GET the same URL. Status is `302`. `Location` has `status=confirmed` and `flow=confirm`. Do not follow the redirect.
- **Failure (redirect host).** GET `/identity/confirmEmail?userId=${USER_ID}&code=not-a-valid-code`. Status is `302`. `Location` has `status=failed` and `flow=confirm`.
- **Proof.** Keep register, mailbox, and the confirm GET status plus headers (`Location` when redirected).

## Gotchas

- Confirmation links in the mailbox are HTML-encoded (`&amp;`). Decode before GET.
- The harness `get` does not follow redirects. Read `Location` from `--out` headers.
- Tokens, user ids, and emails are not added to the redirect query.
- `/test/mailbox` is not a library route. Cite `/identity/confirmEmail` as the product proof.
