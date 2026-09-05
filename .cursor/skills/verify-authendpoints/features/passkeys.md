# Passkeys

Passwordless passkey register and login on `/account/passkeys`. Register creates the user and stores a credential. Confirmation mail matches password `POST /identity/register`. Completers still refuse a session when `CanSignInAsync` fails.

## Sub-features

- `register-options` returns WebAuthn creation options for an email, including an existing email (no enumeration).
- `register-create` creates an unconfirmed user, stores the passkey, and sends a confirmation email.
- `register-unconfirmed-no-session` returns 200 with `credentialId` and no application cookie when `RequireConfirmedAccount` is true.
- `register-duplicate` returns 400 `Unable to complete registration` for an existing email and does not send mail.
- `confirm-then-login` confirms the emailed link, then passkey login with `?useCookies=true` establishes a session.

## How to get to it (user POV)

- `POST /account/passkeys/register/options` JSON `{ "email" }` with CSRF.
- Browser `navigator.credentials.create`. On this host, `POST /test/webauthn/attestation` JSON `{ "optionsJson", "origin" }` returns `{ "credentialJson" }`.
- `POST /account/passkeys/register?useCookies=true` JSON `{ "email", "credentialJson" }` with CSRF.
- `GET /test/mailbox` lists captured mail `{ email, kind, body }`. Confirmation `body` is the HTML-encoded confirm URL.
- `GET /identity/confirmEmail?userId=&code=` from that URL.
- `POST /account/passkeys/requestOptions` with CSRF, then `POST /test/webauthn/assertion`, then `POST /account/passkeys/login?useCookies=true`.

## Driving it with ae-http

Preconditions:

- Launch with `AE_REQUIRE_CONFIRMED_ACCOUNT=true`.
- Host is healthy (`ae-http.sh doctor`).
- Cookie jar is empty.
- `EMAIL` is unused. Origin header is `AE_BASE_URL` (the harness sends it).

- **Password control.** Register a different email with a password. Run `ae-http.sh post /identity/register "{\"email\":\"${EMAIL}-pw@test.local\",\"password\":\"${PASS}\"}" --out pw-register`. Then `ae-http.sh get /test/mailbox --out mailbox-after-password`. Body contains a `confirm` item for that email.
- **Passkey options.** Run `ae-http.sh post --csrf /account/passkeys/register/options "{\"email\":\"${EMAIL}\"}" --out pk-options`. Status is `200`. Body is creation-options JSON with `challenge` and `user.id`.
- **Attest.** Send that options JSON to the test authenticator. Status is `200`. Body has `credentialJson`.
- **Register.** POST `credentialJson` to `/account/passkeys/register?useCookies=true` with CSRF. Status is `200`. Body has `credentialId`. Headers do **not** set `.AspNetCore.Identity.Application`.
- **No session.** Run `ae-http.sh get /identity/manage/info --out pk-info-before-confirm`. Status is `401`.
- **Mailbox.** Run `ae-http.sh get /test/mailbox --out mailbox-after-passkey`. Body contains a `confirm` item for `EMAIL` whose `body` includes `/identity/confirmEmail`.
- **Confirm.** GET the HTML-decoded confirm URL. Status is `200`. Body contains `confirming`.
- **Login options.** Run `ae-http.sh post --csrf /account/passkeys/requestOptions --out pk-request-options`. Status is `200`.
- **Assert and login.** POST assertion `credentialJson` to `/account/passkeys/login?useCookies=true` with CSRF. Status is `200` or `204`. Then `GET /identity/manage/info` is `200` with the same email and `isEmailConfirmed` true.
- **Proof.** Keep `pw-register.status`, `mailbox-after-password.body`, `pk-register.status`, `pk-register.headers` (no session cookie), `pk-info-before-confirm.status` (`401`), `mailbox-after-passkey.body`, confirm GET, `pk-login` plus `info` after login.

Example attest body assembly (python):

```bash
python3 - "$AE_EVIDENCE_DIR/pk-options.body" "$AE_BASE_URL" <<'PY'
import json, sys
options = open(sys.argv[1]).read()
print(json.dumps({"optionsJson": options, "origin": sys.argv[2]}))
PY
```

POST that JSON to `/test/webauthn/attestation` (`--out pk-attest`). Build the register body from `credentialJson` the same way.

## Gotchas

- `/test/webauthn/*` and `/test/mailbox` are not library routes. They only produce or observe inputs. Cite `/account/passkeys/register` and `/login` as the product proof.
- `credentialJson` is a **string** of JSON, not a nested object. Double-encode it in the register/login body.
- Confirmation links in the mailbox are HTML-encoded (`&amp;`). Decode before GET.
- Duplicate-email register is **400**, unlike password register (200). Do not treat that as enumeration-safe copy of password register.
- Passkey register is rate-limited (3 / minute). Use a fresh email rather than retrying the same ceremony in a tight loop.
- Default test host allows unconfirmed sign-in. Confirmation-gate proof requires `AE_REQUIRE_CONFIRMED_ACCOUNT=true` on **launch**.
- Completer cookie flags follow Identity bearer login: `?useCookies=true` on `/account/passkeys/register` and `/login`, not `POST /identity/login`.
