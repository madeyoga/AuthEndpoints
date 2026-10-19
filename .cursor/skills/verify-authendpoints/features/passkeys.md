# Passkeys

Passwordless passkey register and login on `/account/passkeys`. Register creates the user and stores a credential. Confirmation mail matches password `POST /identity/register`. When `CanSignInAsync` fails, `PasskeySignInGate` returns `credentialId` and does not call the completer. This host registers `IdentityPasskeySignInCompleter`.

Compose and the cookie facade keep antiforgery on `/account/passkeys`. A ceremony without a token returns `400`. The bearer facade passes Identity bearer and does not require a token. Password cookie and JWT cookie refresh require one. Password JWT body refresh does not, and `GET /auth/csrfToken` is unmapped. Keep the `Identity.TwoFactorUserId` cookie between options and register or login. Sending `RequestVerificationToken` is accepted when the filter is absent.

## Sub-features

- `register-options` returns WebAuthn creation options for an email, including an existing email (no enumeration).
- `register-create` creates an unconfirmed user, stores the passkey, and sends a confirmation email.
- `register-unconfirmed-no-session` returns 200 with `credentialId` and no application cookie when `RequireConfirmedAccount` is true.
- `register-confirmed-bearer` (`RequireConfirmedAccount` false, no `useCookies`) returns 200 with `accessToken` and no `credentialId`. `GET /identity/manage/info` with that bearer is 200.
- `register-confirmed-cookie` (`RequireConfirmedAccount` false, `?useCookies=true`) returns 200 with `credentialId`, no `accessToken`, and sets `.AspNetCore.Identity.Application`. `?useSessionCookies=true` sets a session cookie.
- `register-jwt-token-only` is `JwtPasskeySignInCompleter`: access token and refresh cookie, no `credentialId`, and `useCookies` is ignored. This host does not register that completer.
- `register-duplicate` returns 400 `Unable to complete registration.` after a successful attestation when the email already has an account, and does not send mail or store a passkey.
- `register-no-ceremony` returns that same 400 for a known email and an unknown email when `credentialJson` is `{}`. The email is not checked until attestation succeeds.
- `register-existing-id` returns 400 `Unable to complete registration` when attestation `userEntity.Id` already exists and does not attach a passkey. Add credentials on an existing account with authenticated `creationOptions` + `POST /passkeys/`.
- `confirm-then-login` confirms the emailed link, then passkey login with `?useCookies=true` establishes a session.
- `list-passkeys` returns the stored credential from `GET /account/passkeys/` after a cookie register.
- `delete-last-method` returns 400 `Cannot remove the last sign-in method.` when ReAuth deletes the only credential.

## How to get to it (user POV)

- `POST /account/passkeys/register/options` JSON `{ "email" }` with CSRF.
- Browser `navigator.credentials.create`. On this host, `POST /test/webauthn/attestation` JSON `{ "optionsJson", "origin" }` returns `{ "credentialJson" }`.
- `POST /account/passkeys/register` JSON `{ "email", "credentialJson" }` with CSRF. No cookie flag → Identity bearer `accessToken` when sign-in is allowed. `?useCookies=true` → `credentialId` plus a persistent application cookie. `?useSessionCookies=true` → `credentialId` plus a session application cookie.
- `GET /test/mailbox` lists captured mail `{ email, kind, body }`. Confirmation `body` is the HTML-encoded confirm URL.
- `GET /identity/confirmEmail?userId=&code=` from that URL.
- `POST /account/passkeys/requestOptions` JSON `{ "email" }` with CSRF, then `POST /test/webauthn/assertion`, then `POST /account/passkeys/login`. No cookie flag returns an access token when sign-in is allowed. `?useCookies=true` sets the application cookie. Empty or unknown email still returns `200` options (usernameless). Identifier-first may reveal passkey presence via `allowCredentials`.
- Signed-in management: `GET /account/passkeys/`, `POST /account/passkeys/creationOptions`, `POST /account/passkeys/`, `PATCH /account/passkeys/`, `DELETE /account/passkeys/{credentialId}`. Mutations require CSRF and ReAuth. `POST /identity/confirmIdentity/passkeyOptions` builds the assertion for a passwordless user.

## Driving it with ae-http

Preconditions:

- Two launches. The confirmation gate is `AE_REQUIRE_CONFIRMED_ACCOUNT` and is read at process start.
- Host is healthy (`ae-http.sh doctor`).
- Cookie jar is empty. `unset AE_BEARER` and `unset AE_REAUTH`.
- `EMAIL` is unused. Origin header is `AE_BASE_URL` (the harness sends it).
- `credentialJson` is a string. Passkey register is 3 per minute. Use a distinct email per ceremony.

- **Unconfirmed host.** Launch with `AE_REQUIRE_CONFIRMED_ACCOUNT=true`.
- **Password control.** Register a different email with a password. `PW_EMAIL="pw-${EMAIL}"` (`pw-` plus the full address, still one `@`). Run `ae-http.sh post /identity/register "{\"email\":\"${PW_EMAIL}\",\"password\":\"${PASS}\"}" --out pw-register`. Then `ae-http.sh get /test/mailbox --out mailbox-after-password`. Body contains a `confirm` item for `PW_EMAIL`.
- **Passkey options.** Run `ae-http.sh post --csrf /account/passkeys/register/options "{\"email\":\"${EMAIL}\"}" --out pk-options`. Status is `200`. Body is creation-options JSON with `challenge` and `user.id`.
- **Attest.** Send that options JSON to the test authenticator. Status is `200`. Body has `credentialJson`.
- **Register.** POST `credentialJson` to `/account/passkeys/register?useCookies=true` with CSRF. Status is `200`. Body has `credentialId`. Headers do **not** set `.AspNetCore.Identity.Application`.
- **No session.** Run `ae-http.sh get /identity/manage/info --out pk-info-before-confirm`. Status is `401`.
- **Mailbox.** Run `ae-http.sh get /test/mailbox --out mailbox-after-passkey`. Body contains a `confirm` item for `EMAIL` whose `body` includes `/identity/confirmEmail`.
- **Confirm.** GET the HTML-decoded confirm URL. Status is `200`. Body is `Thank you for confirming your email.`
- **Unknown email options.** Run `ae-http.sh post --csrf /account/passkeys/requestOptions "{\"email\":\"nobody-${AE_RUN_ID}@test.local\"}" --out pk-request-options-unknown`. Status is `200`. Body is request-options JSON (no 404, no "user not found"). Do this before the identifier-first login options so it does not replace the login challenge.
- **Login options.** Run `ae-http.sh post --csrf /account/passkeys/requestOptions "{\"email\":\"${EMAIL}\"}" --out pk-request-options`. Status is `200`. Body is request-options JSON. Identifier-first may include `allowCredentials`.
- **Assert and login.** POST assertion `credentialJson` to `/account/passkeys/login?useCookies=true` with CSRF. Status is `200` or `204`. Then `GET /identity/manage/info` is `200` with the same email and `isEmailConfirmed` true.
- **Confirmed host.** Stop and launch again with `AE_REQUIRE_CONFIRMED_ACCOUNT` unset. New `EMAIL` values.
- **Bearer register.** Options, attest, then POST `/account/passkeys/register` with CSRF and **no** `useCookies` or `useSessionCookies`. Status is `200`. Body has `accessToken` and no `credentialId`. Headers do not set `.AspNetCore.Identity.Application`. Export `AE_BEARER` from that access token. `ae-http.sh get /identity/manage/info --out pk-bearer-info` is `200` and the email matches.
- **Cookie register.** `unset AE_BEARER` and empty the jar. A second email: options, attest, then POST `/account/passkeys/register?useCookies=true` with CSRF. Status is `200`. Body has `credentialId` and no `accessToken`. Headers set `.AspNetCore.Identity.Application`. `ae-http.sh get /identity/manage/info --out pk-cookie-info` is `200`.
- **List.** Run `ae-http.sh get /account/passkeys/ --out pk-list`. Status is `200`. Body `passkeys` includes that `credentialId`.
- **Delete only method.** Run `ae-http.sh post --csrf /identity/confirmIdentity/passkeyOptions --out pk-reauth-options`. Status is `200`. Assert that options JSON. The test authenticator body must include `credentialId` from the cookie register, because this process already stored the bearer-register credential too. Then `ae-http.sh post --csrf /identity/confirmIdentity "{\"credentialJson\":\"...\"}" --out pk-reauth-confirm`. Status is `200`. Body has `reauthToken`. Export `AE_REAUTH`. Run `ae-http.sh delete --csrf "/account/passkeys/${CREDENTIAL_ID}" --out pk-delete-last`. Status is `400`. Body contains `Cannot remove the last sign-in method.`
- **JWT completer.** Do not drive it here. `Program.cs` does not register `JwtPasskeySignInCompleter`, and no env flag selects it.
- **Traces.** Run `ae-http.sh traces` on each host. Error spans and exception events are both zero. `ae-http.sh traces sql` lists `db.statement` for the passkey routes you called and flags a repeated identical statement in one trace. On a fresh host, `ae-http.sh traces probe` compares `POST /account/passkeys/requestOptions` for an existing email vs an unknown email (two runs each). A large median gap is a timing side-channel flag in `traces-summary.txt`.
- **Proof.** Keep the unconfirmed register headers (no session cookie), `pk-info-before-confirm.status` (`401`), confirm GET, login plus info, the bearer register body (`accessToken`, no `credentialId`), the cookie register body and `Set-Cookie`, `pk-list.body`, `pk-delete-last.status` (`400`), and both `traces-summary.txt` files.

Example attest body assembly (python):

```bash
python3 - "$AE_EVIDENCE_DIR/pk-options.body" "$AE_BASE_URL" <<'PY'
import json, sys
options = open(sys.argv[1]).read()
print(json.dumps({"optionsJson": options, "origin": sys.argv[2]}))
PY
```

POST that JSON to `/test/webauthn/attestation` (`--out pk-attest`). Build the register body from `credentialJson` the same way. Assertion uses `/test/webauthn/assertion` and the same wrapper. Add `"credentialId"` when the test authenticator already holds another credential:

```bash
python3 - "$AE_EVIDENCE_DIR/pk-reauth-options.body" "$AE_BASE_URL" "$CREDENTIAL_ID" <<'PY'
import json, sys
options = open(sys.argv[1]).read()
print(json.dumps({"optionsJson": options, "origin": sys.argv[2], "credentialId": sys.argv[3]}))
PY
```

## Gotchas

- `/test/webauthn/*` and `/test/mailbox` are not library routes. They only produce or observe inputs. Cite `/account/passkeys/register` and `/login` as the product proof.
- `credentialJson` is a **string** of JSON, not a nested object. Double-encode it in the register/login body.
- `/test/webauthn/assertion` omits `credentialId` only when that process has stored one credential. A second passkey on the same host requires `credentialId` or the helper returns 500.
- Confirmation links in the mailbox are HTML-encoded (`&amp;`). Decode before GET.
- Duplicate-email register is **400**, unlike password register (200). Do not treat that as enumeration-safe copy of password register.
- Passkey register is rate-limited (3 / minute). Use a fresh email rather than retrying the same ceremony in a tight loop. `POST /account/passkeys/` (add to an existing account) shares that limit.
- Default test host allows unconfirmed sign-in. Confirmation-gate proof requires `AE_REQUIRE_CONFIRMED_ACCOUNT=true` on **launch**.
- Completer cookie flags follow Identity bearer login: `?useCookies=true` on `/account/passkeys/register` and `/login`, not `POST /identity/login`.
- Each `POST /account/passkeys/requestOptions` replaces the pending assertion challenge. Drive unknown-email options before the login options you will assert, or after login. `POST /identity/confirmIdentity/passkeyOptions` is a separate challenge for the signed-in user.
- The test host stores Identity data in SQLite. EF in-memory does not round-trip passkey `Data`, so login after register would fail on that provider.
- Management mutations (`creationOptions`, `POST /`, `PATCH /`, `DELETE /{credentialId}`) require a sign-in and ReAuth. A passwordless account confirms with `credentialJson`, not a password.
