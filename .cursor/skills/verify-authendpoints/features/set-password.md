# Set a password

`POST /identity/manage/password` sets a password on a signed-in account that has none. The compose host maps it with account management. The body is `{ "newPassword" }`. The route requires a sign-in, CSRF, and a ReAuth proof.

## Sub-features

- `without-reauth` returns `403` for a signed-in caller with CSRF and no ReAuth proof
- `with-reauth` returns `200` and password login then works
- `already-has-password` returns `400` `UserAlreadyHasPassword`
- `facade-unmapped` returns `404` on `AE_HOST_MODE=bearer-facade` because the frozen facade does not map the route
- `security-mail` records a mailbox item `kind` `security` and `body` `password-set`

## How to get to it (user POV)

- Cookie session for an account with no password. On the compose host, create one with email-code sign-up (`AE_EMAIL_CODE=true` and `AE_EMAIL_CODE_SIGNUP=true`), then `POST /identity/emailCode/verify?useSessionCookies=true`.
- `POST /identity/confirmIdentity/emailCode/send` (no body, CSRF) then `POST /identity/confirmIdentity` JSON `{ "emailCode" }`. Mailbox `purpose` is `2`.
- `POST /identity/manage/password` JSON `{ "newPassword" }` with CSRF and the ReAuth cookie or `X-AuthEndpoints-Reauth`.
- `POST /identity/login` JSON `{ "email", "password" }` with the password just set.
- `GET /test/mailbox` lists the security notice. This is a test-host probe.

## Driving it with ae-http

Preconditions:

- Launch the compose host with `AE_EMAIL_CODE=true` and `AE_EMAIL_CODE_SIGNUP=true`.
- Host is healthy (`ae-http.sh doctor`).
- Cookie jar is empty.
- `EMAIL` is unused. `NEW_PASS` is `SetPass1!`.
- Password sign-in is mapped on this host (`POST /identity/login`), so the route is not `404`.

- **Create a passwordless user.** Run `ae-http.sh post /identity/emailCode/send "{\"email\":\"${EMAIL}\"}" --out send`. Status is `200`. Read `body` from `ae-http.sh get /test/mailbox --out mailbox` where `kind` is `email-code` and `purpose` is `1`.
- **Cookie session.** Run `ae-http.sh post "/identity/emailCode/verify?useSessionCookies=true" "{\"email\":\"${EMAIL}\",\"code\":\"CODE\"}" --out verify`. Status is `200`. Then `ae-http.sh get /identity/manage/info --out info` is `200`.
- **Without ReAuth.** Run `ae-http.sh post --csrf /identity/manage/password "{\"newPassword\":\"${NEW_PASS}\"}" --out set-no-reauth`. Status is `403`.
- **Step up.** Run `ae-http.sh post --csrf /identity/confirmIdentity/emailCode/send "{}" --out reauth-send`. Status is `200`. Read the mailbox item with `purpose` `2`. Run `ae-http.sh post --csrf /identity/confirmIdentity "{\"emailCode\":\"CODE\"}" --out confirm`. Status is `200`. Export `AE_REAUTH` from `reauthToken` when the cookie is not sent.
- **Set the password.** Run `ae-http.sh post --csrf /identity/manage/password "{\"newPassword\":\"${NEW_PASS}\"}" --out set`. Status is `200`. Body is empty.
- **Notice.** Run `ae-http.sh get /test/mailbox --out mailbox-after`. One item has `kind` `security` and `body` `password-set`.
- **Password login.** New jar. Run `ae-http.sh post /identity/login "{\"email\":\"${EMAIL}\",\"password\":\"${NEW_PASS}\"}" --out login`. Status is `200` or `204`. Then `ae-http.sh get /identity/manage/info --out info-login` is `200`.
- **Already has a password.** On the password session, confirm with `{ "password": "${NEW_PASS}" }` and CSRF, then post `/identity/manage/password` again. Status is `400` and the body contains `UserAlreadyHasPassword`.
- **Facade.** A second host with `AE_HOST_MODE=bearer-facade` returns `404` for `POST /identity/manage/password`. That route is absent. A password-sign-in-unmapped `404` while the route is mapped is covered by `SetPasswordEndpointTests`.
- **Proof.** Keep `set-no-reauth.status` (`403`), `set.status` (`200`), `login.status`, `info-login.status` (`200`), and `mailbox-after.body`.

## Gotchas

- Email-code step-up is offered only while the account has no password, authenticator, or passkey. After the password is set, the next proof is the password. The set-password call rotates the security stamp, so the previous ReAuth cookie is `403` on the next sensitive action.
- A missing CSRF token is `400` with the body `Invalid or missing CSRF token.`
- The frozen facade does not map this route. `404` there is routing, not the password-sign-in check.
- An email-code-only map still maps `POST /manage/password` and returns `404` until `POST /login` or JWT `POST /create` is mapped.
- The default `IAccountSecurityEmailSender<TUser>` only logs. This host replaces it with the capturing sender, so the mailbox item exists here.
