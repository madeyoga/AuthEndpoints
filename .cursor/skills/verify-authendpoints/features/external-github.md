# External GitHub

`AE_HOST_MODE=external` maps GitHub sign-in and account routes under `/auth/external`, and password login, cookie session, and account management under `/auth`. Email-code verify is not mapped, so email code does not count as a sign-in method. Step-up for a GitHub-only account is the ReAuth email code.

## Sub-features

- `sign-up` plants a GitHub external cookie and `GET /auth/external/login/github/callback` returns `302` to the return URL
- `last-method` refuses `DELETE /auth/external/logins/GitHub/{key}` with `400` `last_signin_method` before a password exists
- `set-password` uses the email-code ReAuth proof and `POST /auth/manage/password` returns `200`
- `password-login` signs in with that password
- `unlink` succeeds after a password ReAuth proof

## How to get to it (user POV)

- The browser starts at `GET /auth/external/login/github`. This host plants the provider cookie at `POST /test/external-cookie` so the callback can run without GitHub.
- The callback creates the account and sets the application cookie.
- `POST /auth/confirmIdentity/emailCode/send` then `POST /auth/confirmIdentity` with `{ "emailCode" }`.
- `POST /auth/manage/password` with `{ "newPassword" }`.
- Sign out, `POST /auth/login` with the new password, confirm identity with `{ "password" }`, then delete the GitHub login.

## Driving it with ae-http

Preconditions:

- Launch with `AE_HOST_MODE=external`.
- Host is healthy (`ae-http.sh doctor` prints `mode=external` and `GET /auth/csrfToken` is `200`).
- Cookie jar is empty.
- `EMAIL` is `github-user@example.com`. `NEW_PASS` is `Passw0rd`. `KEY` is `github-key-1`.

- **Sign up.** Run `ae-http.sh post /test/external-cookie "{\"provider\":\"GitHub\",\"key\":\"${KEY}\",\"email\":\"${EMAIL}\",\"verified\":true}" --out plant`. Status is `204`. Run `ae-http.sh get "/auth/external/login/github/callback?returnUrl=%2Fdashboard" --out callback`. Status is `302` and the `Location` header is `/dashboard`.
- **Linked.** Run `ae-http.sh get /auth/external/logins --out logins`. Status is `200` and the body contains `GitHub`.
- **Last method.** Run `ae-http.sh post --csrf /auth/confirmIdentity/emailCode/send "{}" --out reauth-send`. Status is `200`. Read `body` from `ae-http.sh get /test/mailbox --out mailbox` where `purpose` is `2`. Run `ae-http.sh post --csrf /auth/confirmIdentity "{\"emailCode\":\"CODE\"}" --out confirm`. Status is `200`. Run `ae-http.sh delete --csrf "/auth/external/logins/GitHub/${KEY}" --out unlink-refused`. Status is `400` and the body contains `last_signin_method`.
- **Set the password.** Run `ae-http.sh post --csrf /auth/manage/password "{\"newPassword\":\"${NEW_PASS}\"}" --out set`. Status is `200`.
- **Password login.** New jar. Run `ae-http.sh post /auth/login "{\"email\":\"${EMAIL}\",\"password\":\"${NEW_PASS}\"}" --out login`. Status is `200` or `204`.
- **Unlink.** Run `ae-http.sh post --csrf /auth/confirmIdentity "{\"password\":\"${NEW_PASS}\"}" --out password-proof`. Status is `200`. Run `ae-http.sh delete --csrf "/auth/external/logins/GitHub/${KEY}" --out unlink`. Status is `204`. Run `ae-http.sh get /auth/external/logins --out logins-after`. Status is `200` and the array is empty.

## Gotchas

- Do not map `POST /emailCode/verify` on this host. A confirmed email would then count as a sign-in method and the unlink before set-password would succeed.
- The callback does not call GitHub. `POST /test/external-cookie` is a test-host probe.
- After set-password the security stamp changes. The email-code ReAuth cookie does not authorize the unlink. Confirm again with the password.
