# AddAuthEndpoints builder

`AddAuthEndpoints(...).AddPassword().AddPasskeys()` / `MapAuthEndpoints("/auth", session)` on the in-repo host. Every route is under `/auth`. `AE_HOST_MODE` picks the session: `builder-cookie`, `builder-jwt`, or `builder-bearer`. Passkeys are mapped (`ServerDomain=localhost`). `AE_EMAIL_CODE=true` adds email code. Email confirmation is required unless `AE_REQUIRE_CONFIRMED_ACCOUNT=false`.

## Sub-features

- `cookie-register-confirm-login` creates an account, confirms the mailed link, and sets the application cookie
- `cookie-manage-logout` reads `GET /auth/manage/info` and CSRF-logs out so the next read is `401`
- `jwt-create-verify` confirms the account, then `POST /auth/create` and `GET /auth/verify` return `204`
- `jwt-refresh-logout` rotates the refresh cookie, revokes the family on logout, and rejects a replayed refresh
- `bearer-login-refresh` returns `accessToken` and `refreshToken` from `POST /auth/login`, reads `GET /auth/manage/info` with `Authorization: Bearer`, and refreshes with `POST /auth/refresh`
- `bearer-csrf-absent` returns `404` from `GET /auth/csrfToken` on `builder-bearer`

## How to get to it (user POV)

- `POST /auth/register` JSON `{ "email", "password" }`
- `GET /test/mailbox` lists captured mail. Confirmation `body` is the HTML-encoded confirm URL
- `GET /auth/confirmEmail?userId=&code=` from that URL
- Cookie: `POST /auth/login` JSON `{ "email", "password" }` sets `.AspNetCore.Identity.Application`
- JWT: `POST /auth/create` JSON `{ "email", "password" }` returns `accessToken` and `tokenType` `Bearer`. Cookie transport sets `AuthEndpoints.Jwt.RefreshToken` and omits `refreshToken`. Body transport (`AE_JWT_REFRESH_TRANSPORT=Body`) also returns `refreshToken` and sets no refresh cookie
- Identity bearer: `POST /auth/login` JSON `{ "email", "password" }` with no cookie flags returns `accessToken` and `refreshToken`. `POST /auth/refresh` JSON `{ "refreshToken" }`
- `GET /auth/manage/info` with the application cookie, or with `Authorization: Bearer` for JWT and Identity bearer
- `GET /auth/csrfToken` then `POST /auth/logout` with `RequestVerificationToken` (cookie and JWT cookie refresh)
- JWT also: `GET /auth/verify` with the bearer token, and `POST /auth/refresh` with the CSRF token
- Passkeys: `POST /auth/passkeys/requestOptions`, `/auth/passkeys/login`, `/auth/passkeys/register/options`, `/auth/passkeys/register`, and management under `/auth/passkeys/`

## Driving it with ae-http

Preconditions:

- `AE_HOST_MODE=builder-cookie`, `builder-jwt`, or `builder-bearer` before `launch`. Leave `AE_JWT_REFRESH_TRANSPORT` unset for JWT cookie refresh.
- Host is healthy (`ae-http.sh doctor`). Cookie and JWT cookie refresh check `GET /auth/csrfToken`. Identity bearer and JWT body refresh check that `GET /auth/manage/info` is `401`.
- Cookie jar is empty.
- `EMAIL` is unused. `PASS` is `Passw0rd!`.

- **Register.** Run `ae-http.sh post /auth/register "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out register`. Status is `200`.
- **Login before confirm.** Cookie or bearer: `ae-http.sh post /auth/login "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out login-too-soon`. JWT: `ae-http.sh post /auth/create "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out create-too-soon`. Status is `401`.
- **Mailbox.** Run `ae-http.sh get /test/mailbox --out mailbox`. Body contains a `confirm` item whose `body` includes `/auth/confirmEmail`.
- **Confirm.** GET the HTML-decoded confirm URL. Status is `200`. Body contains `confirming`.
- **Cookie login.** Run `ae-http.sh post /auth/login "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out login`. Status is `200`. Headers include `.AspNetCore.Identity.Application`.
- **Cookie manage.** Run `ae-http.sh get /auth/manage/info --out info`. Status is `200`. Body email matches `EMAIL`.
- **Cookie logout.** Run `ae-http.sh post --csrf /auth/logout --out logout`. Status is `200`. A later `ae-http.sh get /auth/manage/info --out info-after` is `401`.
- **JWT create.** Run `ae-http.sh post /auth/create "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out create`. Status is `200`. Body has `accessToken`. Headers include `AuthEndpoints.Jwt.RefreshToken`.
- **JWT verify.** Export `AE_BEARER` from `accessToken`. Run `ae-http.sh get /auth/verify --out verify`. Status is `204`.
- **JWT manage.** Run `ae-http.sh get /auth/manage/info --out info`. Status is `200`.
- **JWT refresh.** Run `ae-http.sh post --csrf /auth/refresh --out refresh`. Status is `200`. Body has `accessToken`. Headers set a new `AuthEndpoints.Jwt.RefreshToken`.
- **JWT logout.** Run `ae-http.sh post --csrf /auth/logout --out logout`. Status is `200`.
- **JWT replay.** Run `ae-http.sh post --csrf /auth/refresh --out refresh-replay`. Status is `400`.
- **Bearer login.** On `builder-bearer`, run `ae-http.sh post /auth/login "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out bearer-login`. Status is `200`. Body has `accessToken` and `refreshToken`.
- **Bearer manage.** Export `AE_BEARER` from `accessToken`. Run `ae-http.sh get /auth/manage/info --out bearer-info`. Status is `200`.
- **Bearer refresh.** Set `REFRESH` from `bearer-login.body`. Run `ae-http.sh post /auth/refresh "{\"refreshToken\":\"${REFRESH}\"}" --out bearer-refresh`. Status is `200`. Body has a new `accessToken`.
- **Bearer CSRF absent.** Unset `AE_BEARER`. Run `ae-http.sh get /auth/csrfToken --out bearer-csrf-absent`. Status is `404`.
- **Traces.** Run `ae-http.sh traces`. Error spans and exception events are both zero.

## Gotchas

- Confirmation links in the mailbox are HTML-encoded (`&amp;`). Decode before GET.
- `/test/mailbox` is not a library route. Cite `/auth/confirmEmail` as the product proof.
- Unconfirmed login and create are `401` on this host because `RequireConfirmedAccount` defaults to true.
- JWT password sign-in is `POST /auth/create`. `POST /auth/login` is not mapped in `builder-jwt`.
- Passkey ceremonies follow the session. Cookie and JWT cookie refresh require a CSRF token on `requestOptions`, `register/options`, `register`, and `login`. Identity bearer and `AE_JWT_REFRESH_TRANSPORT=Body` do not, and `GET /auth/csrfToken` is unmapped there. Signed-in passkey changes always require the token, unless the caller sends `Authorization: Bearer`. The Identity ceremony state lives in the `TwoFactorUserIdScheme` cookie (`Identity.TwoFactorUserId`). That cookie is single-use state, not a credential, and clients must send it between options and login.
- An extra `MapCookieAuthEndpoints` or `MapIdentityManagementApi` on this host throws `Call AddPasswordEndpoints before ...` when the map runs. The builder registers the individual password features, not the `AddPasswordEndpoints` bundle.
- Email-code routes are mapped only with `AE_EMAIL_CODE=true`.
