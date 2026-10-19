# Password facade

`AddPasswordAuth` / `MapPasswordAuth` on the in-repo host. Cookie session and JWT session both live under `/auth`. Passkeys are mapped (`ServerDomain=localhost`). Email confirmation is required unless `AE_REQUIRE_CONFIRMED_ACCOUNT=false`.

## Sub-features

- `cookie-register-confirm-login` creates an account, confirms the mailed link, and sets the application cookie
- `cookie-manage-logout` reads `GET /auth/manage/info` and CSRF-logs out so the next read is `401`
- `jwt-create-verify` confirms the account, then `POST /auth/create` and `GET /auth/verify` return `204`
- `jwt-refresh-logout` rotates the refresh cookie, revokes the family on logout, and rejects a replayed refresh

## How to get to it (user POV)

- `POST /auth/register` JSON `{ "email", "password" }`
- `GET /test/mailbox` lists captured mail. Confirmation `body` is the HTML-encoded confirm URL
- `GET /auth/confirmEmail?userId=&code=` from that URL
- Cookie: `POST /auth/login` JSON `{ "email", "password" }` sets `.AspNetCore.Identity.Application`
- JWT: `POST /auth/create` JSON `{ "email", "password" }` returns `accessToken` and `tokenType` `Bearer`. Cookie transport sets `AuthEndpoints.Jwt.RefreshToken` and omits `refreshToken`. Body transport (`AE_JWT_REFRESH_TRANSPORT=Body`) also returns `refreshToken` and sets no refresh cookie
- `GET /auth/manage/info` with the application cookie, with `Identity.Bearer` in cookie mode, or with `Authorization: Bearer` for JWT
- `GET /auth/csrfToken` then `POST /auth/logout` with `RequestVerificationToken`
- JWT also: `GET /auth/verify` with the bearer token, and `POST /auth/refresh` with the CSRF token

## Driving it with ae-http

Preconditions:

- `AE_HOST_MODE=password-cookie` or `AE_HOST_MODE=password-jwt` before `launch`. Leave `AE_JWT_REFRESH_TRANSPORT` unset for cookie refresh.
- Host is healthy (`ae-http.sh doctor`). Cookie and JWT cookie-refresh doctor checks `GET /auth/csrfToken`.
- Cookie jar is empty.
- `EMAIL` is unused. `PASS` is `Passw0rd!`.

- **Register.** Run `ae-http.sh post /auth/register "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out register`. Status is `200`.
- **Login before confirm.** Cookie: `ae-http.sh post /auth/login "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out login-too-soon`. JWT: `ae-http.sh post /auth/create "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out create-too-soon`. Status is `401`.
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

## Gotchas

- Confirmation links in the mailbox are HTML-encoded (`&amp;`). Decode before GET.
- `/test/mailbox` is not a library route. Cite `/auth/confirmEmail` as the product proof.
- Unconfirmed login and create are `401` on this host because `RequireConfirmedAccount` defaults to true.
- JWT password sign-in is `POST /auth/create`. `POST /auth/login` is not mapped in `password-jwt`.
- Passkey ceremonies are mapped. Do not claim them verified from this recipe. An extra `MapCookieAuthEndpoints` or `MapIdentityManagementApi` on this host throws `Call AddPasswordEndpoints before ...` when the map runs.
- Email-code routes are not mapped.
- `AE_JWT_REFRESH_TRANSPORT=Body` omits `GET /auth/csrfToken` and puts `refreshToken` in JSON. This recipe is cookie transport.
