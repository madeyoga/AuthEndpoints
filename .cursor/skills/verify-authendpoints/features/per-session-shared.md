# Per-session and shared routes

`AE_HOST_MODE=split` maps cookie sign-in under `/web`, JWT sign-in under `/app`, and shared routes once at the root. Register, recovery, email-code send, passkey registration options, account management, and confirm-email are shared. Login, email-code verify, passkey register and login, and each session's own routes stay on the prefix.

## Sub-features

- `shared-register` creates an account at `POST /register` and returns 200.
- `cookie-login` signs in at `POST /web/login` and sets `.AspNetCore.Identity.Application`.
- `cookie-info` returns 200 and the same email from `GET /manage/info` after that login.
- `cookie-logout` ends the cookie session so a later info GET is 401.
- `jwt-create` returns `accessToken` from `POST /app/create`.
- `jwt-verify` returns 204 from `GET /app/verify` with that bearer token.
- `no-cross-prefix` keeps password login off `/app` and password register off `/web` (404).
- `email-send` returns 200 from shared `POST /emailCode/send`.
- `email-verify-cookie` signs in at `POST /web/emailCode/verify` and sets the application cookie.

## How to get to it (user POV)

- `POST /register` JSON `{ "email", "password" }`.
- `POST /forgotPassword` and `POST /resetPassword` at the root.
- `POST /web/login` JSON `{ "email", "password" }`.
- `GET /web/csrfToken`, then `POST /web/logout` with header `RequestVerificationToken`.
- `GET /manage/info` with the application cookie (shared, not under `/web`).
- `POST /app/create` JSON `{ "email", "password" }` → `accessToken`. Refresh cookie is `AuthEndpoints.Jwt.RefreshToken`.
- `GET /app/verify` with `Authorization: Bearer`.
- `GET /app/csrfToken`, then `POST /app/logout` and `POST /app/refresh` with CSRF.
- `POST /emailCode/send` JSON `{ "email" }` at the root. `POST /web/emailCode/verify` and `POST /app/emailCode/verify` JSON `{ "email", "code" }`.
- `POST /passkeys/register/options` at the root. `POST /web/passkeys/register`, `POST /web/passkeys/login`, and `POST /web/passkeys/requestOptions` (and the same three under `/app`).
- `GET /confirmEmail` at the root.

## Driving it with ae-http

Preconditions:

- Launch with `AE_HOST_MODE=split`. Do not set `AE_EMAIL_CODE`; this host always maps email-code send and verify.
- Host is healthy (`ae-http.sh doctor` prints `mode=split`).
- Cookie jar is empty.
- `EMAIL` is unused. `PASS` is `Passw0rd!`. `RequireConfirmedAccount` is false unless `AE_REQUIRE_CONFIRMED_ACCOUNT=true`.
- `--csrf` on `/web/*` fetches `/web/csrfToken`. `--csrf` on `/app/*` fetches `/app/csrfToken`. On this host, `--csrf` for any other path fetches `/web/csrfToken`.

- **Register.** Run `ae-http.sh post /register "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out register`. Status is `200`.
- **Cookie login.** Run `ae-http.sh post /web/login "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out web-login`. Status is `200`. Headers include `Set-Cookie` for `.AspNetCore.Identity.Application`.
- **Session info.** Run `ae-http.sh get /manage/info --out info`. Status is `200`. Body `email` matches `EMAIL`.
- **Cookie logout.** Run `ae-http.sh post --csrf /web/logout --out web-logout`. Status is `200` or `204`.
- **Logged out.** Run `ae-http.sh get /manage/info --out info-after-logout`. Status is `401`.
- **JWT create.** Run `ae-http.sh post /app/create "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out app-create`. Status is `200`. Body has `accessToken`.
- **JWT verify.** Export `AE_BEARER` to that access token. Run `ae-http.sh get /app/verify --out app-verify`. Status is `204`. Unset `AE_BEARER` before the next cookie step.
- **No cross-prefix password routes.** `POST /app/login` and `POST /web/register` return `404`.
- **Email code.** Register a second address, then `ae-http.sh post /emailCode/send "{\"email\":\"${EMAIL2}\"}" --out send`. Status is `200`. `ae-http.sh get /test/mailbox --out mailbox` lists `kind` `email-code` and `body` is the code. `ae-http.sh post /web/emailCode/verify "{\"email\":\"${EMAIL2}\",\"code\":\"CODE\"}" --out web-verify`. Status is `200`. Headers include `.AspNetCore.Identity.Application`. A later `GET /manage/info` is `200` and contains `EMAIL2`.
- **Proof.** Keep `register.status`, `web-login.headers`, `info.body`, `info-after-logout.status` (`401`), `app-create.body` (token present), and `app-verify.status` (`204`).

## Gotchas

- JWT password sign-in on this host is `POST /app/create`, not `POST /app/login`. Cookie password sign-in is `POST /web/login`.
- `GET /manage/info` and `POST /register` are shared root routes. They are not under `/web` or `/app`.
- Email-code verify under `/web` finishes with the cookie completer. It sets the application cookie. The compose host's no-flag bearer verify is a different map.
- `AE_EMAIL_CODE` does not gate this host. The compose host still requires it.
- Passkey register and login need the software authenticator in [passkeys.md](./passkeys.md). Options JSON alone is not a completed ceremony.
- Do not log or commit the email code or the JWT access token.
