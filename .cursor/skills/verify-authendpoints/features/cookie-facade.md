# Cookie facade

`AddAuthEndpoints` and `MapAuthEndpoints` with the default cookie sign-in. Management and `LoginCookie` share `/identity`. There is no `/identity/bearer` prefix and no `/identity/refresh`. Passkeys stay on `/account`. JWT stays on `/auth` unless `AE_FACADE_JWT=false`.

## Sub-features

- `facade-register` creates a user at `POST /identity/register`.
- `facade-login` signs in at `POST /identity/login` and sets `.AspNetCore.Identity.Application`. `useCookies` is ignored on this handler.
- `facade-info` returns the user email from `GET /identity/manage/info` with that cookie.
- `facade-no-bearer-prefix` returns 404 from `POST /identity/bearer/login` and from `GET /identity/refresh`.
- `facade-jwt-present` returns 200 from `GET /auth/csrfToken` when `AE_FACADE_JWT` is not `false`.
- `facade-logout` clears the session with CSRF so a later info GET is 401.

## How to get to it (user POV)

- Launch the test host with `AE_HOST_MODE=cookie-facade`.
- Register at `POST /identity/register` JSON `{ "email", "password" }`.
- `POST /identity/login` JSON `{ "email", "password" }`. Optional `useSessionCookies=false` for a persistent cookie.
- `GET /identity/manage/info` with the application cookie.
- `GET /identity/csrfToken`, then `POST /identity/logout` with `RequestVerificationToken`.
- `GET /auth/csrfToken` when facade JWT is on.

## Driving it with ae-http

Preconditions:

- Host launched with `AE_HOST_MODE=cookie-facade`. Leave `AE_FACADE_JWT` unset.
- `ae-http.sh doctor` reports `mode=cookie-facade` and `csrfToken=present`.
- Fresh cookie jar. Password is `Passw0rd!`. Unique `EMAIL`.

- **Register.** Run `ae-http.sh post /identity/register "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out cookie-facade-register`. Status is `200`.
- **Login.** Run `ae-http.sh post /identity/login "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out cookie-facade-login`. Status is `200` or `204`. Headers set `.AspNetCore.Identity.Application`.
- **Info.** Run `ae-http.sh get /identity/manage/info --out cookie-facade-info`. Status is `200`. `email` matches `EMAIL`.
- **No bearer prefix.** Run `ae-http.sh post /identity/bearer/login "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out cookie-facade-bearer-prefix`. Status is `404`.
- **No refresh.** Run `ae-http.sh get /identity/refresh --out cookie-facade-refresh-absent`. Status is `404`.
- **JWT CSRF.** Run `ae-http.sh get /auth/csrfToken --out cookie-facade-jwt-csrf`. Status is `200`. Body has `csrfToken`.
- **Logout.** Run `ae-http.sh post --csrf /identity/logout --out cookie-facade-logout`. Status is `200` or `204`. Then `ae-http.sh get /identity/manage/info --out cookie-facade-info-after` is `401`.
- **Traces.** Run `ae-http.sh traces`. Error spans and exception events are both zero. `ae-http.sh traces sql` lists `db.statement` for `POST /identity/login` and flags a repeated identical statement in one trace.
- **Proof.** Keep `cookie-facade-login.headers` (application cookie), `cookie-facade-info.body` (email), both `404` statuses, `cookie-facade-jwt-csrf.status` (`200`), `cookie-facade-info-after.status` (`401`), and `traces-summary.txt`.

## Gotchas

- This is not the compose host. Compose also maps `/identity/bearer`. A 200 from `/identity/bearer/login` means the process is compose.
- Doctor on this mode checks `/identity/csrfToken`, same as compose. Bearer-facade doctor checks `manage/info` 401.
- `useCookies` does nothing on `LoginCookie`. Persistent vs session is `useSessionCookies=false` vs omitted/true.
- Set `AE_FACADE_JWT=false` before launch only when the drive is about JWT being absent. The default facade maps `/auth`.
- Duplicate register emails return `200`. Use a distinct `EMAIL`.
