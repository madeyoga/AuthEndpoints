# Identity bearer facade

A native or mobile client uses `AddAuthEndpoints` with `AuthEndpointsSignIn.IdentityBearer` and `MapAuthEndpoints`. Management and password login share `/identity`. Login returns JSON access and refresh tokens. Passkeys stay on `/account`.

## Sub-features

- `facade-register` creates a user at `POST /identity/register`.
- `facade-login` returns `accessToken` and `refreshToken` from `POST /identity/login` with no cookie flags.
- `facade-info` returns the user email from `GET /identity/manage/info` with `Authorization: Bearer`.
- `facade-refresh` returns a new `accessToken` and a new `refreshToken` from `POST /identity/refresh`.
- `facade-csrf-absent` returns 404 from `GET /identity/csrfToken` (cookie CSRF is not mapped).
- `facade-cookie-logout` with `?useCookies=true` sets the application cookie. `POST /identity/logout` (no CSRF) clears it, and a later info GET is 401.

## How to get to it (user POV)

- Launch the test host with `AE_HOST_MODE=bearer-facade`.
- Register at `POST /identity/register` JSON `{ "email", "password" }`.
- `POST /identity/login` JSON `{ "email", "password" }` with neither `useCookies` nor `useSessionCookies` → tokens.
- `POST /identity/login?useCookies=true` → application cookie (same Identity `Login` flags as compose bearer).
- `POST /identity/refresh` JSON `{ "refreshToken" }`. Read `refreshToken` from the login body into `REFRESH` before this call.
- `POST /identity/logout` after a `useCookies` login. No CSRF header. This logout does not revoke a bearer access token.
- `GET /identity/manage/info` with `Authorization: Bearer <accessToken>`.
- Passkeys (if enabled) remain at `/account/passkeys`. JWT (if enabled on this host) remains at `/auth`.

## Driving it with ae-http

Preconditions:

- Host launched with `AE_HOST_MODE=bearer-facade`.
- `ae-http.sh doctor` reports `mode=bearer-facade` and `manage/info=401`.
- Fresh cookie jar. Password is `Passw0rd!`. Unique `EMAIL`.

- **Register.** Run `ae-http.sh post /identity/register "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out facade-register`. Status is `200`.
- **Token login.** Run `ae-http.sh post /identity/login "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out facade-login`. Status is `200`. Body has `accessToken` and `refreshToken`.
- **Manage with bearer.** Export `AE_BEARER` to that access token. Run `ae-http.sh get /identity/manage/info --out facade-info`. Status is `200`. `email` matches `EMAIL`.
- **Refresh.** Set `REFRESH` from `facade-login.body` (`refreshToken`). Run `ae-http.sh post /identity/refresh "{\"refreshToken\":\"${REFRESH}\"}" --out facade-refresh`. Status is `200`. Body has a new `accessToken` and a new `refreshToken`.
- **CSRF absent.** Unset `AE_BEARER`. Run `ae-http.sh get /identity/csrfToken --out facade-csrf-absent`. Status is `404`.
- **Cookie flag and logout.** Empty the jar (`: > "$AE_COOKIE_JAR"`). Keep `AE_BEARER` unset. Run `ae-http.sh post "/identity/login?useCookies=true" "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out facade-cookie`. Status is `200` or `204`. `ae-http.sh get /identity/manage/info --out facade-cookie-info` is `200`. Run `ae-http.sh post /identity/logout --out facade-logout`. Status is `200` or `204`. Then `ae-http.sh get /identity/manage/info --out facade-info-after-logout` is `401`.
- **Traces.** Run `ae-http.sh traces`. Error spans and exception events are both zero. `ae-http.sh traces sql` lists `db.statement` for `POST /identity/login` and flags a repeated identical statement in one trace. The built-in `traces probe` targets the compose host; on this facade, use `traces timing` for per-route duration after the drive.
- **Proof.** Keep `facade-login.body` (both tokens), `facade-info.body` (email), `facade-refresh.body` (new access token and refresh token), `facade-csrf-absent.status` (`404`), `facade-info-after-logout.status` (`401`), and `traces-summary.txt`.

## Gotchas

- This is not the default compose host. `AE_HOST_MODE` must be `bearer-facade` or doctor will look for `/identity/csrfToken`.
- Facade bearer login lives at `/identity/login`, not `/identity/bearer/login`. The compose host keeps the extra `/identity/bearer` prefix.
- `useCookies` works on this login handler. It does nothing on the cookie facade's `LoginCookie`.
- Duplicate register emails return `200`. Use a distinct `EMAIL`.
- Do not treat `/test/*` as proof of the facade.
