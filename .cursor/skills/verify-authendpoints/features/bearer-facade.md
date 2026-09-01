# Identity bearer facade

A native or mobile client uses `AddAuthEndpoints` with `AuthEndpointsSignIn.IdentityBearer` and `MapAuthEndpoints`. Management and password login share `/identity`. Login returns JSON access and refresh tokens. Passkeys stay on `/account`.

## Sub-features

- `facade-register` creates a user at `POST /identity/register`.
- `facade-login` returns `accessToken` and `refreshToken` from `POST /identity/login` with no cookie flags.
- `facade-info` returns the user email from `GET /identity/manage/info` with `Authorization: Bearer`.
- `facade-refresh` returns a new `accessToken` from `POST /identity/refresh`.
- `facade-csrf-absent` returns 404 from `GET /identity/csrfToken` (cookie CSRF is not mapped).

## How to get to it (user POV)

- Launch the test host with `AE_HOST_MODE=bearer-facade`.
- Register at `POST /identity/register` JSON `{ "email", "password" }`.
- `POST /identity/login` JSON `{ "email", "password" }` with neither `useCookies` nor `useSessionCookies` → tokens.
- `POST /identity/login?useCookies=true` → application cookie (same Identity `Login` flags as compose bearer).
- `POST /identity/refresh` JSON `{ "refreshToken" }`.
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
- **Refresh.** Unset is not required. Run `ae-http.sh post /identity/refresh "{\"refreshToken\":\"${REFRESH}\"}" --out facade-refresh`. Status is `200`. Body has a new `accessToken`.
- **CSRF absent.** Unset `AE_BEARER`. Run `ae-http.sh get /identity/csrfToken --out facade-csrf-absent`. Status is `404`.
- **Proof.** Keep `facade-login.body` (both tokens), `facade-info.body` (email), `facade-refresh.body` (new access token), and `facade-csrf-absent.status` (`404`).

## Gotchas

- This is not the default compose host. `AE_HOST_MODE` must be `bearer-facade` or doctor will look for `/identity/csrfToken`.
- Facade bearer login lives at `/identity/login`, not `/identity/bearer/login`. The compose host keeps the extra `/identity/bearer` prefix.
- `useCookies` works on this login handler. It does nothing on the cookie facade's `LoginCookie`.
- Duplicate register emails return `200`. Use a distinct `EMAIL`.
- Do not treat `/test/*` as proof of the facade.
