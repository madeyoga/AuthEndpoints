# Simple JWT

A client exchanges email and password for a Bearer access token and an HttpOnly refresh cookie, then calls `/auth/verify` and refreshes with CSRF.

## Sub-features

- `jwt-create` returns `accessToken` from `POST /auth/create` and sets `AuthEndpoints.Jwt.RefreshToken`.
- `jwt-create-bad` returns 401 `Invalid credentials` for a wrong password.
- `jwt-verify` accepts `Authorization: Bearer` on `GET /auth/verify` (204 No Content).
- `jwt-refresh` returns a new access token from `POST /auth/refresh` using the refresh cookie plus CSRF.
- `jwt-refresh-missing-cookie` fails when the refresh cookie is absent.
- `jwt-logout` returns 200 from `POST /auth/logout` with CSRF and clears the refresh cookie. A later refresh is not 200.

## How to get to it (user POV)

- Register the user at `POST /identity/register` (JWT mapping has no register of its own).
- `POST /auth/create` JSON `{ "email", "password" }`.
- `GET /auth/verify` with `Authorization: Bearer <accessToken>`.
- `GET /auth/csrfToken`, then `POST /auth/refresh` with cookies and `RequestVerificationToken`.
- `POST /auth/logout` with CSRF to clear the refresh cookie.

## Driving it with ae-http

Preconditions:

- Host is healthy.
- User `EMAIL` exists via `/identity/register`.
- Fresh cookie jar (JWT refresh cookie must come from `/auth/create`, not from cookie login).

- **Create.** Run `ae-http.sh post /auth/create "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out jwt-create`. Status is `200`. Body has `accessToken` and `tokenType` `Bearer`. Headers set `AuthEndpoints.Jwt.RefreshToken`.
- **Wrong password.** Run `ae-http.sh post /auth/create "{\"email\":\"${EMAIL}\",\"password\":\"WrongPassword!\"}" --out jwt-create-bad`. Status is `401`. Body contains `Invalid credentials`.
- **Verify.** `export AE_BEARER` to the access token. Run `ae-http.sh get /auth/verify --out jwt-verify`. Status is `204`.
- **Refresh.** Keep the jar from create. Run `ae-http.sh post --csrf /auth/refresh --out jwt-refresh`. Status is `200`. Body has a new `accessToken`.
- **Missing cookie.** Empty the jar (`: > "$AE_COOKIE_JAR"`). No create. Run `ae-http.sh post --csrf /auth/refresh --out jwt-refresh-missing`. Status is not 200 (typically 400) and the body mentions a missing refresh token cookie.
- **Logout.** The missing-cookie step cleared the jar. Run `ae-http.sh post /auth/create "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out jwt-create-2`. Status is `200`. Run `ae-http.sh post --csrf /auth/logout --out jwt-logout`. Status is `200`. Run `ae-http.sh post --csrf /auth/refresh --out jwt-refresh-after-logout`. Status is not 200.
- **Traces.** Run `ae-http.sh traces`. Error spans and exception events are both zero. `ae-http.sh traces sql` lists `db.statement` for `POST /auth/create` and flags a repeated identical statement in one trace.
- **Proof.** Keep `jwt-create.body` + `jwt-create.headers` (refresh cookie), `jwt-verify.status` (`204`), `jwt-refresh.body` (new access token), `jwt-logout.status` (`200`), `jwt-refresh-after-logout.status`, and `traces-summary.txt`.

## Gotchas

- `/auth/create` is rate-limited with the login policy. Space it from other logins.
- Refresh and logout require CSRF on the **JWT** token endpoint (`/auth/csrfToken`).
- The access token is only in JSON. The refresh token is **only** in the cookie named `AuthEndpoints.Jwt.RefreshToken`, not in the create JSON.
- Two-factor users get 401 with `requiresTwoFactor` when no code is sent. This test-host user is not 2FA unless you enabled it.
- The compose host always maps `/auth`. A facade host maps `/auth` unless `AE_FACADE_JWT=false` before `launch`. Refresh reads that cookie only. Do not send the refresh token in the JSON body.
