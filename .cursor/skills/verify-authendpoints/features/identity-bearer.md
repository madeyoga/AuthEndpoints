# Identity bearer

A native or mobile client signs in at the bearer-mapped prefix and receives JSON access and refresh tokens. The same handler can issue an application cookie instead when cookie query flags are set.

## Sub-features

- `bearer-login` returns `accessToken` and `refreshToken` from `POST /identity/bearer/login` with no cookie flags.
- `bearer-refresh` returns new tokens from `POST /identity/bearer/refresh`.
- `bearer-refresh-bad` returns 401 for a garbage refresh token.
- `bearer-use-cookies` with `?useCookies=true` signs in with the application cookie and does not require JSON tokens for `GET /identity/bearer/manage/info`.

## How to get to it (user POV)

- Register once at `POST /identity/register` (shared management on `/identity`).
- `POST /identity/bearer/login` JSON `{ "email", "password" }` with neither `useCookies` nor `useSessionCookies` → tokens.
- `POST /identity/bearer/login?useCookies=true` → application cookie (persistent unless `useSessionCookies=true`).
- `POST /identity/bearer/login?useSessionCookies=true` → session application cookie.
- `POST /identity/bearer/refresh` JSON `{ "refreshToken" }`.
- `GET /identity/bearer/manage/info` with `Authorization: Bearer <accessToken>` or with the cookie from `useCookies`.

## Driving it with ae-http

Preconditions:

- Host is healthy.
- User `EMAIL` exists (register on `/identity/register` first). Use a fresh cookie jar so leftover application cookies do not confuse token vs cookie mode.

- **Token login.** Run `ae-http.sh post /identity/bearer/login "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out bearer-login`. Status is `200`. Body has `accessToken` and `refreshToken`.
- **Manage with bearer.** Export `AE_BEARER` to that access token. Run `ae-http.sh get /identity/bearer/manage/info --out bearer-info`. Status is `200`. `email` matches `EMAIL`.
- **Refresh.** Run `ae-http.sh post /identity/bearer/refresh "{\"refreshToken\":\"${REFRESH}\"}" --out bearer-refresh`. Status is `200`. Body has a new `accessToken`.
- **Bad refresh.** Run `ae-http.sh post /identity/bearer/refresh '{"refreshToken":"not-a-real-refresh-token"}' --out bearer-refresh-bad`. Status is `401`.
- **Cookie flag.** New jar. Run `ae-http.sh post "/identity/bearer/login?useCookies=true" "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out bearer-cookie`. Status is `200` or `204`. Then `ae-http.sh get /identity/bearer/manage/info --out bearer-cookie-info` is `200` **without** `AE_BEARER`.
- **Proof.** Keep `bearer-login.body` (both tokens), `bearer-info.body` (email), `bearer-refresh.body` (new access token), and `bearer-cookie-info.status` (`200`).

## Gotchas

- Facade cookie login (`/identity/login`) is a different handler. `useCookies` only applies to **this** Identity `Login` mapping.
- Do not map cookie and bearer login on the same path in a real host. The test host uses `/identity` vs `/identity/bearer`.
- Unset `AE_BEARER` before proving the cookie-flag path.
- `/identity/bearer` also maps management. Info lives under `/identity/bearer/manage/info`, not `/identity/manage/info`, when you signed in on the bearer prefix with cookies.
- Refresh body field is `refreshToken` (camelCase JSON).
