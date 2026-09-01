# CSRF on cookie mutations

Cookie clients must fetch an antiforgery token and send it on unsafe methods that mutate the cookie session. Token-only bearer requests skip that filter; a cookie session still requires CSRF even if a bearer token is also present.

## Sub-features

- `csrf-issue` returns a non-empty token from `GET /identity/csrfToken`.
- `logout-missing-csrf` rejects cookie logout without the header.
- `logout-with-csrf` succeeds when the header matches the antiforgery cookie in the jar.
- `jwt-csrf-issue` returns a token from `GET /auth/csrfToken` for JWT refresh/logout.

## How to get to it (user POV)

- `GET /identity/csrfToken` (cookie prefix) or `GET /auth/csrfToken` (JWT prefix).
- On `POST` / `PUT` / `PATCH` / `DELETE` that require antiforgery, send header `RequestVerificationToken` with that value **and** the cookies from the same jar.
- Cookie logout: `POST /identity/logout`.
- JWT refresh/logout: `POST /auth/refresh` and `POST /auth/logout` (JWT CSRF path).

## Driving it with ae-http

Preconditions:

- Host is healthy.
- A cookie session exists (register + `POST /identity/login` for `EMAIL`).
- Cookie jar still holds the application cookie and the antiforgery cookie from `csrfToken`.

- **Issue token.** Fetch CSRF. Run `ae-http.sh get /identity/csrfToken --out csrf`. Status is `200`. Body has `csrfToken`. Response sets an antiforgery cookie.
- **Logout without header.** POST logout with the session cookie and no CSRF. Run `ae-http.sh post /identity/logout --out logout-no-csrf`. Status is **not** 200/204 (typically 400) and the body mentions CSRF. A following `GET /identity/manage/info` is still **200** (session remains).
- **Logout with header.** POST logout through the harness CSRF helper. Run `ae-http.sh post --csrf /identity/logout --out logout-csrf`. Status is `200` or `204`.
- **Session gone.** Run `ae-http.sh get /identity/manage/info --out info-after-csrf-logout`. Status is `401`.
- **JWT CSRF endpoint.** Run `ae-http.sh get /auth/csrfToken --out jwt-csrf`. Status is `200` with `csrfToken`.
- **Proof.** Keep `csrf.body` (token), `logout-no-csrf.status` (failure) plus `info` still 200, then `logout-csrf.status` and `info-after-csrf-logout.status` (`401`).

## Gotchas

- The header name is `RequestVerificationToken`. Hosts may rename it via `AntiforgeryOptions.HeaderName`; this test host does not.
- The token is bound to the antiforgery **cookie**. A token from a different jar fails.
- `--csrf` on JWT paths (`/auth/...`) uses `GET /auth/csrfToken`, not `/identity/csrfToken`.
- Identity bearer login JSON and `POST /identity/bearer/refresh` are not cookie mutations. Do not require CSRF there. Cookie session + same request still needs CSRF.
- `/test/csrf` is a test-only probe. It can illustrate an anonymous 400, but it is not a library route. Do not cite it as the only CSRF proof.
