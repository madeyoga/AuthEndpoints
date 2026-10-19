# CSRF on cookie mutations

Cookie clients must fetch an antiforgery token and send it on unsafe methods that mutate the cookie session. The filter skips only when a non-empty `Authorization: Bearer` header is present, Identity bearer or JWT authenticates, and the application cookie does not. A token delivered only by a cookie still requires CSRF. A refresh cookie alone does not. Hosts that read the access token from a cookie send the CSRF token.

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
- **Logout without header.** POST logout with the session cookie and no CSRF. Run `ae-http.sh post /identity/logout --out logout-no-csrf`. Status is `400`. Body is `Invalid or missing CSRF token.`
- **Still signed in.** Run `ae-http.sh get /identity/manage/info --out info-still-signed-in`. Status is `200`.
- **Logout with header.** POST logout through the harness CSRF helper. Run `ae-http.sh post --csrf /identity/logout --out logout-csrf`. Status is `200` or `204`.
- **Session gone.** Run `ae-http.sh get /identity/manage/info --out info-after-csrf-logout`. Status is `401`.
- **JWT CSRF endpoint.** Run `ae-http.sh get /auth/csrfToken --out jwt-csrf`. Status is `200` with `csrfToken`.
- **Traces.** Run `ae-http.sh traces`. Error spans and exception events are both zero. `ae-http.sh traces sql` lists `db.statement` for the logout and token requests and flags a repeated identical statement in one trace.
- **Proof.** Keep `csrf.body` (token), `logout-no-csrf.status` (`400`), `info-still-signed-in.status` (`200`), `logout-csrf.status`, `info-after-csrf-logout.status` (`401`), and `traces-summary.txt`.

## Gotchas

- The header name is `RequestVerificationToken`. Hosts may rename it via `AntiforgeryOptions.HeaderName`; this test host does not.
- The token is bound to the antiforgery **cookie**. A token from a different jar fails.
- `--csrf` on JWT paths (`/auth/...`) uses `GET /auth/csrfToken`, not `/identity/csrfToken`.
- Identity bearer login JSON, `POST /identity/bearer/refresh`, and `POST /identity/bearer/logout` are not CSRF-protected. JWT cookie refresh protects `POST /auth/refresh` and `POST /auth/logout`. Body refresh does not. A refresh cookie alone does not skip CSRF. Cookie session + the same request still needs CSRF.
- Passkey ceremonies require a token for a cookie session and for JWT cookie refresh. Identity bearer and JWT body refresh do not. Compose `MapPasskeyEndpoints` follows Identity bearer. The cookie facade still requires the token.
- `/test/csrf` is a test-only probe. It can illustrate an anonymous 400, but it is not a library route. Do not cite it as the only CSRF proof.
