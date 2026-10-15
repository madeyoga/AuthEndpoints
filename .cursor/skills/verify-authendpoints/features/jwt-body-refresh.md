# JWT body refresh

`AE_JWT_REFRESH_TRANSPORT=Body` puts the refresh token in JSON for native and CLI clients. Login, email-code verify, and refresh return `refreshToken`. Refresh and logout read that value from the body. There is no JWT antiforgery and no JWT `csrfToken` route.

## Sub-features

- `body-create` returns `200` `{ accessToken, tokenType, refreshToken }` from `POST /auth/create` and does not set `AuthEndpoints.Jwt.RefreshToken`
- `body-verify` returns `204` from `GET /auth/verify` with `Authorization: Bearer` and does not return a refresh token
- `body-refresh` returns a new `accessToken` and `refreshToken` from `POST /auth/refresh` with no CSRF header and no cookie
- `body-replay` of the previous refresh token returns `400`, and the successor then fails too
- `body-logout` returns `200` from `POST /auth/logout` with `{ "refreshToken" }`, and a later refresh of that token is `400`
- `body-absolute` with `AE_JWT_ABSOLUTE_LIFETIME` rejects refresh after that cap
- `split-verify` on `AE_HOST_MODE=split` returns `refreshToken` from `POST /app/emailCode/verify`

## How to get to it (user POV)

- `POST /auth/create` JSON `{ "email", "password" }`
- `GET /auth/verify` with `Authorization: Bearer`
- `POST /auth/refresh` JSON `{ "refreshToken" }`
- `POST /auth/logout` JSON `{ "refreshToken" }`
- Split host: `POST /emailCode/send`, then `POST /app/emailCode/verify` JSON `{ "email", "code" }`, then `POST /app/refresh`

## Driving it with ae-http

Preconditions:

- Launch with `AE_JWT_REFRESH_TRANSPORT=Body`. Add `AE_JWT_ABSOLUTE_LIFETIME=00:00:03` only for the cap case. Add `AE_HOST_MODE=split` and `AE_EMAIL_CODE` is unnecessary on split; the compose host does not need `AE_EMAIL_CODE` for `/auth/create`.
- Host is healthy (`ae-http.sh doctor`). Compose doctor still uses `GET /identity/csrfToken`.
- Cookie jar starts empty. Body mode must not depend on it.
- `EMAIL` is unused. Password is `Passw0rd!`.

- **Create.** Run `ae-http.sh post /auth/create "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out jwt-body-create`. Status is `200`. Body has `accessToken`, `tokenType` `Bearer`, and `refreshToken`. Headers do not set `AuthEndpoints.Jwt.RefreshToken`.
- **Verify.** `export AE_BEARER` to that access token. Run `ae-http.sh get /auth/verify --out jwt-body-verify`. Status is `204`.
- **Refresh.** Run `ae-http.sh post /auth/refresh "{\"refreshToken\":\"REFRESH\"}" --out jwt-body-refresh` with no `--csrf`. Status is `200`. Body has a new `accessToken` and a new `refreshToken`.
- **Replay.** POST `/auth/refresh` again with the create-time `refreshToken`. Status is `400`. POST the refresh from the successful rotation. Status is `400`.
- **Logout.** On a new create, run `ae-http.sh post /auth/logout "{\"refreshToken\":\"REFRESH\"}" --out jwt-body-logout`. Status is `200`. A later refresh with that token is `400`.
- **Absolute lifetime.** Relaunch with `AE_JWT_ABSOLUTE_LIFETIME=00:00:03`. Create, wait at least 3 seconds, refresh. Status is `400`.
- **Email-code verify.** Relaunch with `AE_HOST_MODE=split` and `AE_JWT_REFRESH_TRANSPORT=Body`. Register at `POST /register` (or seed a confirmed user). `POST /emailCode/send` JSON `{ "email" }`. Read the code from `GET /test/mailbox`. `POST /app/emailCode/verify` JSON `{ "email", "code" }`. Status is `200` with `refreshToken` and no refresh cookie. `POST /app/refresh` with that token returns `200`.
- **Proof.** Keep create body (has `refreshToken`, headers lack the refresh cookie), verify status `204`, refresh body (new `refreshToken`), replay statuses `400` and `400`, and logout status `200` followed by refresh `400`.

## Gotchas

- Do not pass `--csrf` on body refresh or logout. `/auth/csrfToken` is `404` in this mode.
- `GET /verify` does not issue a refresh token.
- A reused refresh token revokes the family. The token you just received also stops working.
- The default family cap is 14 days from sign-in. `AE_JWT_ABSOLUTE_LIFETIME` is a test-host override, not a library default.
- Compose `POST /identity/emailCode/verify` is the Identity bearer completer unless the host is split and you call `/app/emailCode/verify`.
- Cookie-mode JWT is [simple-jwt.md](./simple-jwt.md). Leave `AE_JWT_REFRESH_TRANSPORT` unset for that recipe.
