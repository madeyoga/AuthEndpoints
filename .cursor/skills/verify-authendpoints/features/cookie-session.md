# Cookie session

A first-party browser client registers with email and password, signs in through the cookie login handler, reads account info with the application cookie, and signs out.

## Sub-features

- `register-ok` creates an account at `POST /identity/register` and returns 200.
- `register-invalid` rejects a non-email with 400.
- `register-duplicate` returns 200 for a duplicate email (no second account signal).
- `login-ok` signs in at `POST /identity/login` and sets `.AspNetCore.Identity.Application`.
- `login-bad` returns 401 with `Invalid credentials` for a wrong password.
- `info-session` returns 200 and the same email from `GET /identity/manage/info` after login.
- `logout-session` clears the session so a later info GET is 401.

## How to get to it (user POV)

- `POST /identity/register` with JSON `{ "email", "password" }`.
- `POST /identity/login` with the same JSON. Optional query `useSessionCookies=false` for a persistent cookie. `useCookies` is ignored on this handler.
- `GET /identity/manage/info` with the application cookie.
- `POST /identity/logout` with the application cookie and CSRF header.

## Driving it with ae-http

Preconditions:

- Host is healthy (`ae-http.sh doctor`).
- Cookie jar is empty.
- `EMAIL` is unused on this host. `PASS` is `Passw0rd!`.

- **Register.** Create the account. Run `ae-http.sh post /identity/register "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out register`. Status is `200`. Body is empty or `{}`.
- **Invalid email.** Register `not-an-email`. Run `ae-http.sh post /identity/register '{"email":"not-an-email","password":"Passw0rd!"}' --out register-invalid`. Status is `400`.
- **Login.** Sign in. Run `ae-http.sh post /identity/login "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out login`. Status is `200` or `204`. Headers include `Set-Cookie` for `.AspNetCore.Identity.Application`.
- **Wrong password.** Use a distinct email that was registered, then login with `WrongPass1!`. Status is `401`. Body contains `Invalid credentials` and does not contain `LockedOut`.
- **Session info.** Read the signed-in account. Run `ae-http.sh get /identity/manage/info --out info`. Status is `200`. Body `email` matches `EMAIL`.
- **Logout.** End the session. Run `ae-http.sh post --csrf /identity/logout --out logout`. Status is `200` or `204`.
- **Logged out.** Read info again. Run `ae-http.sh get /identity/manage/info --out info-after-logout`. Status is `401`.
- **Proof.** Keep `register.*`, `login.headers` (cookie), `info.body` (email), and `info-after-logout.status` (`401`).

## Gotchas

- This path is `LoginCookie` on `/identity/login`. `useCookies=true` does nothing here. Persistent vs session is only `useSessionCookies=false` vs omitted/true.
- Register does not sign the user in. Always login after register before calling `/manage/info`.
- Duplicate email register is 200 by design. Use a new email when you need a distinct user.
- Login is rate-limited (token bucket). Bursting logins from one IP yields 429.
- Logout without CSRF is a CSRF failure, not a successful logout. See [CSRF on cookie mutations](./csrf.md).
- Test host allows unconfirmed users to sign in. Production facade default does not.
