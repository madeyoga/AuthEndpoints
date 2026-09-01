# AuthEndpoints verification map

This directory is the maintained source for verifying the HTTP API the library exposes through the in-repo test host. Read this index before driving, then use the matching feature file as the recipe.

## Baseline preconditions

- Launch the test host with `.cursor/skills/verify-authendpoints/scripts/ae-http.sh launch`.
- `ae-http.sh doctor` reports `ok` for this run’s PID and `AE_BASE_URL`.
- Cookie jar is empty at the start of a feature unless that feature’s preconditions say otherwise.
- Password for new users is `Passw0rd!`. Emails must be unique per run (`verify-<id>@test.local`).
- Never drive a host this run did not start.
- This host has `RequireConfirmedAccount = false`. That is a **test-host** setting, not the library facade default.

## Driving conventions

- Start every recipe from the baseline (fresh jar, doctor ok) unless listed otherwise.
- Treat paths, JSON field names, and header names as literal.
- Send JSON as `application/json`. Use `--csrf` only on unsafe cookie or JWT-cookie mutations that the map marks as CSRF-protected.
- Login cookie route ignores `useCookies`. Bearer login does not.
- On 429, let the helper retry. Do not hammer `/identity/login` or `/auth/create`.
- Restore nothing in the database (in-memory). Start a new email or a new host if state is dirty.
- Do not delete proof files during cleanup.

## Proof and skip reporting

- Capture the request, status, headers, and body for each step (`--out`).
- Mutation proof includes a later GET (or a failed GET after logout).
- Record the feature ID and the exact path used.
- If an entry point cannot be reached, report the command and the unmet precondition. Do not mark it verified via a different path.
- `/test/*` routes are not library entry points.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph. It then uses exactly four H2 sections in this order.

1. `Sub-features` lists short IDs with one line for each behavior.
2. `How to get to it (user POV)` lists every client entry point.
3. `Driving it with ae-http` starts with `Preconditions:` and pairs each action with an exact command and observable result.
4. `Gotchas` lists traps that can waste or invalidate a run.

## Features

- [Cookie session](./cookie-session.md) covers register, cookie login, session info, and logout.
- [CSRF on cookie mutations](./csrf.md) covers token issue and the requirement on cookie logout.
- [Identity bearer](./identity-bearer.md) covers token login, refresh, and the `useCookies` query flag on the compose host prefix `/identity/bearer`.
- [Identity bearer facade](./bearer-facade.md) covers the one-call `MapAuthEndpointsBearer` host (`AE_HOST_MODE=bearer-facade`) at `/identity/login`.
- [Simple JWT](./simple-jwt.md) covers `/auth/create`, verify, and refresh-cookie refresh.
- [ReAuth step-up](./reauth.md) covers `confirmIdentity` and a protected manage mutation.
