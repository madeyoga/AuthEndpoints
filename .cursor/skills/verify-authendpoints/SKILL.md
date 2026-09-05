---
name: verify-authendpoints
description: Drive the AuthEndpoints HTTP API via the in-repo test host (cookie sessions, Identity bearer, Simple JWT, CSRF, ReAuth). Use when verifying a change to src/AuthEndpoints or tests/AuthEndpoints.Tests, proving register/login/session/token behavior, or when a task needs a live auth API instead of only `dotnet test`.
---

# Verify AuthEndpoints

AuthEndpoints is a **library**, not a GUI app. The user-facing surface to drive is the **HTTP API** composed by the in-repo test host in `tests/AuthEndpoints.Tests/Program.cs`. A later agent that has never seen the repo should launch that host, call the same routes a first-party client would, and keep response files as proof.

xUnit under `tests/AuthEndpoints.Tests` is complementary regression coverage. It does **not** replace this skill. Do not treat `dotnet test` as evidence that a live cookie/CSRF/token path works.

The Nuxt docs site in `Documentation/` is a separate surface. Do not use this skill to verify docs UI.

## Launch

Preconditions:

- .NET **10** SDK on `PATH` (`dotnet --version` starts with `10.`).
- Run from the repository root.
- Pick a unique `AE_RUN_ID` and a free `AE_PORT`. Do not attach to an already-running host.

```bash
export PATH="$HOME/.dotnet:$PATH"   # if the SDK was installed with dotnet-install.sh
export AE_RUN_ID="${AE_RUN_ID:-$(date +%Y%m%dT%H%M%S)-$$}"
export AE_PORT="${AE_PORT:-5088}"
export AE_EVIDENCE_DIR="${AE_EVIDENCE_DIR:-/tmp/authendpoints-verify-${AE_RUN_ID}/evidence}"
HARNESS=".cursor/skills/verify-authendpoints/scripts/ae-http.sh"

chmod +x "$HARNESS"
"$HARNESS" launch
"$HARNESS" doctor
```

Ready signal for the default **compose** host: `GET {AE_BASE_URL}/identity/csrfToken` returns **200** and JSON with `csrfToken` (Pascal `CsrfToken` is also accepted). The helper polls that URL after start.

Identity bearer facade: set `AE_HOST_MODE=bearer-facade` before `launch`. Ready signal is `GET /identity/manage/info` returning **401**. Doctor prints `mode=bearer-facade`. See [bearer-facade.md](features/bearer-facade.md).

Teardown: `"$HARNESS" stop` kills **only** the PID in `$AE_RUN_DIR/host.pid`. It must not delete `$AE_EVIDENCE_DIR`.

What the host actually is (`tests/AuthEndpoints.Tests/Program.cs`):

Default `AE_HOST_MODE=compose`:

| Prefix | Mapped surface |
| --- | --- |
| `/identity` | Identity management + **cookie** login (`LoginCookie`) + logout + `/csrfToken` |
| `/identity/bearer` | Second management map + **Identity bearer** login (`Login`) |
| `/auth` | Simple JWT (`/create`, `/refresh`, `/verify`, `/logout`, `/csrfToken`) |
| `/account` | Passkey routes |
| `/test/*` | **Test-only** probes (`/test/csrf`, `/test/reauth`, `/test/csrf-auth`). Not library surface. Use them only as extra observation, never as the sole proof of a library feature. |

`AE_HOST_MODE=bearer-facade` uses `AddAuthEndpoints(..., AuthEndpointsSignIn.IdentityBearer)` / `MapAuthEndpoints` instead of the compose maps:

| Prefix | Mapped surface |
| --- | --- |
| `/identity` | Identity management + **Identity bearer** login (`Login`) + `/refresh` (no `/csrfToken`) |
| `/auth` | Simple JWT (facade JWT opt-in is on for this host) |
| `/account` | Passkey routes |
| `/test/*` | Same test-only probes |

Host defaults that **differ from production library defaults**:

- `SignIn.RequireConfirmedAccount = false` (library facade default is **true**). Set `AE_REQUIRE_CONFIRMED_ACCOUNT=true` before `launch` to match the library default for confirmation-gated sign-in.
- Password rules are relaxed (`RequiredLength = 6`, no digit/case/symbol requirements). Use `Passw0rd!`.
- EF Core **in-memory** database; all users vanish when the process exits.
- JWT signing key is the test-only value in `Program.cs`. Never treat it as a production secret.
- `IEmailSender<TUser>` is a capturing sender. `GET /test/mailbox` lists `{email,kind,body}` (confirmation links are HTML-encoded). This is a **test-only** probe.
- Software WebAuthn: `POST /test/webauthn/attestation` and `POST /test/webauthn/assertion` turn options JSON into `credentialJson`. These are **test-only** probes. The library still verifies attestation/assertion on `/account/passkeys/register` and `/login`.

Isolation: two hosts may run on **different ports**. Refuse to drive a port that was already listening when `launch` ran. Never kill by process name (`pkill`, `killall`).

## Doctor

Run `"$HARNESS" doctor` before the first drive, after any failed drive, and whenever the host looks wrong. It is read-only and must report:

1. `$AE_RUN_DIR/host.pid` exists and that PID is alive.
2. `AE_BASE_URL` accepts connections (the port we chose).
3. Compose host: `GET /identity/csrfToken` is 200 with a non-empty `csrfToken`. Bearer facade host: `GET /identity/manage/info` is 401.

If doctor fails, `stop` (if we started the process) and `launch` again. Do not keep driving a surprising instance.

## Drive

Use the harness. It wraps curl with a cookie jar, retries **429** (login is a token bucket: 10 tokens, +2 / 10s), and can attach CSRF, `Authorization: Bearer`, and `X-AuthEndpoints-Reauth`.

```bash
HARNESS=".cursor/skills/verify-authendpoints/scripts/ae-http.sh"
EMAIL="verify-${AE_RUN_ID}@test.local"
PASS='Passw0rd!'

"$HARNESS" post /identity/register "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out register
"$HARNESS" post /identity/login "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\"}" --out login
"$HARNESS" get /identity/manage/info --out info
"$HARNESS" post --csrf /identity/logout --out logout
```

Stable handles (paths and headers), not coordinates:

| Handle | Value |
| --- | --- |
| Cookie login | `POST /identity/login` JSON `{email,password}`. Query `useCookies` is **ignored**. Only `useSessionCookies=false` makes the cookie persistent. |
| Bearer login | `POST /identity/bearer/login` with **no** cookie flags → JSON `accessToken` + `refreshToken`. `?useCookies=true` issues the application cookie instead. |
| JWT login | `POST /auth/create` JSON `{email,password}` → JSON `accessToken`; refresh is cookie `AuthEndpoints.Jwt.RefreshToken`. |
| CSRF fetch | `GET /identity/csrfToken` or `GET /auth/csrfToken` |
| CSRF header | `RequestVerificationToken` (ASP.NET Core default; the library does not rename it) |
| ReAuth header | `X-AuthEndpoints-Reauth` with `reauthToken` from `POST /identity/confirmIdentity` |
| Session cookie | `.AspNetCore.Identity.Application` |
| JWT refresh cookie | `AuthEndpoints.Jwt.RefreshToken` |
| ReAuth cookie | `AuthEndpoints.ReAuth` |

Read the feature map before driving. Cover the mapped entry points for the feature you claim, not a single convenient alias.

`AE_BEARER` and `AE_REAUTH` are honored by the helper on every request when set:

```bash
export AE_BEARER='...'    # Identity bearer or JWT access token
export AE_REAUTH='...'    # reauthToken from confirmIdentity
```

## Evidence

Default location: `$AE_EVIDENCE_DIR` (default `/tmp/authendpoints-verify-$AE_RUN_ID/evidence`). `stop` must leave this directory in place.

Each drive step that uses `--out NAME` writes:

- `NAME.request` — method, URL, body
- `NAME.status` — HTTP status code
- `NAME.headers` — response headers (cookies, WWW-Authenticate)
- `NAME.body` — response body

Proof standards:

- Hit the **real client paths** in the table above, not `/test/*` as the only check, and not `WebApplicationFactory` internals.
- Capture the **action and the resulting state**. Example: login headers (`Set-Cookie`) **and** a later `GET /identity/manage/info` (200 + email), not only the login status.
- For mutations, prove a second read: after register+login, `manage/info`; after logout, `manage/info` is 401; after JWT create, `GET /auth/verify` with `Authorization: Bearer` is **204**.
- 429 is not success. Retry via the helper; if still 429, wait 10s and retry the step. Do not record a rate-limit as a product failure unless it persists on a fresh host.
- Duplicate register emails return **200** (no enumeration). Do not treat that 200 as “a second user was created” without a distinct email.

Cloud Agent walkthroughs may **copy** evidence files to `/opt/cursor/artifacts` after the drive. Copying is extra; the named evidence dir is the source of truth.

## Cleanup

```bash
"$HARNESS" stop
```

Removes the host process started by this run. Does **not** delete `$AE_EVIDENCE_DIR`. Cookie jar and host log under `$AE_RUN_DIR` may be left; they are scratch. After a failed iteration, still `stop` so the port is free.

Never `pkill -f AuthEndpoints` or similar.

## Helpers

```bash
.cursor/skills/verify-authendpoints/scripts/ae-http.sh --help
```

| Command | What it does |
| --- | --- |
| `launch` | `dotnet build` the test project, start `AuthEndpoints.Tests.dll` on `AE_BASE_URL`, wait until `/identity/csrfToken` is 200 (or `/identity/manage/info` is 401 when `AE_HOST_MODE=bearer-facade`) |
| `doctor` | PID + port + ready signal for the current `AE_HOST_MODE` |
| `csrf [path]` | Print the token string |
| `get <path> [--out N]` | GET with cookie jar |
| `post [--csrf] <path> [json] [--out N]` | POST JSON; `--csrf` fetches a token first (JWT paths use `/auth/csrfToken`) |
| `stop` | SIGTERM the launch PID |

The script is executable (`chmod +x` if git lost the bit).

## Feature map

Index: `.cursor/skills/verify-authendpoints/features/README.md`

Start with those files. Automated `dotnet test AuthEndpoints.sln` is allowed **in addition** after a live drive, not instead of it.

Passkeys (`/account/passkeys`) need a WebAuthn authenticator for a full ceremony. Do not claim passkey register/login verified from HTTP options JSON alone. Use the software authenticator at `/test/webauthn/attestation` and `/test/webauthn/assertion` (see [Passkeys](features/passkeys.md)), then POST the returned `credentialJson` to the library routes. xUnit in `tests/AuthEndpoints.Tests` covers the same ceremony.

## Maintenance

When the host mappings, CSRF header, or login query flags change, update this skill and the feature map. `/maintain-verification-skill` is the upkeep loop.
