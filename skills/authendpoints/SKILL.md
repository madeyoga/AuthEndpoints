---
name: authendpoints
description: Compose AuthEndpoints 3.x in an ASP.NET Core host — AddAuthEndpoints, UseAuthEndpoints, MapAuthEndpoints, cookie vs Identity bearer vs Simple JWT, passkeys, CSRF, ReAuth, and production options. Use when the project has the AuthEndpoints NuGet package, the user asks to add Identity auth API endpoints, or an agent is wiring login/register/session/token flows for a first-party web or mobile client.
license: MIT
---

# AuthEndpoints 3.x (library users)

Ready-made Identity auth API endpoints for first-party web and mobile clients. This skill is for **apps that consume the NuGet package**, not for changing the AuthEndpoints source repo.

Canonical docs: https://madeyoga.github.io/AuthEndpoints — follow those pages; do not invent APIs.

Requires **.NET 10**, ASP.NET Core Identity, and EF Core. The host `DbContext` is typically `IdentityDbContext<TUser>` (or with roles). `TUser` may use any Identity key type (`string`, `Guid`, `long`, …). Passwordless passkey **account register** needs a `string` or `Guid` key.

## Install

```bash
dotnet add package AuthEndpoints
```

GitHub/Google OAuth is a **separate preview** package (independent versioning, not in the facade):

```bash
dotnet add package AuthEndpoints.External.OAuth --prerelease
```

Docs: https://madeyoga.github.io/AuthEndpoints/modules/external-oauth

## Prefer the facade

One Add / Use / Map triad. Cookie is the default sign-in. Native/mobile uses `AuthEndpointsSignIn.IdentityBearer`. Compose modules yourself only for JWT-only hosts, custom prefixes, or a mix the facade does not cover.

### Cookie web

Default: **Identity management + cookie sign-in** at `IdentityPath` (`/identity`) and **passkeys** at `PasskeyPath` (`/account`). JWT is **opt-in**.

```cs
builder.Services.AddDbContext<AppDbContext>(/* your provider */);

builder.Services.AddAuthEndpoints<AppUser, AppDbContext>(o =>
{
    o.Passkeys.ServerDomain = "example.com"; // required in Production when passkeys are enabled
});

// Required in Production (Identity's no-op sender is rejected).
builder.Services.AddTransient<IEmailSender<AppUser>, MyEmailSender>();

var app = builder.Build();

app.UseAuthEndpoints();          // authentication, authorization, rate limiting, antiforgery
app.MapAuthEndpoints<AppUser>(); // /identity (management + cookie) + /account (passkeys)
app.Run();
```

### Identity bearer (native / mobile)

Same methods and pipeline. Maps Identity `Login` (JSON access and refresh tokens) instead of `LoginCookie`.

```cs
builder.Services.AddAuthEndpoints<AppUser, AppDbContext>(AuthEndpointsSignIn.IdentityBearer, o =>
{
    o.Passkeys.ServerDomain = "example.com";
});

builder.Services.AddTransient<IEmailSender<AppUser>, MyEmailSender>();

var app = builder.Build();

app.UseAuthEndpoints();
app.MapAuthEndpoints<AppUser>(); // /identity (management + bearer login/refresh) + /account (passkeys)
app.Run();
```

`AddAuthEndpoints` returns `IdentityBuilder` for optional chaining. It registers Identity API endpoints, EF stores, `IdentitySchemaVersions.Version3` (required for passkey credential storage), antiforgery, cookie or bearer auth helpers, ReAuth, and rate limits.

`UseAuthEndpoints` must run after exception-handling middleware. Enable HTTPS in Production separately. Safe to call once; a second call is a no-op.

Quick start: https://madeyoga.github.io/AuthEndpoints/getting-started/quick-start

### Roles

Use the three-type overload so `AddRoles` runs **before** `AddEntityFrameworkStores`:

```cs
builder.Services.AddAuthEndpoints<AppUser, AppRole, AppDbContext>(o =>
{
    o.Passkeys.ServerDomain = "example.com";
});
```

`DbContext` should be `IdentityDbContext<AppUser, AppRole, TKey>` (or equivalent). Do **not** chain bare `.AddRoles<TRole>()` after the two-type overload.

## Choose cookie vs bearer vs JWT

| Stack | Typical client | How to select |
| --- | --- | --- |
| **Cookie** | First-party browser / SPA | `AddAuthEndpoints` + `MapAuthEndpoints` |
| **Identity bearer** | Native / mobile (tokens in JSON, no cookie jar) | `AddAuthEndpoints(..., AuthEndpointsSignIn.IdentityBearer)` + `MapAuthEndpoints` |
| **Simple JWT** | Browser that wants a Bearer access token + HttpOnly refresh cookie | Facade `o.Jwt.Enabled = true` and `modelBuilder.UseRefreshToken()` |

Mixed web + native: map **separate** sign-in groups (or hosts) per client type. Do not map cookie and bearer login on the same path without separate groups.

Recipes: https://madeyoga.github.io/AuthEndpoints/composables/recipes

## Login query flags

**Which handler is mapped decides which query flags work.** Cookie facade / `MapCookieAuthEndpoints` maps `LoginCookie`. Bearer facade / `MapBearerAuthEndpoints` maps Identity `Login`. `useCookies` on the cookie-facade login URL does nothing.

### Cookie facade → `LoginCookie`

Always the application cookie. Only `useSessionCookies` is read. **`useCookies` is ignored.**

| Query | Result |
| --- | --- |
| omitted or `useSessionCookies=true` | session cookie (`isPersistent = false`) |
| `useSessionCookies=false` | persistent cookie |

Body is Identity `LoginRequest` (`email`, `password`, optional `twoFactorCode` / `twoFactorRecoveryCode`). `POST /login` does not need CSRF. Lockout on failure. Rate-limited.

### Bearer facade → Identity `Login`

Cookie iff `useCookies==true || useSessionCookies==true`. Persistent iff `useCookies==true && useSessionCookies!=true`. Neither flag → Identity bearer tokens (`AccessTokenResponse`).

| Query | Result |
| --- | --- |
| neither flag | Identity bearer tokens |
| `useCookies=true` (and `useSessionCookies` not true) | persistent application cookie |
| `useSessionCookies=true` | session application cookie |

Default passkey completer (`IdentityPasskeySignInCompleter`) uses **these Identity `Login` rules**, not `LoginCookie` — even when password login uses the cookie facade.

## CSRF on cookie mutations

Cookie sessions and the JWT refresh cookie need antiforgery on unsafe methods (`POST` / `PUT` / `PATCH` / `DELETE`). Login does not.

1. `GET {prefix}/csrfToken` (cookie facade: `/identity/csrfToken`; JWT: `/auth/csrfToken`) → JSON `csrfToken`.
2. Send the token in the antiforgery **header**.
3. Send cookies (`credentials: "include"` / Axios `withCredentials`).

The library calls `AddAntiforgery()` with no header override. ASP.NET Core's default header name is `RequestVerificationToken`. Hosts may set `AntiforgeryOptions.HeaderName` to `X-CSRF-TOKEN` (common for SPAs). **Clients must use the header the host configured.**

CSRF is skipped when the request is authenticated via Identity bearer or JWT Bearer **and not** via the application/external cookie. Cookie sessions still require CSRF even if a bearer token is also present.

## Facade options

| Property | Default | Notes |
| --- | --- | --- |
| `IdentityPath` | `/identity` | Management + the configured sign-in stack |
| `SignIn` | `Cookie` | `Cookie` or `IdentityBearer`. Pass `IdentityBearer` to `AddAuthEndpoints`, or set `o.SignIn`. |
| `PasskeyPath` | `/account` | Passkey routes |
| `RequireConfirmedAccount` | `true` | Confirmed email required before sign-in. Set `false` only if the host accepts unconfirmed sign-in. |
| `Passkeys.Enabled` | `true` | When false, passkey DI and mapping are skipped |
| `Passkeys.ServerDomain` | `null` | WebAuthn RP domain. **Required in Production** when enabled |
| `Jwt.Enabled` | `false` | When true, registers and maps JWT |
| `Jwt.Path` | `/auth` | JWT route prefix |
| `Jwt.Configure` | `null` | `Action<SimpleJwtOptions>` (issuer, audience, signing, lifetimes) |
| `ConfigureIdentity` | `null` | After secure Identity defaults |
| `ConfigurePasskeys` | `null` | After `ServerDomain` is applied |
| `RequireEmailSenderInProduction` | `true` | Production must register a real `IEmailSender<TUser>` |

Full table: https://madeyoga.github.io/AuthEndpoints/getting-started/configuration

Password `/register` does not sign the user in. Duplicate email returns `200 OK` (no enumeration). With the default confirmed-account policy, unconfirmed login is **401**; passkey register still stores the credential but does not create a session.

## Passkeys

Enabled by default. In Production set `Passkeys.ServerDomain`, or disable with `o.Passkeys.Enabled = false`.

Mapped under `{PasskeyPath}/passkeys` (default `/account/passkeys`). CSRF is required for WebAuthn ceremonies. Add/rename/delete/`creationOptions` also require ReAuth.

Facade JWT opt-in does **not** auto-select `JwtPasskeySignInCompleter`. Register it explicitly when passkey register/login should issue Simple JWT (access token + refresh cookie); that completer ignores cookie query flags.

Module: https://madeyoga.github.io/AuthEndpoints/modules/passkeys

## Simple JWT (opt-in)

When `o.Jwt.Enabled = true`:

- Call `modelBuilder.UseRefreshToken()` and migrate (`AuthEndpoints.AuthEndpointsRefreshTokens`).
- Production: non-default issuer and audience; symmetric key ≥ 32 UTF-8 bytes (or RSA/ECDSA/X509).
- Refresh cookie name: `AuthEndpoints.Jwt.RefreshToken`. Recreate the table if upgrading from plaintext storage.

Module: https://madeyoga.github.io/AuthEndpoints/modules/jwt

## Compose when the facade does not fit

Custom prefixes, JWT-only, or a custom mix. Match DI to maps. Pipeline equivalent of `UseAuthEndpoints`:

```cs
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.UseAntiforgery();
```

| You map | You register |
| --- | --- |
| `MapIdentityManagementApi` | Identity API endpoints + EF stores + token providers |
| `MapCookieAuthEndpoints` | `AddCookieAuthEndpoints()` + `AddAntiforgery()` |
| `MapBearerAuthEndpoints` | `AddBearerAuthEndpoints()` |
| `MapJwtAuthEndpoints` | `AddJwtEndpoints<TUser, TContext>(…)` + `UseRefreshToken()` |
| `MapPasskeyEndpoints` | `AddPasskeyEndpoints<TUser>()` |

Map `MapIdentityManagementApi` **once** in production. Pair it with **one** of cookie | bearer | JWT per prefix.

https://madeyoga.github.io/AuthEndpoints/composables

## ReAuth (step-up)

Manage 2FA/info mutations and sensitive passkey routes require ReAuth plus CSRF where applicable. Header: `X-AuthEndpoints-Reauth` with `reauthToken`. Cookie scheme: `AuthEndpoints.ReAuth`. Protect host endpoints with `.RequireReauth()`.

https://madeyoga.github.io/AuthEndpoints/modules/reauth

## Production checklist

- HTTPS
- Real `IEmailSender<TUser>`
- `Passkeys.ServerDomain` if passkeys stay enabled; otherwise `Passkeys.Enabled = false`
- JWT: `UseRefreshToken()`, real issuer/audience/signing material

https://madeyoga.github.io/AuthEndpoints/getting-started/production
