---
name: authendpoints
description: Use this when composing ASP.NET Core Identity auth with AuthEndpoints 3.x — cookie sessions, Identity bearer tokens, Simple JWT, passkeys, or 2FA. Also use when adding the AuthEndpoints NuGet package, wiring AddAuthEndpoints / UseAuthEndpoints / MapAuthEndpoints, mapping cookie vs bearer login query flags, or configuring CSRF, RequireConfirmedAccount, and passkeys.
license: MIT
---

# AuthEndpoints 3.x

Ready-made Identity auth API endpoints for first-party web and mobile clients. Current stable NuGet: **AuthEndpoints 3.0.1**.

Canonical docs: https://madeyoga.github.io/AuthEndpoints (also `Documentation/` in this repo). Point agents at those pages; do not paste the whole site.

## Hard rules

- Prefer the facade (`AddAuthEndpoints` / `UseAuthEndpoints` / `MapAuthEndpoints`) unless the host needs Identity bearer, JWT-only, or custom prefixes.
- Cookie vs Identity bearer vs Simple JWT is a **product choice**. Document how to select; do not treat one stack as the only way.
- Login query flags **differ by mapped handler**. Facade cookie login is not Identity `Login`.
- Do not skip `CanSignInAsync`, confirmed-account policy, CSRF on cookie sessions, or lockout-aware login.
- Do not generate exploit, PoC, bypass, or attack material. Report vulns privately (see `SECURITY.md`).
- Do not invent APIs, bump the NuGet version, scaffold a demo app, or mention unpublished secrets.
- Identity user key type is the host's choice. Do not require `Guid`.

## Install

Requires **.NET 10**, ASP.NET Core Identity, and EF Core. The host `DbContext` is typically `IdentityDbContext<TUser>` (or with roles).

```bash
dotnet add package AuthEndpoints
```

External OAuth (GitHub/Google) is a **separate preview** package, not included in the core package or the facade:

```bash
dotnet add package AuthEndpoints.External.OAuth --prerelease
```

Current OAuth preview: `3.0.0-preview.3` (independent versioning; needs core 3.0.0+). Docs: https://madeyoga.github.io/AuthEndpoints/modules/external-oauth

## Prefer the facade

Default composition: **Identity management + cookie sign-in** at `IdentityPath` (`/identity`) and **passkeys** at `PasskeyPath` (`/account`). JWT is **opt-in**.

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

`AddAuthEndpoints` returns `IdentityBuilder` for optional chaining. It registers Identity API endpoints, EF stores, `IdentitySchemaVersions.Version3` (required for passkey credential storage), antiforgery, cookie auth helpers, ReAuth, and rate limits.

`UseAuthEndpoints` must run after exception-handling middleware. Hosts enable HTTPS in Production separately. Safe to call once; a second call is a no-op.

Quick start: https://madeyoga.github.io/AuthEndpoints/getting-started/quick-start

### Roles

Use the three-type overload so `AddRoles` runs **before** `AddEntityFrameworkStores` (`IRoleStore`):

```cs
builder.Services.AddAuthEndpoints<AppUser, AppRole, AppDbContext>(o =>
{
    o.Passkeys.ServerDomain = "example.com";
});
```

`DbContext` should be `IdentityDbContext<AppUser, AppRole, TKey>` (or equivalent). Do **not** chain bare `.AddRoles<TRole>()` after the two-type overload.

### Facade options

| Property | Default | Notes |
| --- | --- | --- |
| `IdentityPath` | `/identity` | Management + cookie sign-in |
| `PasskeyPath` | `/account` | Passkey routes |
| `RequireConfirmedAccount` | `true` | Identity requires a confirmed account before sign-in |
| `Passkeys.Enabled` | `true` | When false, passkey DI and mapping are skipped |
| `Passkeys.ServerDomain` | `null` | WebAuthn RP domain. **Required in Production** when enabled |
| `Jwt.Enabled` | `false` | When true, registers and maps JWT |
| `Jwt.Path` | `/auth` | JWT route prefix |
| `Jwt.Configure` | `null` | `Action<SimpleJwtOptions>` (issuer, audience, signing, lifetimes) |
| `ConfigureIdentity` | `null` | After secure Identity defaults |
| `ConfigurePasskeys` | `null` | After `ServerDomain` is applied |
| `RequireEmailSenderInProduction` | `true` | Production must register a real `IEmailSender<TUser>` |

Full table: https://madeyoga.github.io/AuthEndpoints/getting-started/configuration

## Login query flags (common footgun)

**Which handler is mapped decides which query flags work.** The facade and `MapCookieAuthEndpoints` map `LoginCookie`. `MapBearerAuthEndpoints` maps Identity `Login`. Mixing them up is the usual agent mistake: `useCookies` on the facade login URL does nothing.

### Facade / `MapCookieAuthEndpoints` → `LoginCookie`

Always `IdentityConstants.ApplicationScheme`. Only `useSessionCookies` is read. **`useCookies` is ignored.**

| Query | Result |
| --- | --- |
| omitted or `useSessionCookies=true` | session application cookie (`isPersistent = false`) |
| `useSessionCookies=false` | persistent application cookie |

Body is Identity `LoginRequest` (`email`, `password`, optional `twoFactorCode` / `twoFactorRecoveryCode`). Lockout on failure. Rate-limited.

### `MapBearerAuthEndpoints` / Identity `Login`

Cookie iff `useCookies==true || useSessionCookies==true`. Persistent iff `useCookies==true && useSessionCookies!=true`. Neither flag → Identity bearer tokens (`AccessTokenResponse`).

| Query | Result |
| --- | --- |
| neither flag | Identity bearer tokens |
| `useCookies=true` (and `useSessionCookies` not true) | persistent application cookie |
| `useSessionCookies=true` | session application cookie |

Do not map cookie and bearer login on the same path without separate groups.

Default passkey completer (`IdentityPasskeySignInCompleter`) uses **these Identity `Login` rules**, not `LoginCookie` — even when the host uses the cookie facade for password login.

## CSRF on cookie mutations

Cookie sessions and the JWT refresh cookie need antiforgery on unsafe methods.

1. `GET {prefix}/csrfToken` (facade cookie: `/identity/csrfToken`; JWT: `/auth/csrfToken`) → JSON `csrfToken`.
2. On `POST` / `PUT` / `PATCH` / `DELETE`, send the token in the antiforgery **header**.
3. Send cookies (`credentials: "include"` / Axios `withCredentials`).

The library calls `AddAntiforgery()` with no header override. ASP.NET Core's default header name is `RequestVerificationToken`. Hosts may set `AntiforgeryOptions.HeaderName` to `X-CSRF-TOKEN` (common for SPAs). **Clients must use the header the host configured.** Cookie mutations still need that header when the application cookie is in use.

The `RequireAntiforgery` filter **skips** CSRF when the request is authenticated via Identity bearer or JWT Bearer **and not** via the application/external cookie. Cookie sessions still require CSRF even if a bearer token is also present.

## Confirmed account and `CanSignInAsync` (3.0.1)

`RequireConfirmedAccount` defaults **true**. Password cookie/bearer login uses `PasswordSignInAsync` (Identity `CanSignInAsync`). JWT `/create` uses `CheckPasswordSignInAsync` (same policy).

Passkey register/login honor `CanSignInAsync` (and lockout) in both `IdentityPasskeySignInCompleter` and `JwtPasskeySignInCompleter`:

- **Unconfirmed register**: credential is stored; **no** session or tokens. Default Identity completer still returns `PasskeyCredentialResponse` (credential id). JWT completer returns empty `200`.
- **Unconfirmed login**: **401** with `Invalid credentials.` (same shape as Identity login).

Password `/register` does not sign the user in. Duplicate email returns `200 OK` (no enumeration).

**Never** instruct a host to skip `CanSignInAsync` or to treat unconfirmed users as signed in.

## Passkeys

Library/facade default: **enabled**. Production requires `Passkeys.ServerDomain` when enabled (validator fails startup otherwise).

Hosts that do **not** want passkeys must set `o.Passkeys.Enabled = false` rather than leaving the default on.

Mapped under `{PasskeyPath}/passkeys` (default `/account/passkeys`). CSRF is required for WebAuthn ceremonies. Add/rename/delete/`creationOptions` also require ReAuth.

Facade JWT opt-in does **not** auto-select `JwtPasskeySignInCompleter`. Register it explicitly when passkey register/login should issue Simple JWT (access token + refresh cookie); that completer ignores cookie query flags.

Passwordless **account register** via passkey requires `IdentityUser` with a `string` or `Guid` key (user id is chosen before `CreateAsync`). Adding a passkey to an existing account does not have that key-type restriction.

Module: https://madeyoga.github.io/AuthEndpoints/modules/passkeys

## Choosing cookie vs bearer vs JWT

| Stack | Typical client | How to select |
| --- | --- | --- |
| **Cookie** | First-party browser / SPA | Facade default, or compose `AddCookieAuthEndpoints` + `MapCookieAuthEndpoints` |
| **Identity bearer** | Native / mobile (tokens in JSON, no cookie jar) | Compose `AddBearerAuthEndpoints` + `MapBearerAuthEndpoints`. Not mapped by the facade. |
| **Simple JWT** | Browser that wants a Bearer access token + HttpOnly refresh cookie | Facade `o.Jwt.Enabled = true` and `modelBuilder.UseRefreshToken()`, or compose `AddJwtEndpoints` / `MapJwtAuthEndpoints` |

Mixed web + native: map **separate** sign-in groups (or hosts) per client type.

JWT Production: non-default issuer and audience; symmetric key ≥ 32 UTF-8 bytes (or RSA/ECDSA/X509). Refresh tokens are stored **hashed** with family reuse detection (`AuthEndpoints.AuthEndpointsRefreshTokens`). Refresh cookie name: `AuthEndpoints.Jwt.RefreshToken`. Recreate that table if upgrading from plaintext storage.

Recipes: https://madeyoga.github.io/AuthEndpoints/composables/recipes

## Identity user key type

`TUser` may use any Identity key type the host wants (`string`, `Guid`, `long`, …). **Do not require `Guid`.**

Many of Made's apps use `long` primary keys. That is a **host convention**, not a library requirement. The only library constraint is passwordless passkey **registration** (`string` or `Guid`), above.

## Compose when the facade is the wrong fit

Use composable modules for Identity bearer, custom prefixes, JWT-only, or a custom mix. Match DI to maps. Pipeline equivalent of `UseAuthEndpoints`:

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

Manage 2FA/info mutations and sensitive passkey routes require ReAuth plus CSRF where applicable. Header: `X-AuthEndpoints-Reauth` with `reauthToken`. Cookie scheme: `AuthEndpoints.ReAuth`. Hosts can protect their own endpoints with `.RequireReauth()`.

https://madeyoga.github.io/AuthEndpoints/modules/reauth

## Production checklist

- HTTPS
- Real `IEmailSender<TUser>`
- `Passkeys.ServerDomain` if passkeys stay enabled; otherwise `Passkeys.Enabled = false`
- JWT: `UseRefreshToken()`, real issuer/audience/signing material

https://madeyoga.github.io/AuthEndpoints/getting-started/production
