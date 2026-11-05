---
name: authendpoints
description: "Wire AuthEndpoints in an ASP.NET Core host. AddPasswordAuth, UseAuthEndpoints, and MapPasswordAuth are the password session (cookie by default, prefix /auth). AddAuthEndpoints is the 3.x compatibility facade. Covers JWT, Identity bearer, passkeys, CSRF, ReAuth, email code, GitHub or Google, active sessions, and composing building blocks. Use when the project references the AuthEndpoints package, the user asks for Identity auth API endpoints, or the task is login, register, session, or token flows for a first-party web or mobile client. Read this skill instead of decompiling the assembly or web-searching the API."
license: MIT
metadata:
  version: "4.1.0"
---

# Wire AuthEndpoints

Use this skill when the app consumes the NuGet package.

Use the symbols, routes, and option names on this page and in `references/`. Do not decompile the assembly or guess names from other auth libraries. For anything not covered here, follow the pages at https://authendpoints.harten.id.

This skill ships inside the `AuthEndpoints` package, so the copy under `~/.nuget/packages/authendpoints/<version>/skills/authendpoints/` matches the API of that version. A copy taken from the repository with `npx skills add` follows the main branch and can describe a newer release than the one the app restores. When the two differ, prefer the copy in the NuGet cache.

The host needs the .NET 10 SDK (`net10.0`), ASP.NET Core Identity, and EF Core. `TUser` is a class with a public parameterless constructor. The usual user type derives from `IdentityUser<TKey>`. The key may be `string`, `Guid`, `long`, or another Identity key. `AddJwtEndpoints` throws `{TypeName} must derive from IdentityUser<TKey> to use AuthEndpoints.` when `TUser` does not derive from `IdentityUser<TKey>`. Passwordless passkey registration throws that same message in that case. A key other than `string` or `Guid` throws `Passwordless passkey registration requires IdentityUser with a string or Guid key so the user id can be chosen before CreateAsync.`

Current packages:

| Package | Version | Role |
| --- | --- | --- |
| `AuthEndpoints` | 4.1.0 | Endpoints, both facades, and external OAuth types in namespace `AuthEndpoints.External.OAuth` |
| `AuthEndpoints.OAuth.GitHub` | 4.0.1 | Registers the GitHub handler. The host maps the routes. |
| `AuthEndpoints.OAuth.Google` | 4.0.1 | Registers the Google handler. The host maps the routes. |
| `AuthEndpoints.External.OAuth` | 4.0.1 | Forwarding shim. Remove the reference. |

The provider packages depend on `AuthEndpoints` `[4.0.0, 5.0.0)`. A reference to `AuthEndpoints.External.OAuth` below 4.0.0 fails the build with `AE4000`. The 4.0.1 shim warns `AE4001`.

## Choose the session

| Client | Call |
| --- | --- |
| First-party browser, one password session | `AddPasswordAuth` and `MapPasswordAuth`. Leave `Session` unset. |
| Browser or native client that wants a Simple JWT | `Session = AuthEndpointsSession.Jwt` and a `Jwt` callback on `AddPasswordAuth`. See [references/jwt.md](references/jwt.md). |
| Native client that wants Identity bearer tokens | `AddAuthEndpoints(..., AuthEndpointsSignIn.IdentityBearer)` and `MapAuthEndpoints`. |
| Cookie and a second session | `MapSignInEndpoints` on each prefix and `MapSharedAuthEndpoints` once. See [references/composition.md](references/composition.md). |

Map one sign-in stack per prefix. Cookie and bearer both map `POST /logout`, so they need different prefixes.

## Wire one password session

New hosts that want one password session call `AddPasswordAuth`, `UseAuthEndpoints`, and `MapPasswordAuth`. The session is a cookie. The prefix is `/auth`. Passkeys stay off until `Passkeys.ServerDomain` is set. Email-code sign-in and external sign-in stay unmapped. Roles use `AddPasswordAuth<TUser, TRole, TContext>` so `AddRoles<TRole>()` runs before `AddEntityFrameworkStores`. `IUserStore<TUser>` then implements `IUserRoleStore<TUser>`, `RoleManager<TRole>` resolves, and sign-in uses `UserClaimsPrincipalFactory<TUser, TRole>`. The context is `IdentityDbContext<TUser, TRole, TKey>` or the equivalent. The two-type overload registers no roles. Do not chain `.AddRoles<TRole>()` after it.

```cs
builder.Services.AddDbContext<AppDbContext>(/* your provider */);

builder.Services.AddPasswordAuth<AppUser, AppDbContext>(o =>
{
	o.Passkeys.ServerDomain = "example.com"; // omit to leave passkeys off
});

builder.Services.AddTransient<IEmailSender<AppUser>, MyEmailSender>();

var app = builder.Build();

app.UseAuthEndpoints();
app.MapPasswordAuth<AppUser>();
```

`AddPasswordAuth` registers Identity (`RequireConfirmedAccount` true, schema version 3), password sign-up, sign-in, and recovery, account management, and the cookie session. A second `AddPasswordAuth` throws. `MapPasswordAuth` without `AddPasswordAuth` throws `InvalidOperationException`.

`UseAuthEndpoints` adds authentication, authorization, rate limiting, and antiforgery, in that order. Call it after exception-handling middleware. Enable HTTPS in Production yourself. A second call is a no-op.

`MapPasswordAuth<AppUser>` maps the routes under `PasswordAuthOptions.Path`. Cookie login is `POST /auth/login` and returns an empty `200` plus `Set-Cookie: .AspNetCore.Identity.Application`. A host that also calls `AddAuthEndpoints` fails startup validation.

Tutorial: [Quick start](https://authendpoints.harten.id/getting-started/quick-start). The building-block list is on [Password auth](https://authendpoints.harten.id/modules/password-auth).

## Set password facade options

`AddPasswordAuth<TUser, TContext>(Action<PasswordAuthOptions>?)` takes these options. `Session`, `Path`, and `Passkeys.ServerDomain` are fixed by that callback. A later `Configure<PasswordAuthOptions>` that changes any of them fails validation. `EmailConfirmation` can still be set later.

| Property | Default | Meaning |
| --- | --- | --- |
| `Session` | `AuthEndpointsSession.Cookie` | `Cookie` or `Jwt`. `IdentityBearer` fails validation. |
| `Path` | `/auth` | Rooted prefix for every route this facade maps. |
| `RequireConfirmedAccount` | `true` | Applied before `ConfigureIdentity`. Unconfirmed sign-in is `401`. |
| `Passkeys.ServerDomain` | `null` | A non-whitespace value maps passkey sign-in and management. Omit it to leave passkeys off. An empty or whitespace value leaves them off and fails validation in Production. |
| `EmailConfirmation.ConfirmEmailRedirectUri` | `null` | After `GET` confirm-email, redirect here. Absolute `https` (or `http` in Development), or a rooted path. Null keeps the plain-text response. |
| `EmailConfirmation.AllowedRedirectOrigins` | empty | Required when the redirect URI is absolute. A rooted path needs no entry. |
| `Jwt` | `null` | Required `Action<SimpleJwtOptions>` when `Session` is `Jwt`. |
| `ConfigureIdentity` | `null` | `Action<IdentityOptions>` after `RequireConfirmedAccount`. |
| `RequireEmailSenderInProduction` | `true` | Production requires a real `IEmailSender<TUser>`. Identity's no-op sender fails startup. Development skips that check. |

`AddPasswordAuth` copies `EmailConfirmation` onto `AuthEndpointsOptions.EmailConfirmation`, which the confirm-email handler reads.

Set the ReAuth lifetime with `Configure<AuthEndpointsReAuthOptions>`. The default is 5 minutes. Startup rejects a lifetime under 1 minute or over 60 minutes. The cookie is a browser-session cookie. The ticket expires after `Lifetime` and stays fixed if the user keeps calling the API.

```cs
builder.Services.Configure<AuthEndpointsReAuthOptions>(o =>
{
	o.Lifetime = TimeSpan.FromMinutes(2);
});
```

Full tables: [Configuration options](https://authendpoints.harten.id/modules/configuration).

## Read the reference for the task

Load only the file the task needs. Each one is self-contained.

| Task | File |
| --- | --- |
| Every password facade route, its auth, CSRF, ReAuth, and rate limit | [references/routes.md](references/routes.md) |
| JWT session, refresh rotation, refresh transport, signing keys | [references/jwt.md](references/jwt.md) |
| Antiforgery token, header, and the bearer-header skip rule | [references/csrf.md](references/csrf.md) |
| Passkey routes, user ids, and completers | [references/passkeys.md](references/passkeys.md) |
| ReAuth step-up, `reauthToken`, `.RequireReauth()` | [references/reauth.md](references/reauth.md) |
| Email-code sign-in, magic link, email-code step-up | [references/email-code.md](references/email-code.md) |
| GitHub or Google sign-in, linking, unlinking | [references/external-oauth.md](references/external-oauth.md) |
| List and revoke signed-in sessions | [references/active-sessions.md](references/active-sessions.md) |
| More than one session, or a mix neither facade covers | [references/composition.md](references/composition.md) |
| A host still on `AddAuthEndpoints` and `MapAuthEndpoints` (3.x) | [references/compatibility-facade.md](references/compatibility-facade.md) |

To make this app an OAuth 2.0 authorization server for other apps, CLIs, or MCP clients, use the `authendpoints-openiddict` skill that ships in the `AuthEndpoints.OpenIddict` package.

## Check production

- Serve the API over HTTPS. `UseAuthEndpoints` leaves HTTPS to the host.
- Register a real `IEmailSender<TUser>`. The password facade and `AddJwtEndpoints` register `LoggingAccountSecurityEmailSender<TUser>` when no `IAccountSecurityEmailSender<TUser>` is registered. That sender writes registration-attempt notices to the log.
- For email code, call `UseEmailCodes()`, register a real `IEmailCodeSender<TUser>` outside Development, and use `https` plus `AllowedOrigins` for an absolute magic-link URI in Production.
- Set `Passkeys.ServerDomain` when passkeys stay on. On the 3.x facade, set `Passkeys.Enabled` to false to turn them off. On the password facade, omit `ServerDomain`.
- For JWT, call `UseRefreshToken()` and set a real issuer, audience, and signing key.

Page: [Prepare for production](https://authendpoints.harten.id/concepts/production).
