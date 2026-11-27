---
name: authendpoints
description: "Wire AuthEndpoints in an ASP.NET Core host. AddAuthEndpoints returns a builder (AddPassword, AddPasskeys, AddEmailCode, AddJwt, AddIdentityBearer), and MapAuthEndpoints maps what was added under one prefix for one session. Covers JWT, Identity bearer, passkeys, CSRF, ReAuth, email code, GitHub or Google, active sessions, and composing building blocks. Use when the project references the AuthEndpoints package, the user asks for Identity auth API endpoints, or the task is login, register, session, or token flows for a first-party web or mobile client. Read this skill instead of decompiling the assembly or web-searching the API."
license: MIT
metadata:
  version: "4.3.0"
---

# Wire AuthEndpoints

Use this skill when the app consumes the NuGet package.

Use the symbols, routes, and option names on this page and in `references/`. Do not decompile the assembly or guess names from other auth libraries. For anything not covered here, follow the pages at https://authendpoints.harten.id.

This skill ships inside the `AuthEndpoints` package, so the copy under `~/.nuget/packages/authendpoints/<version>/skills/authendpoints/` matches the API of that version. A copy taken from the repository with `npx skills add` follows the main branch and can describe a newer release than the one the app restores. When the two differ, prefer the copy in the NuGet cache.

The host needs the .NET 10 SDK (`net10.0`), ASP.NET Core Identity, and EF Core. `TUser` is a class with a public parameterless constructor. The usual user type derives from `IdentityUser<TKey>`. The key may be `string`, `Guid`, `long`, or another Identity key. `AddJwtEndpoints` throws `{TypeName} must derive from IdentityUser<TKey> to use AuthEndpoints.` when `TUser` does not derive from `IdentityUser<TKey>`. Passwordless passkey registration throws that same message in that case. A key other than `string` or `Guid` throws `Passwordless passkey registration requires IdentityUser with a string or Guid key so the user id can be chosen before CreateAsync.`

Current packages:

| Package | Version | Role |
| --- | --- | --- |
| `AuthEndpoints` | 4.3.0 | Endpoints, the `AddAuthEndpoints` builder, and external OAuth types in namespace `AuthEndpoints.External.OAuth` |
| `AuthEndpoints.OAuth.GitHub` | 4.0.1 | Registers the GitHub handler. The host maps the routes. |
| `AuthEndpoints.OAuth.Google` | 4.0.1 | Registers the Google handler. The host maps the routes. |
| `AuthEndpoints.External.OAuth` | 4.0.1 | Forwarding shim. Remove the reference. |

The provider packages depend on `AuthEndpoints` `[4.0.0, 5.0.0)`. A reference to `AuthEndpoints.External.OAuth` below 4.0.0 fails the build with `AE4000`. The 4.0.1 shim warns `AE4001`.

## Choose the session

| Client | Call |
| --- | --- |
| First-party browser | `AddAuthEndpoints(...).AddPassword()` and `MapAuthEndpoints(path, AuthEndpointsSession.Cookie)`. |
| Browser or native client that wants a Simple JWT | Add `.AddJwt(jwt => ...)` and map `AuthEndpointsSession.Jwt`. See [references/jwt.md](references/jwt.md). |
| Native client that wants Identity bearer tokens | Add `.AddIdentityBearer()` and map `AuthEndpointsSession.IdentityBearer`. |
| Cookie and a second session | `MapSignInEndpoints` on each prefix and `MapSharedAuthEndpoints` once. See [references/composition.md](references/composition.md). |

Map one sign-in stack per prefix. Cookie and bearer both map `POST /logout`, so they need different prefixes.

## Wire one session

`AddAuthEndpoints<TUser, TContext>()` registers Identity (`RequireConfirmedAccount` true, schema version 3), account management, and the cookie session, and returns `AuthEndpointsBuilder<TUser, TContext>`. Each builder method adds one sign-in method or session. `MapAuthEndpoints<TUser>(path, session)` maps exactly what was added under one prefix. Roles use `AddAuthEndpoints<TUser, TRole, TContext>` so `AddRoles<TRole>()` runs before `AddEntityFrameworkStores`. `IUserStore<TUser>` then implements `IUserRoleStore<TUser>`, `RoleManager<TRole>` resolves, and sign-in uses `UserClaimsPrincipalFactory<TUser, TRole>`. The context is `IdentityDbContext<TUser, TRole, TKey>` or the equivalent.

```cs
builder.Services.AddDbContext<AppDbContext>(/* your provider */);

builder.Services.AddAuthEndpoints<AppUser, AppDbContext>()
	.AddPassword()
	.AddPasskeys(p => p.ServerDomain = "example.com"); // omit to leave passkeys off

builder.Services.AddTransient<IEmailSender<AppUser>, MyEmailSender>();

var app = builder.Build();

app.UseAuthEndpoints();
app.MapAuthEndpoints<AppUser>("/auth", AuthEndpointsSession.Cookie);
```

| Builder method | Adds |
| --- | --- |
| `AddPassword(p => ...)` | Password sign-in. `SignUp` (default true) adds `POST /register`. `Recovery` (default true) adds forgot and reset password. |
| `AddPasskeys(p => ...)` | Passkey sign-in and passkey step-up. `ServerDomain` sets the relying party. `SignUp` (default true) adds anonymous passkey register. `Management` (default true) adds the signed-in passkey routes. |
| `AddEmailCode(o => ...)` | Email-code send and verify, and email-code step-up. Takes `EmailCodeOptions`. |
| `AddJwt(jwt => ...)` | The JWT session. Required before mapping `AuthEndpointsSession.Jwt`. |
| `AddIdentityBearer()` | The Identity bearer session. Required before mapping `AuthEndpointsSession.IdentityBearer`. |
| `ConfigureIdentity(i => ...)` | `IdentityOptions`, such as `SignIn.RequireConfirmedAccount` and password rules. |

`MapAuthEndpoints` without `AddAuthEndpoints` throws `Call AddAuthEndpoints before MapAuthEndpoints.` Mapping `Jwt` or `IdentityBearer` without the matching builder call throws and names it. It returns the route group, so `WithTags` and other conventions apply to every route.

A route that is missing was not added. Startup logs `Skipped {routes}: {reason}` at `Information` under the `AuthEndpoints.Routing` category, and the reason names the `Add*` call that maps it.

`UseAuthEndpoints` adds authentication, authorization, rate limiting, and antiforgery, in that order. Call it after exception-handling middleware. Enable HTTPS in Production yourself. A second call is a no-op.

Cookie login is `POST /auth/login` and returns an empty `200` plus `Set-Cookie: .AspNetCore.Identity.Application`.

Tutorial: [Quick start](https://authendpoints.harten.id/getting-started/quick-start). The building-block list is on [AddAuthEndpoints](https://authendpoints.harten.id/modules/add-auth-endpoints).

## Set options

`AddAuthEndpoints<TUser, TContext>(Action<AuthEndpointsOptions>?)` takes runtime settings. A later `Configure<AuthEndpointsOptions>` applies too.

| Property | Default | Meaning |
| --- | --- | --- |
| `EmailConfirmation.ConfirmEmailRedirectUri` | `null` | After `GET` confirm-email, redirect here. Absolute `https` (or `http` in Development), or a rooted path. Null keeps the plain-text response. |
| `EmailConfirmation.AllowedRedirectOrigins` | empty | Required when the redirect URI is absolute. A rooted path needs no entry. |
| `RequireEmailSenderInProduction` | `true` | Production requires a real `IEmailSender<TUser>`. Identity's no-op sender fails startup. Development skips that check. |

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
| Every `MapAuthEndpoints` route, its auth, CSRF, ReAuth, and rate limit | [references/routes.md](references/routes.md) |
| JWT session, refresh rotation, refresh transport, signing keys | [references/jwt.md](references/jwt.md) |
| Antiforgery token, header, the bearer-header skip rule, `BearerSchemes`, and `allowBearer: false` | [references/csrf.md](references/csrf.md) |
| Passkey routes, user ids, and completers | [references/passkeys.md](references/passkeys.md) |
| ReAuth step-up, `reauthToken`, `.RequireReauth()` | [references/reauth.md](references/reauth.md) |
| Email-code sign-in, magic link, email-code step-up | [references/email-code.md](references/email-code.md) |
| GitHub or Google sign-in, linking, unlinking | [references/external-oauth.md](references/external-oauth.md) |
| List and revoke signed-in sessions | [references/active-sessions.md](references/active-sessions.md) |
| Tell people from AI agents and API keys, `RequireDirectPerson()`, the any-caller scheme | [references/callers.md](references/callers.md) |
| More than one session, or a mix the builder does not cover | [references/composition.md](references/composition.md) |

To make this app an OAuth 2.0 authorization server for other apps, CLIs, or MCP clients, use the `authendpoints-openiddict` skill that ships in the `AuthEndpoints.OpenIddict` package.

## Check production

- Serve the API over HTTPS. `UseAuthEndpoints` leaves HTTPS to the host.
- Register a real `IEmailSender<TUser>`. `AddPassword` and `AddJwtEndpoints` register `LoggingAccountSecurityEmailSender<TUser>` when no `IAccountSecurityEmailSender<TUser>` is registered. That sender writes registration-attempt notices to the log.
- For email code, call `UseEmailCodes()`, register a real `IEmailCodeSender<TUser>` outside Development, and use `https` plus `AllowedOrigins` for an absolute magic-link URI in Production.
- Set `ServerDomain` on `AddPasskeys` when passkeys are on. Leave out `AddPasskeys` to keep them off.
- For JWT, call `UseRefreshToken()` and set a real issuer, audience, and signing key.

Page: [Prepare for production](https://authendpoints.harten.id/concepts/production).
