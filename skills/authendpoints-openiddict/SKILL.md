---
name: authendpoints-openiddict
description: "Turn an AuthEndpoints app into an OAuth 2.0 and OpenID Connect provider with AuthEndpoints.OpenIddict (preview). AddOAuthServer, UseAuthEndpointsOpenIddict, MapOAuthServer, and SeedOAuthClientsAsync set up authorization code + PKCE, rotating refresh tokens, revocation, metadata, a host-rendered consent step, developer apps, and optional dynamic registration and protected resource metadata for MCP clients. The openid scope turns on ID tokens, userinfo, logout, and the email, email_verified, and amr claims. Use when the project references AuthEndpoints.OpenIddict, or the task is letting other apps, CLIs, or MCP clients sign users in through this app and get access or ID tokens. Not for signing in to this app with GitHub, Google, or another OpenID provider (use the authendpoints skill). Read this skill instead of decompiling the assembly or web-searching the API."
license: MIT
metadata:
  version: "4.0.0-preview.1"
---
# Run an OAuth server with AuthEndpoints.OpenIddict

Use this skill when the app issues OAuth 2.0 or OpenID Connect tokens to other clients through the `AuthEndpoints.OpenIddict` package. The app signs users in with AuthEndpoints first; for that part, use the `authendpoints` skill that ships in the `AuthEndpoints` package.

Use the symbols, routes, and option names on this page and in `references/`. Do not decompile the assembly, and do not copy OpenIddict samples that call `AddOpenIddict()` directly; this package registers OpenIddict for you. For anything not covered here, read the package [README](https://github.com/madeyoga/AuthEndpoints/tree/main/src/AuthEndpoints.OpenIddict#readme).

This skill ships inside the `AuthEndpoints.OpenIddict` package, so the copy under `~/.nuget/packages/authendpoints.openiddict/<version>/skills/authendpoints-openiddict/` matches the API of that version.

The package is a preview built on OpenIddict 7.7 and depends on `AuthEndpoints` 4.x. The core `AuthEndpoints` package has no OpenIddict dependency. Install this package only in the app that issues tokens.

## Know the routes

| Route | Served by | Notes |
| --- | --- | --- |
| `GET /connect/authorize` | this package | Validated by OpenIddict first, then stores a pending consent and redirects to your consent page. Signed-out users go to your login page. |
| `POST /connect/token` | OpenIddict | `authorization_code` and `refresh_token` grants. |
| `POST /connect/revoke` | OpenIddict | RFC 7009. Public clients send `client_id`. |
| `GET /.well-known/oauth-authorization-server` | OpenIddict | RFC 8414 metadata. Endpoint URLs come from `Issuer`, never from the request `Host`. |
| `GET /.well-known/jwks` | OpenIddict | The public signing keys. |
| `GET /.well-known/openid-configuration`, `GET\|POST /connect/userinfo`, `GET\|POST /connect/logout` | OpenIddict, this package | OpenID Connect. **Only with the `openid` scope.** See [references/openid-connect.md](references/openid-connect.md). |
| `POST /connect/register` | this package | RFC 7591. **Off by default.** |
| `GET /.well-known/oauth-protected-resource` | this package | RFC 9728. **Off by default.** |
| `GET /oauth/requests/{id}`, `POST …/approve`, `POST …/deny` | this package | JSON consent API. Mapped by `MapOAuthServer` unless turned off. |
| `GET\|POST /oauth/apps`, `GET\|PUT\|DELETE /oauth/apps/{id}`, `POST …/secret` | this package | Developer console API. Mapped by `MapOAuthServer` unless turned off. |

Defaults:

- Authorization code flow only, with PKCE required and **S256 only** (`plain` is rejected).
- Reference access and refresh tokens, stored in your database, so revocation takes effect at once.
- Access tokens last 15 minutes. Refresh tokens last 30 days and rotate on every use, with **zero reuse leeway**.
- Authorization codes last 5 minutes. Consent requests last 10 minutes and work once.
- `ClockSkew` is zero for both issuing and validating.
- Every code exchange and refresh checks the approving user again. See [When the user changes](references/settings.md#when-the-user-changes).
- HTTPS is required. Token audiences (RFC 8707 resources) are validated, and each client needs a permission for each resource.
- The issuer, endpoint URLs, and audience come from configuration. The request `Host` header is never trusted.

## Register the server

```csharp
using AuthEndpoints.OpenIddict;

builder.Services.AddPasswordAuth<AppUser, AppDbContext>(); // or your existing AuthEndpoints setup

builder.Services.AddOAuthServer<AppUser, AppDbContext>(options =>
{
    options.Issuer = new Uri("https://auth.example.com/");
    options.Audience = "https://api.example.com/";
    options.Scopes.Add("api");
    options.DefaultScopes.Add("api");
    options.LoginUrl = "https://app.example.com/sign-in";
    options.ConsentUrl = "https://app.example.com/oauth/consent";
    options.Certificates.Path = "/var/lib/myapp/oauth-keys";
})
.BindConfiguration("OAuthServer"); // optional: appsettings values override the code above
```

`TUser` is your Identity user type and must derive from `IdentityUser<TKey>`, as everywhere else in AuthEndpoints. The key type (`string`, `Guid`, …) is read from it.

The app fails at startup when a required setting is missing: `Issuer`, `Audience`, `LoginUrl`, `ConsentUrl`, and exactly one certificate source. These are the settings only your app can decide. `Scopes` lists what clients may ask for.

`AddOAuthServer` also registers the authorization and antiforgery services that the consent and developer app routes need. It returns `OAuthServerBuilder`, so `AddPrincipalFactory<T>()`, `AddDeveloperAppOwnerDisplay<T>()`, `BindConfiguration(…)`, and `.OpenIddict` are available on the result. Call it once, instead of `AddAuthEndpointsOpenIddict` (see [Without the recipe](references/mapping.md#without-the-recipe)).

## Add the tables

```csharp
public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : IdentityDbContext<AppUser>(options)
{
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.UseAuthEndpointsOpenIddict<AppUser>();
    }
}
```

This adds the four OpenIddict tables (`OpenIddictApplications`, `OpenIddictAuthorizations`, `OpenIddictScopes`, `OpenIddictTokens`, with `ReferenceId` widened to 512 characters) an `OAuthRequests` table for pending consents, and an `OAuthDeveloperApps` table for [developer apps](references/developer-apps.md), each with a cascading foreign key to the user. Then add a migration:

```bash
dotnet ef migrations add OAuthServer
```

Pass `userForeignKey: false` when the users table is in a different DbContext.

## Map the routes

```csharp
app.UseAuthEndpoints(); // or UseAuthentication, UseAuthorization, UseAntiforgery

app.MapOAuthServer();

// After migrations, when options.Clients lists clients:
await app.Services.SeedOAuthClientsAsync();
app.Run();
```

`MapOAuthServer` maps `/connect/authorize`, the consent API under `/oauth`, and the developer app API under `/oauth/apps`, plus `/connect/register` and `/.well-known/oauth-protected-resource` when they are enabled in the options, and `/connect/userinfo` and `/connect/logout` when `openid` is in `Scopes`. OpenIddict serves the token, revocation, metadata, and key set endpoints itself. `MapOAuthServer` checks the settings, and that `UseAuthEndpointsOpenIddict<TUser>()` is in the model, when it runs, so a missing setting or a forgotten model call fails at startup instead of on the first request. The model check builds the EF model only; it does not connect to the database.

The recipe does not seed `options.Clients`. Seeding writes to the database, so it has to run after the schema exists, and only your app knows when that is (`Migrate()` at startup, a migration job, or `EnsureCreated` in tests). Call `SeedOAuthClientsAsync()` at that point. It creates a missing client and updates an existing one.

To turn off the consent API or developer apps, move their prefixes, or call the building blocks one by one, read [references/mapping.md](references/mapping.md).

## Protect your API with the issued tokens

The package registers OpenIddict validation for this host. By default it accepts only tokens whose audience is `Audience`.

```csharp
builder.Services.AddAuthorization(options => options.AddPolicy("api", policy => policy
    .AddAuthenticationSchemes(OAuthServerServiceCollectionExtensions.ValidationScheme)
    .RequireAuthenticatedUser()));

app.MapGet("/api/me", (ClaimsPrincipal user) => user.FindFirst("sub")?.Value)
    .RequireAuthorization("api");
```

Access tokens are reference tokens, validated against this server's database. APIs in other processes are not supported yet (that needs introspection or JWT access tokens, see [Limitations](#limitations)).

To accept tokens for more than one of this host's resources (for example `/api` and `/mcp`), and to keep each token on its own routes with `RequireOAuthAudience`, read [references/settings.md](references/settings.md#one-host-more-than-one-resource).

Only `Authorization: Bearer` is read. The query string and form body are not (a breaking change from earlier builds). For SignalR or WebSocket hubs, add their prefix to `QueryStringTokenPaths`; see [references/settings.md](references/settings.md#where-the-token-is-read-from).

## Read the reference for the task

Load only the file the task needs. Each one is self-contained.

| Task | File |
| --- | --- |
| Build the consent page, use the JSON consent API, approve from your own endpoint, or change the token subject | [references/consent.md](references/consent.md) |
| Seed clients from configuration, turn on dynamic registration, or match redirect URIs | [references/clients.md](references/clients.md) |
| Let signed-in users register their own OAuth apps, and review them | [references/developer-apps.md](references/developer-apps.md) |
| Turn mapped parts off, move prefixes, or skip the recipe | [references/mapping.md](references/mapping.md) |
| Turn on OpenID Connect: ID tokens, the `email`, `email_verified`, and `amr` claims, `userinfo`, logout, and post-logout redirect URIs | [references/openid-connect.md](references/openid-connect.md) |
| Every option, where access tokens are read from (SignalR hubs), certificates and key rotation, user revalidation, and protected resource metadata for MCP clients | [references/settings.md](references/settings.md) |

## Limitations

This is a preview. These are known gaps, not bugs. Do not promise these features to the user:

- **OpenID Connect covers sign-in and logout, not every option.** The claims are `sub`, `email`, `email_verified`, and `amr`; there are no `profile`, `phone`, or `address` claims, and no `auth_time`, so `prompt=login` and `max_age` are refused. Logout is RP-initiated only: there is no front-channel or back-channel logout and no session (`sid`) claim. There is no implicit or hybrid flow, so ID tokens come from the token endpoint only.
- **`amr` depends on the cookie.** A session signed in before `openid` was turned on has no `amr` until the user signs in again, and neither does a sign-in through a completer registered after `AddOAuthServer`. See [How the user signed in](references/openid-connect.md#how-the-user-signed-in).
- **Only this server validates tokens.** Access tokens are reference tokens, so an API in another process cannot validate them. There is no introspection endpoint and no JWT access token option yet.
- **Issued access tokens outlive a user change.** A locked-out user or a changed password stops the grant at the next code exchange or refresh. An access token that was already issued works until it expires. See [When the user changes](references/settings.md#when-the-user-changes).
- **Fixed routes.** The endpoints are always under `/connect` and `/.well-known` (see `OAuthServerConstants`), relative to the app's `PathBase`.
- **Cookie sign-in only at the authorize step.** The user is read from `AuthenticationScheme` (the Identity cookie by default). Password, two-factor, passkey, and cookie-mode external sign-in all end with that cookie. A sign-in that is still waiting for a second factor, or an external sign-in that has not been completed, does not count.

An OIDC client for AuthEndpoints (the other direction) is tracked separately in issue #380.
