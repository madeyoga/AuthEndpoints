# AuthEndpoints.OpenIddict

An opt-in OAuth 2.0 and OpenID Connect authorization server for AuthEndpoints apps, built on [OpenIddict](https://documentation.openiddict.com/) 7.7. Other apps, CLIs, and tool clients (MCP clients, for example) sign users in through your app and receive access, refresh, and ID tokens.

The core `AuthEndpoints` package does not change and has no OpenIddict dependency. Install this package only in the app that issues tokens.

> **Preview.** This release covers OAuth 2.0 (authorization code + PKCE, refresh, revocation, metadata, and optional dynamic registration) and opt-in [OpenID Connect](#openid-connect-optional): ID tokens, `userinfo`, logout, and the `email`, `email_verified`, and `amr` claims. See [Limitations](#limitations).

## What you get

| Route | Served by | Notes |
| --- | --- | --- |
| `GET /connect/authorize` | this package | Validated by OpenIddict first, then stores a pending consent and redirects to your consent page. Signed-out users go to your login page. |
| `POST /connect/token` | OpenIddict | `authorization_code` and `refresh_token` grants. |
| `POST /connect/revoke` | OpenIddict | RFC 7009. Public clients send `client_id`. |
| `GET /.well-known/oauth-authorization-server` | OpenIddict | RFC 8414 metadata. Endpoint URLs come from `Issuer`, never from the request `Host`. |
| `GET /.well-known/jwks` | OpenIddict | The public signing keys. |
| `GET /.well-known/openid-configuration`, `GET\|POST /connect/userinfo`, `GET\|POST /connect/logout` | OpenIddict, this package | OpenID Connect. **Only with the `openid` scope.** See [OpenID Connect](#openid-connect-optional). |
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
- Every code exchange and refresh checks the approving user again. See [When the user changes](#when-the-user-changes).
- HTTPS is required. Token audiences (RFC 8707 resources) are validated, and each client needs a permission for each resource.
- The issuer, endpoint URLs, and audience come from configuration. The request `Host` header is never trusted.

## Setup

The default recipe is one registration call, one model call, and one map call, in the style of `AddPasswordAuth` / `MapPasswordAuth`. It turns on the authorization server (code + PKCE, refresh, revocation, metadata), the JSON consent API, and developer app management. Anonymous (dynamic) registration stays off. Everything else keeps the defaults above, and each optional part can be turned off.

### 1. Register the server

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

`AddOAuthServer` also registers the authorization and antiforgery services that the consent and developer app routes need. It returns `OAuthServerBuilder`, so `AddPrincipalFactory<T>()`, `AddDeveloperAppOwnerDisplay<T>()`, `BindConfiguration(…)`, and `.OpenIddict` work as before. Call it once, instead of `AddAuthEndpointsOpenIddict` (see [Without the recipe](#without-the-recipe)).

### 2. Add the tables

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

This adds the four OpenIddict tables (`OpenIddictApplications`, `OpenIddictAuthorizations`, `OpenIddictScopes`, `OpenIddictTokens`, with `ReferenceId` widened to 512 characters) an `OAuthRequests` table for pending consents, and an `OAuthDeveloperApps` table for [developer apps](#developer-apps), each with a cascading foreign key to the user. Then add a migration:

```bash
dotnet ef migrations add OAuthServer
```

Pass `userForeignKey: false` when the users table is in a different DbContext.

### 3. Map the routes

```csharp
app.UseAuthEndpoints(); // or UseAuthentication, UseAuthorization, UseAntiforgery

app.MapOAuthServer();

// After migrations, when options.Clients lists clients:
await app.Services.SeedOAuthClientsAsync();
app.Run();
```

`MapOAuthServer` maps `/connect/authorize`, the consent API under `/oauth`, and the developer app API under `/oauth/apps`, plus `/connect/register` and `/.well-known/oauth-protected-resource` when they are enabled in the options, and `/connect/userinfo` and `/connect/logout` when `openid` is in `Scopes`. OpenIddict serves the token, revocation, metadata, and key set endpoints itself. `MapOAuthServer` checks the settings, and that `UseAuthEndpointsOpenIddict<TUser>()` is in the model, when it runs, so a missing setting or a forgotten model call fails at startup instead of on the first request. The model check builds the EF model only; it does not connect to the database.

The recipe does not seed `options.Clients`. Seeding writes to the database, so it has to run after the schema exists, and only your app knows when that is (`Migrate()` at startup, a migration job, or `EnsureCreated` in tests). Call `SeedOAuthClientsAsync()` at that point. It creates a missing client and updates an existing one.

#### Turning parts off

```csharp
var oauth = app.MapOAuthServer(parts =>
{
    parts.ConsentApi = false;                       // approve through IOAuthConsentService from your own routes
    parts.DeveloperAppsPrefix = "/developers/apps"; // keep developer apps, under another path
    // parts.DeveloperApps = false;                 // or no developer console API at all
});
oauth.DeveloperApps!.RequireRateLimiting("developer-apps"); // the mapped groups take conventions
```

| Part | Default | Where |
| --- | --- | --- |
| Authorization server (authorize, token, revocation, metadata) | on | Always mapped. |
| OpenID Connect (`userinfo`, logout, discovery) | **off** | Add `openid` to `options.Scopes`. |
| Consent API | on, `/oauth` | `parts.ConsentApi`, `parts.ConsentPrefix` |
| Developer apps | on, `/oauth/apps` | `parts.DeveloperApps`, `parts.DeveloperAppsPrefix`. Approval and limits: `options.DeveloperApps`. |
| Anonymous registration (RFC 7591) | **off** | `options.DynamicRegistration.Enabled` |
| Protected resource metadata (RFC 9728) | **off** | `options.ProtectedResource.Enabled` |

Anonymous registration and protected resource metadata are server settings, not route switches, because they also change what the metadata advertises. With developer apps on, any signed-in user can register up to `DeveloperApps.MaxAppsPerUser` (10) clients. Set `options.DeveloperApps.RequireApproval = true` to review them first, or turn the part off.

`MapOAuthServer` returns the consent and developer app groups (`null` when off). Turning off the consent API does not turn off consent: `/connect/authorize` still sends users to `ConsentUrl`, and your page approves through `IOAuthConsentService` ([option B](#option-b-your-own-approve-endpoint)).

#### Without the recipe

The recipe is a shortcut for these calls, which stay public for hosts that want them one by one:

```csharp
builder.Services.AddAuthorization();
builder.Services.AddAntiforgery();
builder.Services.AddAuthEndpointsOpenIddict<AppUser, AppDbContext>(options => { … });

app.MapAuthEndpointsOpenIddict();        // authorize, plus registration and resource metadata when enabled
app.MapOAuthConsentEndpoints();          // optional JSON consent API
app.MapOAuthDeveloperAppEndpoints();     // optional developer console API
await app.Services.SeedOAuthClientsAsync();
```

Use one or the other. Mapping `MapOAuthServer` and also `MapOAuthConsentEndpoints` maps the same routes twice.

There is no sample host or template yet. The login, consent, and developer console pages are your app's UI, and this package only provides their JSON APIs.

### 4. Protect your API with the issued tokens

The package registers OpenIddict validation for this host. By default it accepts only tokens whose audience is `Audience`.

```csharp
builder.Services.AddAuthorization(options => options.AddPolicy("api", policy => policy
    .AddAuthenticationSchemes(OAuthServerServiceCollectionExtensions.ValidationScheme)
    .RequireAuthenticatedUser()));

app.MapGet("/api/me", (ClaimsPrincipal user) => user.FindFirst("sub")?.Value)
    .RequireAuthorization("api");
```

Access tokens are reference tokens, validated against this server's database. APIs in other processes are not supported yet (that needs introspection or JWT access tokens, see [Limitations](#limitations)).

#### One host, more than one resource

A token's audience is the resource the client asked for at `/connect/authorize` (one per request), or `Audience` when it sent none. To let this host accept tokens for some of its `AdditionalResources` too, list them in `AcceptedAudiences`. Each entry must be `Audience` or in `AdditionalResources`, or startup fails. Resources left out of `AcceptedAudiences` stay rejected here, so keep resources that only other APIs serve in `AdditionalResources` alone.

Once `AcceptedAudiences` has entries, `ValidationScheme` lets a token for any accepted audience through, and a policy that only requires an authenticated user no longer tells them apart. Check the audience on each route. `RequireOAuthAudience` authenticates with `ValidationScheme` and requires the token's `aud` to contain the given resource:

```csharp
builder.Services.AddOAuthServer<AppUser, AppDbContext>(options =>
{
    options.Audience = "https://auth.example.com/api";
    options.AdditionalResources.Add("https://auth.example.com/mcp");
    options.AcceptedAudiences.Add("https://auth.example.com/mcp");
    // ...
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("api", policy => policy.RequireOAuthAudience("https://auth.example.com/api"));
    options.AddPolicy("mcp", policy => policy.RequireOAuthAudience("https://auth.example.com/mcp"));
});

app.MapGroup("/api").RequireAuthorization("api");
app.MapGroup("/mcp").RequireAuthorization("mcp");
```

A token for `/mcp` then gets `403` from `/api`, and the other way round. Protected resource metadata still describes `Audience` only.

## Clients

### Clients from configuration

```json
{
  "OAuthServer": {
    "Clients": [
      {
        "ClientId": "my-cli",
        "DisplayName": "My CLI",
        "RedirectUris": [ "http://127.0.0.1:8765/callback" ],
        "Scopes": [ "api" ]
      }
    ]
  }
}
```

`SeedOAuthClientsAsync` creates each client or updates it in place. A client with no `ClientSecret` is public. A client with a secret is confidential; keep the secret in a secret store, not in `appsettings.json`. Empty `Scopes` or `Resources` means every configured one. Every client must use PKCE.

### Dynamic registration (optional)

```csharp
options.DynamicRegistration.Enabled = true;
options.DynamicRegistration.PermitsPerMinute = 10; // per client IP
options.DynamicRegistration.AllowedScopes.Add("mcp"); // optional: scopes anyone may register for
```

`POST /connect/register` accepts only public clients (`token_endpoint_auth_method` `none`, no `client_secret`), the `authorization_code` and `refresh_token` grants, the `code` response type, and configured scopes. Each redirect URI must be `https`, or `http` on `localhost`, `127.0.0.1`, or `[::1]`, with no fragment and no user info. The rate limit runs inside the endpoint, so it works without `UseRateLimiter`. Behind a proxy, configure forwarded headers so the client IP is right.

By default a registered client may hold every configured scope. Anyone can register, so if a scope is meant only for your own clients (for example one that acts as the user's whole account), list the scopes registered clients may use in `AllowedScopes`. Each must be in `Scopes`; `offline_access` is always allowed, and `openid` must be listed for registered clients to use OpenID Connect. A registration asking for another scope is rejected with `invalid_client_metadata`, and `/connect/authorize` holds clients registered before the list was set to it too. Configured clients and developer apps are not affected.

A registered client that no user approved within `UnusedClientLifetime` (24 hours) is deleted by the background cleanup. Seeded clients are never deleted.

### Developer apps

Signed-in users register OAuth apps they own and get a client id (and, for a confidential app, a client secret), the way the GitHub and Google developer consoles work. `MapOAuthServer()` maps a JSON API for your developer console page (or `MapOAuthDeveloperAppEndpoints()` without the recipe; `parts.DeveloperApps = false` turns it off). Every route requires the signed-in user (`AuthenticationScheme`), and the writes require a CSRF token for cookie callers, as the consent API does.

| Route | |
| --- | --- |
| `GET /oauth/apps` | The caller's apps. |
| `POST /oauth/apps` | Register an app. `201` with `{ app, clientSecret }`. |
| `GET /oauth/apps/{id}` | One app. |
| `PUT /oauth/apps/{id}` | Edit the name, homepage, description, and redirect URIs. |
| `DELETE /oauth/apps/{id}` | Delete the app and every authorization and token issued to it. |
| `POST /oauth/apps/{id}/secret` | Confidential apps only: replace the secret. `{ app, clientSecret }`. The old secret stops working at once. |

```json
{
  "name": "My dashboard",
  "homepageUrl": "https://dashboard.example.com",
  "description": "Optional",
  "redirectUris": [ "https://dashboard.example.com/oauth/callback" ],
  "confidential": true
}
```

There is no SPA, native, or web type to pick. The only choice is whether the app can keep a secret:

- **Confidential** (`"confidential": true`, for server-side apps): a client secret is generated and returned once, with `Cache-Control: no-store`. Only its hash is stored. The app authenticates at the token endpoint with `client_secret_basic` or `client_secret_post`, and still uses PKCE.
- **Public** (the default, for SPAs, desktop and mobile apps, and CLIs): no secret, PKCE only.

`confidential` is fixed at creation and ignored on edit. Each redirect URI is checked on its own:

| Redirect URI | Public | Confidential |
| --- | --- | --- |
| `https://…` | yes | yes |
| `http://localhost`, `http://127.0.0.1`, `http://[::1]` | yes | yes |
| A reverse-domain private-use scheme (RFC 8252 §7.1), for example `com.example.app:/callback` | yes | no |
| `http://` on any other host, single-word schemes (`myapp:`, `javascript:`, `data:`, `file:`), a fragment, or user info | no | no |

Loopback IP redirects may use any port. See [Redirect URIs](#redirect-uris).

Settings, under `options.DeveloperApps`:

| Option | Default | |
| --- | --- | --- |
| `RequireApproval` | `false` | New apps start as `PendingApproval` and cannot sign anyone in until an admin approves them. |
| `MaxAppsPerUser` | 10 | A user at the limit gets `409`. |
| `MaxRedirectUris` | 10 | |

Admin review is in `IOAuthDeveloperAppService`, not in the mapped API, because only your app knows who an admin is. `ListByStatusAsync(OAuthDeveloperAppStatus.PendingApproval)` returns the review queue, and `SetStatusAsync` approves (`Active`) or turns an app off (`Disabled`). Setting any status other than `Active` through `SetStatusAsync` revokes the app's authorizations and tokens. The authorize endpoint answers `unauthorized_client` for an app that is not active, and so does the token endpoint for a code or refresh token issued before the change. Protect your admin endpoints yourself.

With `RequireApproval`, an edit that changes an active app's name or redirect URIs sends it back to `PendingApproval`, so an owner cannot swap in a new redirect or a misleading name after approval. Until an admin approves it again, new sign-ins and token refreshes get `unauthorized_client`. Existing grants are not revoked, so they work again once the app is approved. Access tokens that were already issued keep working until they expire. Homepage and description edits do not need review, and editing a disabled app leaves it disabled.

The owner methods of the same service (`ListAsync`, `CreateAsync`, `UpdateAsync`, …) take the caller's user id, for hosts that want their own routes.

When an owner's account is deleted, the cascade removes the app's row. From then on, the authorize and token endpoints refuse its client, and the next cleanup pass deletes it. Developer apps are never treated as unused dynamic registrations.

Developer apps and [dynamic registration](#dynamic-registration-optional) are separate. Anonymous registration stays the path for native apps and CLIs that register themselves. Developer apps are for people building an integration with your service. On the user side, `IOAuthConsentService.RevokeAuthorizationAsync` still disconnects one app from one account.

### Redirect URIs

An authorize request's `redirect_uri` must match one of the client's registered redirect URIs exactly, with one exception from RFC 8252 §7.3: on a loopback IP literal, `http://127.0.0.1` or `http://[::1]`, the port may differ. A native app or CLI can register `http://127.0.0.1/callback` and listen on whatever port is free. The scheme, host, path, and query must still match, so `http://127.0.0.1:51234/callback` matches a registered `http://127.0.0.1:9/callback`, but `/other`, `127.0.0.2`, or `[::1]` do not. This applies to every client: from configuration, dynamic registration, or developer apps.

`localhost` is matched exactly, port included. RFC 8252 §8.3 recommends the IP literals over `localhost`, so register `http://127.0.0.1/…` for a native app. The token request must repeat the `redirect_uri` sent at authorize, port included.

## The consent step

The authorize endpoint never shows a page. When the user is signed in, it stores a pending request and redirects to:

```
{ConsentUrl}?request={id}
```

When the user is signed out, it redirects to:

```
{LoginUrl}?returnUrl=/connect/authorize?client_id=…
```

`returnUrl` is a path on this server, rebuilt from the incoming request. After sign-in, send the browser there (prefix it with the server's origin if your login page is on another origin) and the flow resumes. The user is read from `AuthenticationScheme` (default: the Identity application cookie), so bearer-only apps need the cookie enabled for this step. `prompt=none` returns `login_required` or `consent_required` to the client instead of a page.

### Option A: the built-in JSON consent API

`MapOAuthServer()` maps (or `MapOAuthConsentEndpoints("/oauth")` without the recipe), for the signed-in user:

| Route | Response |
| --- | --- |
| `GET /oauth/requests/{id}` | `{ id, clientId, clientName, redirectHost, scopes, resource, expiresAt, homepageUrl, description, confidential, owner }` |
| `POST /oauth/requests/{id}/approve` | `{ redirectUrl }` with `code`, `state`, and `iss` |
| `POST /oauth/requests/{id}/deny` | `{ redirectUrl }` with `error=access_denied` |

The POSTs require a CSRF token for cookie callers (the same filter as other AuthEndpoints cookie routes). Unknown, expired, used, and other users' requests are all `404`. Your consent page shows `clientName` and `redirectHost`, then sends the browser to `redirectUrl`.

The client is checked again when the user answers, because it can be deleted or edited, or a developer app disabled or sent back to review, after `/connect/authorize` stored the request. A request whose client no longer exists, whose developer app is not `Active`, or whose redirect URI is no longer registered for the client (with the same loopback any-port rule as authorize), is also `404` on all three routes (`OAuthConsentStatus.NotFound` from `IOAuthConsentService`). No code is issued, and deny does not redirect to that client. Approve and deny consume the request, so re-enabling the app does not revive it; the user starts a new authorize request. The card fetch does not consume it.

#### Developer app details on the card

When the client is a [developer app](#developer-apps), the card also tells the user what they are approving, since another user built it:

| Field | Value |
| --- | --- |
| `homepageUrl` | The app's homepage. |
| `description` | The app's description, or `null` when it has none. |
| `confidential` | `true` for an app with a client secret (a server-side app), `false` for a public app (SPA, native, CLI). |
| `owner` | Who built the app, from your `IOAuthDeveloperAppOwnerDisplay`. `null` unless you register one. |

For seeded and dynamically registered clients all four are `null`. `OAuthPendingRequest` (from `IOAuthConsentService.FindAsync`, and `OAuthPrincipalContext.Request` on approve) has the same fields.

`clientName` is copied when `/connect/authorize` runs, as before. The other fields are read from the app when the card is fetched, in the same query as the request, so an owner's homepage or description edit shows up on a pending card.

The owner's email and user name may be private, so the package never shows them. To show something, such as a developer or organization name the owner chose to make public, register a display:

```csharp
builder.Services.AddOAuthServer<AppUser, AppDbContext>(options => { … })
    .AddDeveloperAppOwnerDisplay<DeveloperProfileOwnerDisplay>();

public sealed class DeveloperProfileOwnerDisplay(AppDbContext db) : IOAuthDeveloperAppOwnerDisplay
{
    public async ValueTask<string?> GetOwnerAsync(OAuthDeveloperAppOwnerContext context, CancellationToken ct)
        => await db.DeveloperProfiles
            .Where(profile => profile.UserId == context.OwnerId && profile.Public)
            .Select(profile => profile.DisplayName)
            .FirstOrDefaultAsync(ct);
}
```

It is called once per card fetch for a developer app, with the app id, client id, and owner id. `null` or blank text shows `owner: null`.

### Option B: your own approve endpoint

When the consent page has extra choices, call `IOAuthConsentService` from your own endpoint:

```csharp
app.MapPost("/api/oauth/requests/{id:guid}/approve", async (
    Guid id, ApproveBody body, ClaimsPrincipal user, IOAuthConsentService consent, AppDbContext db) =>
{
    var userId = user.FindFirstValue(ClaimTypes.NameIdentifier)!;
    await using var transaction = await db.Database.BeginTransactionAsync();
    var result = await consent.ApproveAsync(id, userId, async context =>
    {
        var agent = await db.Agents.FindAsync(body.AgentId);
        if (agent?.OwnerId != userId)
        {
            return null; // declined: the request is not consumed
        }

        return OAuthPrincipals.ForSubject(agent.Id.ToString());
    });

    if (result.Status != OAuthConsentStatus.Approved)
    {
        return Results.NotFound();
    }

    db.Grants.Add(new Grant { UserId = userId, AuthorizationId = result.AuthorizationId! });
    await db.SaveChangesAsync();
    await transaction.CommitAsync();
    return Results.Ok(new { redirectUrl = result.RedirectUrl });
}).RequireAuthorization().RequireAntiforgery();
```

The service uses the scoped DbContext, so your transaction also covers the OpenIddict rows. Keep `RevokeAuthorizationAsync(authorizationId)` for a "disconnect app" button: it revokes the authorization and every token from it.

### Who is the token subject

By default `sub` is the Identity user id. Replace it for every approval:

```csharp
builder.Services.AddOAuthServer<AppUser, AppDbContext>(…)
    .AddPrincipalFactory<MyPrincipalFactory>();
```

`IOAuthPrincipalFactory.CreateAsync` gets the signed-in user id and the pending request, and returns the principal (or `null` to decline without consuming the request). The principal needs a `sub` claim. Other claims reach the access token only when you call `SetDestinations` on them.

With OpenID Connect, the ID token `sub` is the same `sub`, so a custom factory changes both. See [Claims](#claims).

## When the user changes

Each grant remembers the user who approved it and that user's security stamp. On every code exchange and refresh, the server checks that the user still exists, can sign in (`SignInManager.CanSignInAsync`), is not locked out, and has the same security stamp. If any check fails, the request gets `invalid_grant`, and the authorization and all its tokens are revoked.

Identity changes the security stamp when the password changes or is reset, an authenticator is reset, two-factor is turned off, or an external login is removed. Call `UserManager.UpdateSecurityStampAsync(user)` to end every OAuth grant for a user on demand, for example from a "sign out everywhere" button.

The check happens at the token endpoint, so an access token that was already issued keeps working until it expires (15 minutes by default) or until the client next refreshes. To stop it sooner, call `IOAuthConsentService.RevokeAuthorizationAsync`.

The approving user's id and stamp are stored in the code and refresh token only. They are never copied into access tokens or ID tokens, even when a principal factory sends every claim to the access token. With OpenID Connect, the user id is also kept on the authorization in the database, so `userinfo` and logout can find the user. Replace `IOAuthUserValidator` to apply your own rules, or set `RevalidateUser = false` to turn the check off.

## OpenID Connect (optional)

Add the `openid` scope to turn on OpenID Connect. Without it, the server stays OAuth 2.0 only: `openid` is rejected and the routes below do not exist.

```csharp
options.Scopes.Add("openid");
options.Scopes.Add("email");                            // optional: releases email and email_verified
options.LogoutUrl = "https://app.example.com/sign-out"; // optional: see Logout
```

`OAuthRequests` has two nullable columns for OpenID Connect, `Nonce` and `AuthenticationMethods`. If you created the tables from an earlier build of this package, add a migration, whether or not you turn OpenID Connect on.

| Route | Served by | Notes |
| --- | --- | --- |
| `GET /.well-known/openid-configuration` | OpenIddict | Discovery. The same document as the RFC 8414 metadata, with endpoint URLs from `Issuer`, never from the request `Host`. |
| `GET\|POST /connect/userinfo` | this package | `sub`, plus the email claims with the `email` scope. |
| `GET\|POST /connect/logout` | this package | RP-initiated logout. |
| `GET /.well-known/jwks` | OpenIddict | The keys that validate ID tokens. |

A request with `openid` gets an `id_token` from the token endpoint, on the code exchange and on every refresh. It is a JWT signed with the signing certificate (RS256). It lasts 20 minutes, OpenIddict's default; change it with `builder.OpenIddict.AddServer(o => o.SetIdentityTokenLifetime(…))`.

### Claims

| Claim | In | Value |
| --- | --- | --- |
| `iss` | ID token | `Issuer`. |
| `aud`, `azp` | ID token | The client id. |
| `sub` | ID token, `userinfo`, access token | From `IOAuthPrincipalFactory`: the Identity user id by default. |
| `nonce` | ID token | The authorize request's `nonce`, when it sent one. At most 512 characters. |
| `amr` | ID token | How the user signed in. See [How the user signed in](#how-the-user-signed-in). Left out when unknown. |
| `email`, `email_verified` | ID token, `userinfo` | With the `email` scope only. `email_verified` is the user's `EmailConfirmed`. |

These claims never reach access tokens. An access token still carries `sub`, plus what your principal factory sends to it.

The email claims come from the Identity user only when `sub` is that user's id. A principal factory that issues tokens for another subject (a service account the user picked, say) does not get the approving user's email attached to it. A claim the factory already set is kept as it is.

ID token claims are read when the user approves, and a refreshed ID token repeats them. `userinfo` reads the user on every call.

### How the user signed in

| Sign-in | `amr` |
| --- | --- |
| Password | `["pwd"]` |
| Password, then an authenticator or recovery code | `["pwd", "otp", "mfa"]` |
| Passkey, when Identity requires user verification (the .NET default) | `["pop", "mfa"]` |
| Passkey, when it does not | `["pop"]` |
| External provider (GitHub, Google, …) | `["fed"]` |
| Email code | `["otp"]` |

The values are from RFC 8176, except `fed`: RFC 8176 has none for a federated sign-in, and `fed` is the value Microsoft Entra ID uses. A recovery code counts as a one-time code, like an authenticator code. A passkey is `mfa` only when `IdentityPasskeyOptions.UserVerificationRequirement` is `required`: Identity then rejects any passkey sign-in where the authenticator did not check a PIN or biometric, so the key and that check are two factors. With `preferred` or `discouraged`, the check may not have happened, so a passkey is `pop` alone.

`amr` is read from the sign-in cookie when `/connect/authorize` runs. AuthEndpoints password sign-in already writes `amr` to the cookie (`pwd`, or `mfa` after a second factor), and so do Identity's `PasswordSignInAsync` and `TwoFactorSignInAsync`. Passkey, external, and email-code sign-in write nothing, so with `openid` on, this package wraps the sign-in completers and adds `amr` to the cookie they write. That covers the built-in `Cookie` and `IdentityBearer` completers, every `ISignInCompleter<TUser>` you register before `AddOAuthServer` under any name, and your own obsolete `IPasskeySignInCompleter`, `IEmailCodeSignInCompleter`, or `IExternalLoginCompleter`. The built-in obsolete completers are left as they are, because AuthEndpoints only routes to an obsolete completer that is not the built-in type. It also keeps `amr` when Identity's security stamp check rebuilds the cookie, which otherwise drops it.

`amr` is left out when the cookie does not say: a session signed in before `openid` was turned on (it gets `amr` at its next sign-in), a completer registered after `AddOAuthServer`, or a plain `SignInManager.SignInAsync` outside a completer. `MapOAuthServer` logs a warning that names every completer registered too late. To supply `amr` yourself, add an `amr` claim to the cookie principal when you sign the user in.

### userinfo

`GET` or `POST /connect/userinfo` with an access token that has the `openid` scope returns `sub`, and with the `email` scope also `email` and `email_verified`. A token without `openid` gets `403` with `insufficient_scope`. A token whose user was deleted gets `401` with `invalid_token` when it asks for the email claims.

### Logout

`GET` or `POST /connect/logout` follows OpenID Connect RP-Initiated Logout 1.0 (`id_token_hint`, `client_id`, `post_logout_redirect_uri`, `state`):

- `post_logout_redirect_uri` must exactly match a post-logout redirect URI registered for the client that `client_id` or `id_token_hint` names. Without either, or with any other URI, the request gets `400` and the browser is not redirected. A disabled or unapproved developer app gets `400` too.
- A signed-in user is signed out (the Identity application, external, and two-factor cookies) only when `id_token_hint` is an ID token that this server issued to that user. Otherwise the user stays signed in. When `LogoutUrl` is set, the browser goes there with the logout URL in `returnUrl`; your page asks the user, signs them out, and sends the browser back to `returnUrl`, which then completes. Without `LogoutUrl`, the request gets `400`. A link on another site cannot sign your users out.
- A signed-out browser goes straight to the validated `post_logout_redirect_uri`, with `state`. With no `post_logout_redirect_uri`, the endpoint answers `200` with no body.

Each client registers its own post-logout redirect URIs:

| Client | Where |
| --- | --- |
| From configuration | `PostLogoutRedirectUris` on the entry in `options.Clients`. |
| Dynamic registration | `post_logout_redirect_uris`, under the same rules as `redirect_uris`. |
| Developer apps | `postLogoutRedirectUris` in the create and edit body, under the same rules as `redirectUris`, and returned with the app. Leave it out of an edit to keep the list. With `RequireApproval`, a change sends an active app back to review. |

### Client permissions

A client gets the `openid` scope and the logout endpoint permission when `openid` is among its scopes: every configured scope by default, or the `Scopes` of a configured client. Unlike plain OpenIddict, `openid` needs that permission here, so a configured client whose `Scopes` leave it out cannot use OpenID Connect. Clients that existed before you added `openid` get the permissions at the next `SeedOAuthClientsAsync` (configured clients) or the next edit (developer apps). A dynamically registered client keeps the permissions it registered with, so it registers again.

`prompt=login` and `max_age` are refused with `invalid_request` instead of being ignored, because the server does not record when the user signed in.

## Certificates

Set exactly one source in `options.Certificates`:

| Setting | Use it for |
| --- | --- |
| `Path` | A self-signed RSA signing and encryption pair, created on first start in that directory and reused. Treat the directory like Data Protection keys: persistent, private, and shared by every instance. Files are created with owner-only permissions on Linux and macOS. |
| `SigningCertificate` + `EncryptionCertificate` | Certificates you manage (Key Vault, a mounted secret, the machine store). Both need a private key. |
| `UseEphemeralKeys` | Tests and local runs only. Keys are lost on restart, which invalidates every issued token. |

To rotate, add the new certificates through `builder.OpenIddict.AddServer(o => o.AddSigningCertificate(…))` before removing the old ones, so tokens signed with the old key still validate until they expire.

## Protected resource metadata (optional)

For APIs whose clients discover the authorization server on their own (MCP clients, for example):

```csharp
options.ProtectedResource.Enabled = true;
options.ProtectedResource.ResourceName = "My API";
options.ProtectedResource.ChallengePaths.Add("/mcp");

app.UseOAuthResourceChallenge(); // before UseAuthentication
```

`GET /.well-known/oauth-protected-resource` returns `Audience`, the issuer, and the scopes. A `401` on a challenge path gets `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource"`. Existing `Bearer` parameters are kept.

## Settings

| Option | Default | |
| --- | --- | --- |
| `Issuer` | required | Absolute; `https` unless `DisableTransportSecurityRequirement`. Use the app root (`https://host/`), or the app's `PathBase`. |
| `Audience` | required | Default resource. This host always accepts it. |
| `AdditionalResources` | empty | Other resources clients may request. Rejected by this host unless also in `AcceptedAudiences`. |
| `AcceptedAudiences` | empty | Resources (`Audience` or `AdditionalResources` entries) this host's validation also accepts. Check `aud` per route, see [One host, more than one resource](#one-host-more-than-one-resource). |
| `Scopes` / `DefaultScopes` | empty | `offline_access` is always registered. Add `openid` for [OpenID Connect](#openid-connect-optional), and `email` for the email claims. |
| `AlwaysIssueRefreshToken` | `true` | Adds `offline_access` when the client has the refresh grant. |
| `LoginUrl`, `LoginReturnUrlParameter` | required, `returnUrl` | |
| `ConsentUrl`, `ConsentRequestParameter` | required, `request` | |
| `LogoutUrl` | none | OpenID Connect only. The sign-out page for a [logout](#logout) without a matching `id_token_hint`. Gets the logout URL in `LoginReturnUrlParameter`. |
| `AuthenticationScheme`, `UserIdClaimType` | Identity cookie, `NameIdentifier` | |
| `AccessTokenLifetime` | 15 minutes | |
| `RefreshTokenLifetime` | 30 days | Rotating, no reuse leeway. |
| `AuthorizationCodeLifetime` | 5 minutes | |
| `ConsentLifetime` | 10 minutes | |
| `DeveloperApps` | approval off, 10 apps, 10 redirects | See [Developer apps](#developer-apps). |
| `CleanupInterval`, `PruneAfter` | 1 hour, 14 days | Background sweep of unused clients, developer apps without an owner, expired consents, old tokens. Zero turns it off; `IOAuthServerCleanup.SweepAsync` runs it on demand. |
| `RevalidateUser` | `true` | Re-check the approving user on every code exchange and refresh. |
| `DisableTransportSecurityRequirement` | `false` | Local development only. |
| `DisableResourceValidation` | `false` | Token endpoint only. Authorize still accepts configured resources only. |
| `IgnoreResourcePermissions` | `false` | Skips per-client `rsrc:` permissions. |

The fixed routes are in `OAuthServerConstants`. Anything else can be set on `OAuthServerBuilder.OpenIddict`.

## How this relates to external sign-in

External providers (`AuthEndpoints.OAuth.GitHub`, `AuthEndpoints.OAuth.Google`) let users sign in to **your** app with another account. This package makes **your** app the provider for other clients. They combine: with cookie-mode external sign-in, a user who signs in with GitHub has an Identity cookie, and the authorize step accepts it like any other sign-in. JWT-mode sign-in does not set that cookie.

## Limitations

This is a preview. These are known gaps, not bugs:

- **OpenID Connect covers sign-in and logout, not every option.** The claims are `sub`, `email`, `email_verified`, and `amr`; there are no `profile`, `phone`, or `address` claims, and no `auth_time`, so `prompt=login` and `max_age` are refused. Logout is RP-initiated only: there is no front-channel or back-channel logout and no session (`sid`) claim. There is no implicit or hybrid flow, so ID tokens come from the token endpoint only.
- **`amr` depends on the cookie.** A session signed in before `openid` was turned on has no `amr` until the user signs in again, and neither does a sign-in through a completer registered after `AddOAuthServer`. See [How the user signed in](#how-the-user-signed-in).
- **Only this server validates tokens.** Access tokens are reference tokens, so an API in another process cannot validate them. There is no introspection endpoint and no JWT access token option yet.
- **Issued access tokens outlive a user change.** A locked-out user or a changed password stops the grant at the next code exchange or refresh. An access token that was already issued works until it expires. See [When the user changes](#when-the-user-changes).
- **Fixed routes.** The endpoints are always under `/connect` and `/.well-known` (see `OAuthServerConstants`), relative to the app's `PathBase`.
- **Cookie sign-in only at the authorize step.** The user is read from `AuthenticationScheme` (the Identity cookie by default). Password, two-factor, passkey, and cookie-mode external sign-in all end with that cookie. A sign-in that is still waiting for a second factor, or an external sign-in that has not been completed, does not count.

An OIDC client for AuthEndpoints (the other direction) is tracked separately in issue #380.
