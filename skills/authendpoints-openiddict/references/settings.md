# Settings, certificates, and user checks

## Settings

| Option | Default | |
| --- | --- | --- |
| `RequireApproval` | `false` | New apps start as `PendingApproval` and cannot sign anyone in until an admin approves them. |
| `MaxAppsPerUser` | 10 | A user at the limit gets `409`. |
| `MaxRedirectUris` | 10 | |

The fixed routes are in `OAuthServerConstants`. Anything else can be set on `OAuthServerBuilder.OpenIddict`.

## One host, more than one resource

A token's audience is the resource the client asked for at `/connect/authorize` (one per request), or `Audience` when it sent none. To let this host accept tokens for some of its `AdditionalResources` too, list them in `AcceptedAudiences`. Each entry must be `Audience` or in `AdditionalResources`, or startup fails. Resources left out of `AcceptedAudiences` stay rejected here, so keep resources that only other APIs serve in `AdditionalResources` alone.

Once `AcceptedAudiences` has entries, `AccessTokenScheme` lets a token for any accepted audience through, and a policy that only requires an authenticated user no longer tells them apart. Check the audience on each route. `RequireOAuthAudience` authenticates with `AccessTokenScheme` and requires the token's `aud` to contain the given resource:

```csharp
builder.Services.AddOAuthServer<AppUser>(options =>
{
    options.Audience = "https://auth.example.com/api";
    options.AdditionalResources.Add("https://auth.example.com/mcp");
    options.AcceptedAudiences.Add("https://auth.example.com/mcp");
    // ...
}).AddEntityFrameworkStores<AppDbContext>();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("api", policy => policy.RequireOAuthAudience("https://auth.example.com/api"));
    options.AddPolicy("mcp", policy => policy.RequireOAuthAudience("https://auth.example.com/mcp"));
});

app.MapGroup("/api").RequireAuthorization("api");
app.MapGroup("/mcp").RequireAuthorization("mcp");
```

A token for `/mcp` then gets `403` from `/api`, and the other way round. With protected resource metadata on, each accepted resource gets its own document; see [One document per resource](#one-document-per-resource).

## Roles and the user id on tokens

A validated access token has `sub` and the granted scopes, but no roles and no `ClaimTypes.NameIdentifier`, so `RequireRole` policies and `UserManager.GetUserId(User)` see a token caller as a user without either. Turn on `AccessTokenClaims` to add them:

```csharp
builder.Services.AddOAuthServer<AppUser>(options =>
{
    // ...
    options.AccessTokenClaims.Roles = true;  // the approving user's Identity roles, as `role` claims
    options.AccessTokenClaims.UserId = true; // ClaimTypes.NameIdentifier from sub
}).AddEntityFrameworkStores<AppDbContext>();

builder.Services.AddAuthorization(options => options.AddPolicy("reports", policy => policy
    .AddAuthenticationSchemes(OAuthServerConstants.AccessTokenScheme)
    .RequireRole("Reports")));
```

- `Roles` adds the approving user's Identity roles as `role` claims. That is the role claim type of the identity `AccessTokenScheme` creates, so `IsInRole`, `RequireRole`, and `[Authorize(Roles = "…")]` work. Code that reads `ClaimTypes.Role` claims directly does not see them. It needs Identity roles (`AddRoles<TRole>()`); without them, mapping the server fails at startup.
- `UserId` adds `ClaimTypes.NameIdentifier`, `UserIdClaimType`, and `IdentityOptions.ClaimsIdentity.UserIdClaimType`, each set to `sub`.
- Both are read at every code exchange and refresh, and written to the access token only, never to the code, the refresh token, or the ID token. A role change reaches the client at its next refresh. An access token that was already issued keeps its roles until it expires (15 minutes by default).
- Both apply only when `sub` is the approving user. A principal factory that issues tokens for another subject gets neither, because the user's roles would describe the wrong subject. A factory that keeps the user id as `sub` keeps its own claims, and the user's roles are added next to any role claims it sends to the access token.
- The security stamp and the grant's internal claims are never copied. Both options are off by default.

## Require scopes

A scope is what the person allowed the client to do for them. It narrows what the user's account may do and never widens it, so keep the role or policy check a route already has and add the scope next to it. `RequireOAuthScope` authenticates with `AccessTokenScheme` and requires every listed scope; a token missing one gets `403`:

```csharp
builder.Services.AddAuthorization(options =>
{
    // A route only OAuth clients call.
    options.AddPolicy("mcp", policy => policy
        .RequireOAuthAudience("https://auth.example.com/mcp")
        .RequireOAuthScope("mcp"));

    // A route that cookie users and OAuth clients share.
    options.AddPolicy("reports.read", policy => policy
        .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme, OAuthServerConstants.AccessTokenScheme)
        .RequireAuthenticatedUser() // and the route's existing role or policy check
        .RequireOAuthScopeWhenDelegated("reports.read"));
});
```

`RequireOAuthScopeWhenDelegated` adds only the scope check. A caller without an OAuth access token (cookie, Identity bearer, JWT) passes it, and a token caller needs every listed scope, even when the same request also carries a valid cookie. It adds no scheme, so list `AccessTokenScheme` in the policy, or the token is never read. Both helpers add an `OAuthScopeRequirement`, which you can also add to a policy you build by hand. A role check on a shared route sees a token caller's roles only with `AccessTokenClaims.Roles` on; see [Roles and the user id on tokens](#roles-and-the-user-id-on-tokens).

For code that authorizes inside a service instead of on the endpoint, such as an MCP tool handler, use the `ClaimsPrincipal` helpers:

```csharp
if (user.IsOAuthDelegated() && !user.HasOAuthScope("reports.read"))
{
    return Results.Forbid();
}
```

`IsOAuthDelegated()`, `GetOAuthScopes()`, and `HasOAuthScope(scope)` read only the identity built from the access token, so a cookie identity never contributes scopes. `HasOAuthScope` is `false` for a caller with no token, so check `IsOAuthDelegated()` first in code that cookie users reach too. The granted scopes include `offline_access` when the client got a refresh token.

## Where the token is read from

**Breaking change.** Earlier builds of this package also accepted the access token from the `access_token` query parameter and from an `access_token` form field, on every route. Now only `Authorization: Bearer` is read. A token in a URL ends up in server logs, proxy logs, and browser history, and a form field lets any HTML form send one.

The form body is never read. To accept `?access_token=` on chosen paths, list their prefixes in `QueryStringTokenPaths`. This is what SignalR and raw WebSocket hosts need, because a browser cannot set headers on a WebSocket or `EventSource` request:

```csharp
builder.Services.AddOAuthServer<AppUser>(options =>
{
    // ...
    options.QueryStringTokenPaths.Add("/hubs");
}).AddEntityFrameworkStores<AppDbContext>();

app.MapHub<ChatHub>("/hubs/chat").RequireAuthorization("api");
```

Prefixes match whole path segments: `/hubs` covers `/hubs`, `/hubs/chat`, and `/hubs/chat/negotiate`, but not `/hubsevil`. They are relative to `PathBase`, like routes. Each must start with `/` and must not end with one. On a listed path the `Authorization` header still wins when both are sent.

**Upgrading a SignalR host:** if a hub's clients pass the token with `accessTokenFactory` (JavaScript) or `AccessTokenProvider` (.NET), add the hub's path prefix to `QueryStringTokenPaths`. Without it, the WebSocket and Server-Sent Events transports get `401` after upgrading. Clients that send `Authorization: Bearer` and form posts that put the token in the header need no change.

### Token callers and cookie redirects

On a route that reads both the Identity cookie and an access token, a refused token caller used to get the cookie's answer. That meant a `302` to the login or access-denied page when the cookie challenged or forbade, for example from `Results.Forbid()` or `Results.Challenge()` with the default scheme, or a `403` that still carried the cookie's `Location` header. An OAuth client cannot follow either.

By default (`BearerRequestsSkipCookieRedirects = true`), a request that carries `Authorization: Bearer` gets `401` where the cookie would redirect to its login page, and `403` where it would redirect to its access-denied page. This applies to the Identity application cookie and to `AuthenticationScheme`. Requests without the header, such as browser navigation, are unchanged. Your own `OnRedirectToLogin` and `OnRedirectToAccessDenied` still run for them, and an `EventsType` you set is kept. To keep the cookie's redirects for every request:

```csharp
options.BearerRequestsSkipCookieRedirects = false;
```

### CSRF on routes that take a token

`AddAuthEndpointsOpenIddict` (and so `AddOAuthServer`) adds the validation scheme (`OAuthServerConstants.AccessTokenScheme`) to `AuthEndpointsAntiforgeryOptions.BearerSchemes`. A route that accepts both the cookie and an OAuth access token, mapped with `RequireAntiforgery()`, no longer asks the token caller for a CSRF token. A cross-site request cannot set `Authorization: Bearer`, and a request the application cookie authenticates is still checked. A token read from the query string on a `QueryStringTokenPaths` prefix does not skip the check, because it is not in the header.

Use `RequireAntiforgery(allowBearer: false)` on routes a token must never call on its own, such as your own consent approval or account deletion. The package's consent and developer app writes already do. To check every OAuth caller again, take the scheme back out after registering the server:

```csharp
builder.Services.PostConfigure<AuthEndpointsAntiforgeryOptions>(options =>
    options.BearerSchemes.Remove(OAuthServerConstants.AccessTokenScheme));
```

## Rate limits

OpenIddict serves `/connect/token` and `/connect/revoke` from its middleware, during `UseAuthentication`, so `RequireRateLimiting` cannot reach them. Turn on the built-in limit instead:

```csharp
options.TokenRateLimit.Enabled = true;       // default false
options.TokenRateLimit.PermitLimit = 60;     // per endpoint, client id, and IP address
options.TokenRateLimit.PermitLimitPerAddress = null; // per endpoint and IP address; null means 4 × PermitLimit
options.TokenRateLimit.Window = TimeSpan.FromMinutes(1);
```

The check runs inside OpenIddict, after the request is parsed and before client authentication or any database read. A request over the limit gets an OAuth error with `429 Too Many Requests` and `Retry-After` (seconds):

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 42

{ "error": "temporarily_unavailable", "error_description": "Too many requests. Try again later." }
```

A request needs a permit from two limits. The first counts every request from one IP address to the endpoint, whatever `client_id` it sends (`PermitLimitPerAddress`, 4 × `PermitLimit` by default). The `client_id` is read before the client is authenticated, so without it a caller could send a new made-up value on each request and get a fresh window every time. The second counts per IP address and `client_id` (`PermitLimit`), so one noisy client behind a shared address does not use up the others' budget. Requests without a `client_id` share one window per IP address.

Behind a reverse proxy, call `UseForwardedHeaders` first, or every client shares the proxy's address. Many users behind one NAT share the per-address limit, and those who use the same configured client share the per-client one too, so size both for that: a client refreshes about once per `AccessTokenLifetime`.

For another algorithm or partition, pass your own limiter. It replaces the built-in one and turns the limit on:

```csharp
builder.Services.AddOAuthServer<AppUser>(options => { /* … */ })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddTokenRateLimiter(_ => PartitionedRateLimiter.Create<OAuthRateLimitContext, string>(context =>
        RateLimitPartition.GetTokenBucketLimiter(
            $"{context.Endpoint}:{context.ClientId}",
            _ => new TokenBucketRateLimiterOptions { TokenLimit = 20, TokensPerPeriod = 20, ReplenishmentPeriod = TimeSpan.FromMinutes(1) })));
```

`OAuthRateLimitContext` has the `HttpContext`, the `Endpoint` (`Token` or `Revocation`), and the `ClientId` as sent (not yet authenticated).

Dynamic registration has its own limit (`DynamicRegistration.PermitsPerMinute`). `/connect/authorize` and the JSON APIs are endpoints, so `RequireRateLimiting` works on them: `MapOAuthServer` returns their groups (`oauth.Consent!.RequireRateLimiting("consent")`).

## Certificates

Set exactly one source in `options.Certificates`:

| Setting | Use it for |
| --- | --- |
| `Path` | A self-signed RSA signing and encryption pair, created on first start in that directory and reused. Treat the directory like Data Protection keys: persistent, private, and shared by every instance. Files are created with owner-only permissions on Linux and macOS. |
| `SigningCertificate` + `EncryptionCertificate` | Certificates you manage (Key Vault, a mounted secret, the machine store). Both need a private key. |
| `UseEphemeralKeys` | Tests and local runs only. Keys are lost on restart, which invalidates every issued token. |

To rotate, add the new certificates through `builder.OpenIddict.AddServer(o => o.AddSigningCertificate(…))` before removing the old ones, so tokens signed with the old key still validate until they expire.

## When the user changes

Each grant remembers the user who approved it and that user's security stamp. On every code exchange and refresh, the server checks that the user still exists, can sign in (`SignInManager.CanSignInAsync`), is not locked out, and has the same security stamp. If any check fails, the request gets `invalid_grant`, and the authorization and all its tokens are revoked.

Identity changes the security stamp when the password changes or is reset, an authenticator is reset, two-factor is turned off, or an external login is removed. Call `UserManager.UpdateSecurityStampAsync(user)` to end every OAuth grant for a user on demand, for example from a "sign out everywhere" button.

The check happens at the token endpoint, so an access token that was already issued keeps working until it expires (15 minutes by default) or until the client next refreshes. To stop it sooner, call `IOAuthConsentService.RevokeAuthorizationAsync`.

The approving user's id and stamp are stored in the code and refresh token only. They are never copied into access tokens or ID tokens, even when a principal factory sends every claim to the access token. The user id is also kept on the authorization in the database, so `userinfo`, logout, [audit events](#audit-events), and the connected apps list can find the user. Replace `IOAuthUserValidator` to apply your own rules, or set `RevalidateUser = false` to turn the check off.

## Audit events

Implement `IOAuthServerEvents` to keep an audit trail of what the OAuth server did, and register it with `AddServerEvents<T>()`. Register as many as you need; each gets every event, in registration order. With none registered (the default), nothing is raised.

```csharp
builder.Services.AddOAuthServer<AppUser>(options => { /* … */ })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddServerEvents<OAuthAuditLog>();

public sealed class OAuthAuditLog(AppDbContext db) : IOAuthServerEvents
{
    public async ValueTask OnEventAsync(OAuthServerEvent e, CancellationToken cancellationToken)
    {
        db.AuditEntries.Add(new AuditEntry(e.Type.ToString(), e.OccurredAt, e.UserId, e.ClientId, e.AuthorizationId));
        await db.SaveChangesAsync(cancellationToken);
    }
}
```

| `Type` | Raised when |
| --- | --- |
| `ConsentApproved` | The user approved a consent request and a code was issued. |
| `ConsentDenied` | The user denied a consent request. |
| `CodeExchanged` | The client exchanged the code for tokens. |
| `TokenRefreshed` | The client refreshed. |
| `GrantRefused` | A code exchange or refresh was refused by [user revalidation](#when-the-user-changes). The grant was revoked. `GrantType` says which grant. |
| `AuthorizationRevoked` | A grant was revoked. `RevokedBy` is `User`, `Admin` (also `IOAuthConsentService.RevokeAuthorizationAsync` and an admin turning a developer app off), `Cleanup` (a developer app whose owner is gone), or `ClientDeleted` (a developer app deleted by its owner). |
| `ClientRegistered` | Dynamic registration, the first stored copy of a client ID metadata document, or a new developer app (`UserId` is its owner). |

Each event has `UserId` (the approving user, even when a principal factory chose another `sub`), `ClientId`, `ClientKind` (`configured`, `dynamic`, `metadata_document`, or `developer_app`; see `OAuthClientKinds`), `AuthorizationId`, `Scopes`, and `Resource`, where they apply. Events never carry a token, an authorization code, a client secret, or the security stamp.

Subscribers are scoped and run in the request, one after another, so keep them fast or hand the event to a queue. A subscriber that throws is logged (event type and subscriber type only) and skipped: the OAuth response does not change and the next subscriber still runs. Calls to your own API are not events; audit those in the API.

Events follow your transaction. When you call `IOAuthConsentService` or `IOAuthConnectedAppService` while a transaction is open on the server's DbContext (`db.Database.BeginTransactionAsync()`, as in [your own approve endpoint](consent.md#option-b-your-own-approve-endpoint)), the events wait: subscribers get them once the transaction commits, and never if it rolls back, so an audit log does not record a grant that was rolled back. Commit or roll back through the `IDbContextTransaction` EF Core returned. A transaction EF Core cannot see (`TransactionScope`, or a `DbTransaction` you commit yourself) does not hold events back. Without a transaction, events are raised at once.

### Last used

Set `RecordLastUsed = true` to record when each grant was last used. The time is written to the authorization at the code exchange and at a refresh, at most once per `LastUsedInterval` (1 hour by default), so a client that refreshes every few minutes does not write on every refresh. A call to the API with an access token does not update it. A write that loses a race with another request is skipped, and the grant is reloaded so later writes in the same token request still succeed; the next refresh records the time.

The package also stores the approving user's id and the approved resource on every authorization (properties `ae_user_id` and `ae_resource`, see `OAuthServerConstants`).

## Protected resource metadata (optional)

For APIs whose clients discover the authorization server on their own (MCP clients, for example):

```csharp
options.ProtectedResource.Enabled = true;
options.ProtectedResource.ResourceName = "My API";
options.ProtectedResource.ChallengePaths.Add("/mcp");

app.UseOAuthResourceChallenge(); // before UseAuthentication
```

`GET /.well-known/oauth-protected-resource` returns `Audience`, the issuer, and the scopes (`ProtectedResource.Scopes`, or every scope when it is empty). A `401` on a challenge path gets `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource"`. Existing `Bearer` parameters are kept.

### One document per resource

When this host serves more than one resource (see [One host, more than one resource](#one-host-more-than-one-resource)), each needs its own document, because a client checks that the document's `resource` is the URL it called. `Audience` and every `AcceptedAudiences` entry whose identifier has a path get a document at the RFC 9728 path-suffixed URL: `https://auth.example.com/mcp` is described at `https://auth.example.com/.well-known/oauth-protected-resource/mcp`. Name a resource, list its scopes, and send its `401` responses there with an entry in `ProtectedResource.Resources`:

```csharp
options.Audience = "https://auth.example.com/api";
options.AdditionalResources.Add("https://auth.example.com/mcp");
options.AcceptedAudiences.Add("https://auth.example.com/mcp");

options.ProtectedResource.Enabled = true;
options.ProtectedResource.ResourceName = "My API";
options.ProtectedResource.ChallengePaths.Add("/api");
options.ProtectedResource.Resources.Add(new OAuthProtectedResourceDefinition
{
    Resource = "https://auth.example.com/mcp",
    ResourceName = "My MCP server",
    Scopes = { "mcp" },
    ChallengePaths = { "/mcp" },
});
```

A `401` on `/mcp` then points at `…/.well-known/oauth-protected-resource/mcp`, and one on `/api` at the root document. The longest matching challenge path wins. When `ProtectedResource.ChallengePaths` is empty, every path that no resource claims points at the root document. An accepted resource without an entry still gets a document, with no name and every scope. `Scopes` is the document's `scopes_supported`: it tells clients what to ask for and does not limit what a token may hold.

The document URL takes its host from the resource identifier, and the endpoint never reads the request `Host` header. Clients fetch it from the resource's host, so that host has to route `/.well-known/oauth-protected-resource/…` to this app. Two accepted resources with the same path on different hosts (`https://a.example/mcp` and `https://b.example/mcp`) cannot be told apart: neither gets a path-suffixed document, and startup fails when a `Resources` entry names one of them. Startup also fails when an entry names a resource that is not in `AcceptedAudiences`, names `Audience` (use the top-level `ResourceName`, `Scopes`, and `ChallengePaths`), has no path or has a query, lists a scope that is not configured, or repeats a challenge path.

#### Under a `PathBase`

RFC 9728 puts the well-known segment between the host and the resource's path, so for an app mounted at `/app` (`Issuer` `https://host/app/`, resource `https://host/app/mcp`) the `401` points at `https://host/.well-known/oauth-protected-resource/app/mcp`, outside `/app`. Route that path to the app at the reverse proxy (or from an app at the root). The app answers it both ways:

- forwarded unchanged, as `/.well-known/oauth-protected-resource/app/mcp`;
- under its `PathBase`, as `/app/.well-known/oauth-protected-resource/mcp`, the location relative to the app, for clients that look there.

The app takes its `PathBase` from the `Issuer` path. At startup, a warning lists accepted resources on the issuer's host whose path is outside it: their documents are reachable only when the proxy forwards the RFC 9728 URL to this app unchanged. The root document is served at `{Issuer}.well-known/oauth-protected-resource` (`/app/.well-known/oauth-protected-resource`) and describes `Audience`.
