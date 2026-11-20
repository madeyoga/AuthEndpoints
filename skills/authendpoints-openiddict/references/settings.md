# Settings, certificates, and user checks

## Settings

| Option | Default | |
| --- | --- | --- |
| `Issuer` | required | Absolute; `https` unless `DisableTransportSecurityRequirement`. Use the app root (`https://host/`), or the app's `PathBase`. |
| `Audience` | required | Default resource. This host always accepts it. |
| `AdditionalResources` | empty | Other resources clients may request. Rejected by this host unless also in `AcceptedAudiences`. |
| `AcceptedAudiences` | empty | Resources (`Audience` or `AdditionalResources` entries) this host's validation also accepts. Check `aud` per route, see [One host, more than one resource](#one-host-more-than-one-resource). |
| `Scopes` / `DefaultScopes` | empty | `offline_access` is always registered. Add `openid` for [OpenID Connect](openid-connect.md), and `email` for the email claims. |
| `AlwaysIssueRefreshToken` | `true` | Adds `offline_access` when the client has the refresh grant. |
| `LoginUrl`, `LoginReturnUrlParameter` | required, `returnUrl` | |
| `ConsentUrl`, `ConsentRequestParameter` | required, `request` | |
| `LogoutUrl` | none | OpenID Connect only. The sign-out page for a [logout](openid-connect.md#logout) without a matching `id_token_hint`. Gets the logout URL in `LoginReturnUrlParameter`. |
| `AuthenticationScheme`, `UserIdClaimType` | Identity cookie, `NameIdentifier` | |
| `AccessTokenLifetime` | 15 minutes | |
| `RefreshTokenLifetime` | 30 days | Rotating, no reuse leeway. |
| `AuthorizationCodeLifetime` | 5 minutes | |
| `ConsentLifetime` | 10 minutes | |
| `DeveloperApps` | approval off, 10 apps, 10 redirects | See [Developer apps](developer-apps.md). |
| `CleanupInterval`, `PruneAfter` | 1 hour, 14 days | Background sweep of unused clients, developer apps without an owner, expired consents, old tokens. Zero turns it off; `IOAuthServerCleanup.SweepAsync` runs it on demand. |
| `RevalidateUser` | `true` | Re-check the approving user on every code exchange and refresh. |
| `AccessTokenClaims` | off | `Roles` and `UserId` add the approving user's Identity roles and user id to access tokens. See [Roles and the user id on tokens](#roles-and-the-user-id-on-tokens). |
| `DisableTransportSecurityRequirement` | `false` | Local development only. |
| `DisableResourceValidation` | `false` | Token endpoint only. Authorize still accepts configured resources only. |
| `IgnoreResourcePermissions` | `false` | Skips per-client `rsrc:` permissions. |
| `QueryStringTokenPaths` | empty | Path prefixes that also accept `?access_token=`, for SignalR and WebSockets. Elsewhere only `Authorization: Bearer` is read. See [Where the token is read from](#where-the-token-is-read-from). |

The fixed routes are in `OAuthServerConstants`. Anything else can be set on `OAuthServerBuilder.OpenIddict`.

## One host, more than one resource

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

A token for `/mcp` then gets `403` from `/api`, and the other way round. With protected resource metadata on, each accepted resource gets its own document; see [One document per resource](#one-document-per-resource).

## Roles and the user id on tokens

A validated access token has `sub` and the granted scopes, but no roles and no `ClaimTypes.NameIdentifier`, so `RequireRole` policies and `UserManager.GetUserId(User)` see a token caller as a user without either. Turn on `AccessTokenClaims` to add them:

```csharp
builder.Services.AddOAuthServer<AppUser, AppDbContext>(options =>
{
    // ...
    options.AccessTokenClaims.Roles = true;  // the approving user's Identity roles, as `role` claims
    options.AccessTokenClaims.UserId = true; // ClaimTypes.NameIdentifier from sub
});

builder.Services.AddAuthorization(options => options.AddPolicy("reports", policy => policy
    .AddAuthenticationSchemes(OAuthServerServiceCollectionExtensions.ValidationScheme)
    .RequireRole("Reports")));
```

- `Roles` adds the approving user's Identity roles as `role` claims. That is the role claim type of the identity `ValidationScheme` creates, so `IsInRole`, `RequireRole`, and `[Authorize(Roles = "…")]` work. Code that reads `ClaimTypes.Role` claims directly does not see them. It needs Identity roles (`AddRoles<TRole>()`); without them, mapping the server fails at startup.
- `UserId` adds `ClaimTypes.NameIdentifier`, `UserIdClaimType`, and `IdentityOptions.ClaimsIdentity.UserIdClaimType`, each set to `sub`.
- Both are read at every code exchange and refresh, and written to the access token only, never to the code, the refresh token, or the ID token. A role change reaches the client at its next refresh. An access token that was already issued keeps its roles until it expires (15 minutes by default).
- Both apply only when `sub` is the approving user. A principal factory that issues tokens for another subject gets neither, because the user's roles would describe the wrong subject. A factory that keeps the user id as `sub` keeps its own claims, and the user's roles are added next to any role claims it sends to the access token.
- The security stamp and the grant's internal claims are never copied. Both options are off by default.

## Require scopes

A scope is what the person allowed the client to do for them. It narrows what the user's account may do and never widens it, so keep the role or policy check a route already has and add the scope next to it. `RequireOAuthScope` authenticates with `ValidationScheme` and requires every listed scope; a token missing one gets `403`:

```csharp
builder.Services.AddAuthorization(options =>
{
    // A route only OAuth clients call.
    options.AddPolicy("mcp", policy => policy
        .RequireOAuthAudience("https://auth.example.com/mcp")
        .RequireOAuthScope("mcp"));

    // A route that cookie users and OAuth clients share.
    options.AddPolicy("reports.read", policy => policy
        .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme, OAuthServerServiceCollectionExtensions.ValidationScheme)
        .RequireAuthenticatedUser() // and the route's existing role or policy check
        .RequireOAuthScopeWhenDelegated("reports.read"));
});
```

`RequireOAuthScopeWhenDelegated` adds only the scope check. A caller without an OAuth access token (cookie, Identity bearer, JWT) passes it, and a token caller needs every listed scope, even when the same request also carries a valid cookie. It adds no scheme, so list `ValidationScheme` in the policy, or the token is never read. Both helpers add an `OAuthScopeRequirement`, which you can also add to a policy you build by hand. A role check on a shared route sees a token caller's roles only with `AccessTokenClaims.Roles` on; see [Roles and the user id on tokens](#roles-and-the-user-id-on-tokens).

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
builder.Services.AddOAuthServer<AppUser, AppDbContext>(options =>
{
    // ...
    options.QueryStringTokenPaths.Add("/hubs");
});

app.MapHub<ChatHub>("/hubs/chat").RequireAuthorization("api");
```

Prefixes match whole path segments: `/hubs` covers `/hubs`, `/hubs/chat`, and `/hubs/chat/negotiate`, but not `/hubsevil`. They are relative to `PathBase`, like routes. Each must start with `/` and must not end with one. On a listed path the `Authorization` header still wins when both are sent.

**Upgrading a SignalR host:** if a hub's clients pass the token with `accessTokenFactory` (JavaScript) or `AccessTokenProvider` (.NET), add the hub's path prefix to `QueryStringTokenPaths`. Without it, the WebSocket and Server-Sent Events transports get `401` after upgrading. Clients that send `Authorization: Bearer` and form posts that put the token in the header need no change.

### CSRF on routes that take a token

`AddAuthEndpointsOpenIddict` (and so `AddOAuthServer`) adds the validation scheme (`OAuthServerServiceCollectionExtensions.ValidationScheme`) to `AuthEndpointsAntiforgeryOptions.BearerSchemes`. A route that accepts both the cookie and an OAuth access token, mapped with `RequireAntiforgery()`, no longer asks the token caller for a CSRF token. A cross-site request cannot set `Authorization: Bearer`, and a request the application cookie authenticates is still checked. A token read from the query string on a `QueryStringTokenPaths` prefix does not skip the check, because it is not in the header.

Use `RequireAntiforgery(allowBearer: false)` on routes a token must never call on its own, such as your own consent approval or account deletion. The package's consent and developer app writes already do. To check every OAuth caller again, take the scheme back out after registering the server:

```csharp
builder.Services.PostConfigure<AuthEndpointsAntiforgeryOptions>(options =>
    options.BearerSchemes.Remove(OAuthServerServiceCollectionExtensions.ValidationScheme));
```

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

The approving user's id and stamp are stored in the code and refresh token only. They are never copied into access tokens or ID tokens, even when a principal factory sends every claim to the access token. With OpenID Connect, the user id is also kept on the authorization in the database, so `userinfo` and logout can find the user. Replace `IOAuthUserValidator` to apply your own rules, or set `RevalidateUser = false` to turn the check off.

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
