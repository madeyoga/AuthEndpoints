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

A token for `/mcp` then gets `403` from `/api`, and the other way round. Protected resource metadata still describes `Audience` only.

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

`GET /.well-known/oauth-protected-resource` returns `Audience`, the issuer, and the scopes. A `401` on a challenge path gets `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource"`. Existing `Bearer` parameters are kept.
