# AuthEndpoints.OpenIddict

An opt-in OAuth 2.0 authorization server for AuthEndpoints apps, built on [OpenIddict](https://documentation.openiddict.com/) 7.7. Other apps, CLIs, and tool clients (MCP clients, for example) sign users in through your app and receive access and refresh tokens.

The core `AuthEndpoints` package does not change and has no OpenIddict dependency. Install this package only in the app that issues tokens.

> **Preview.** This release covers OAuth 2.0: authorization code + PKCE, refresh, revocation, metadata, and optional dynamic registration. OpenID Connect (ID tokens, `userinfo`, logout, and `email`/`email_verified`/`amr` claims) is not in this release. See [Limitations](#limitations).

## What you get

| Route | Served by | Notes |
| --- | --- | --- |
| `GET /connect/authorize` | this package | Validated by OpenIddict first, then stores a pending consent and redirects to your consent page. Signed-out users go to your login page. |
| `POST /connect/token` | OpenIddict | `authorization_code` and `refresh_token` grants. |
| `POST /connect/revoke` | OpenIddict | RFC 7009. Public clients send `client_id`. |
| `GET /.well-known/oauth-authorization-server` | OpenIddict | RFC 8414 metadata. Endpoint URLs come from `Issuer`, never from the request `Host`. |
| `POST /connect/register` | this package | RFC 7591. **Off by default.** |
| `GET /.well-known/oauth-protected-resource` | this package | RFC 9728. **Off by default.** |
| `GET /oauth/requests/{id}`, `POST …/approve`, `POST …/deny` | this package | Optional JSON consent API (`MapOAuthConsentEndpoints`). |
| `GET\|POST /oauth/apps`, `GET\|PUT\|DELETE /oauth/apps/{id}`, `POST …/secret` | this package | Optional developer console API (`MapOAuthDeveloperAppEndpoints`). |

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

### 1. Register the server

```csharp
using AuthEndpoints.OpenIddict;

builder.Services.AddPasswordAuth<AppUser, AppDbContext>(); // or your existing AuthEndpoints setup

builder.Services.AddAuthEndpointsOpenIddict<AppUser, AppDbContext>(options =>
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

The app fails at startup when a required setting is missing: `Issuer`, `Audience`, `LoginUrl`, `ConsentUrl`, and exactly one certificate source.

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

This adds the four OpenIddict tables (`OpenIddictApplications`, `OpenIddictAuthorizations`, `OpenIddictScopes`, `OpenIddictTokens`, with `ReferenceId` widened to 512 characters) an `OAuthRequests` table for pending consents, and an `OAuthDeveloperApps` table for [developer apps](#developer-apps-optional), each with a cascading foreign key to the user. Then add a migration:

```bash
dotnet ef migrations add OAuthServer
```

Pass `userForeignKey: false` when the users table is in a different DbContext.

### 3. Map the routes

```csharp
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapAuthEndpointsOpenIddict();
app.MapOAuthConsentEndpoints();      // optional JSON consent API, see below
app.MapOAuthDeveloperAppEndpoints(); // optional developer console API, see below

await app.Services.SeedOAuthClientsAsync(); // optional, creates clients from options.Clients
app.Run();
```

### 4. Protect your API with the issued tokens

The package registers OpenIddict validation for this host. It accepts only tokens whose audience is `Audience`.

```csharp
builder.Services.AddAuthorization(options => options.AddPolicy("api", policy => policy
    .AddAuthenticationSchemes(OAuthServerServiceCollectionExtensions.ValidationScheme)
    .RequireAuthenticatedUser()));

app.MapGet("/api/me", (ClaimsPrincipal user) => user.FindFirst("sub")?.Value)
    .RequireAuthorization("api");
```

Access tokens are reference tokens, validated against this server's database. APIs in other processes are not supported yet (that needs introspection or JWT access tokens, see [Limitations](#limitations)).

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
```

`POST /connect/register` accepts only public clients (`token_endpoint_auth_method` `none`, no `client_secret`), the `authorization_code` and `refresh_token` grants, the `code` response type, and configured scopes. Each redirect URI must be `https`, or `http` on `localhost`, `127.0.0.1`, or `[::1]`, with no fragment and no user info. The rate limit runs inside the endpoint, so it works without `UseRateLimiter`. Behind a proxy, configure forwarded headers so the client IP is right.

A registered client that no user approved within `UnusedClientLifetime` (24 hours) is deleted by the background cleanup. Seeded clients are never deleted.

### Developer apps (optional)

Signed-in users register OAuth apps they own and get a client id (and, for a confidential app, a client secret), the way the GitHub and Google developer consoles work. `MapOAuthDeveloperAppEndpoints()` maps a JSON API for your developer console page. Every route requires the signed-in user (`AuthenticationScheme`), and the writes require a CSRF token for cookie callers, as the consent API does.

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

`MapOAuthConsentEndpoints("/oauth")` maps, for the signed-in user:

| Route | Response |
| --- | --- |
| `GET /oauth/requests/{id}` | `{ id, clientId, clientName, redirectHost, scopes, resource, expiresAt }` |
| `POST /oauth/requests/{id}/approve` | `{ redirectUrl }` with `code`, `state`, and `iss` |
| `POST /oauth/requests/{id}/deny` | `{ redirectUrl }` with `error=access_denied` |

The POSTs require a CSRF token for cookie callers (the same filter as other AuthEndpoints cookie routes). Unknown, expired, used, and other users' requests are all `404`. Your consent page shows `clientName` and `redirectHost`, then sends the browser to `redirectUrl`.

The client is checked again when the user answers, because it can be deleted, or a developer app disabled or sent back to review, after `/connect/authorize` stored the request. A request whose client no longer exists, or whose developer app is not `Active`, is also `404` on all three routes (`OAuthConsentStatus.NotFound` from `IOAuthConsentService`). No code is issued, and deny does not redirect to that client. Approve and deny consume the request, so re-enabling the app does not revive it; the user starts a new authorize request. The card fetch does not consume it.

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
builder.Services.AddAuthEndpointsOpenIddict<AppUser, AppDbContext>(…)
    .AddPrincipalFactory<MyPrincipalFactory>();
```

`IOAuthPrincipalFactory.CreateAsync` gets the signed-in user id and the pending request, and returns the principal (or `null` to decline without consuming the request). The principal needs a `sub` claim. Other claims reach the access token only when you call `SetDestinations` on them.

## When the user changes

Each grant remembers the user who approved it and that user's security stamp. On every code exchange and refresh, the server checks that the user still exists, can sign in (`SignInManager.CanSignInAsync`), is not locked out, and has the same security stamp. If any check fails, the request gets `invalid_grant`, and the authorization and all its tokens are revoked.

Identity changes the security stamp when the password changes or is reset, an authenticator is reset, two-factor is turned off, or an external login is removed. Call `UserManager.UpdateSecurityStampAsync(user)` to end every OAuth grant for a user on demand, for example from a "sign out everywhere" button.

The check happens at the token endpoint, so an access token that was already issued keeps working until it expires (15 minutes by default) or until the client next refreshes. To stop it sooner, call `IOAuthConsentService.RevokeAuthorizationAsync`.

The approving user's id and stamp are stored in the code and refresh token only. They are never copied into access tokens, even when a principal factory sends every claim to the access token. Replace `IOAuthUserValidator` to apply your own rules, or set `RevalidateUser = false` to turn the check off.

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
| `Audience` | required | Default resource and the only audience this host accepts. |
| `AdditionalResources` | empty | Other resources clients may request (validated elsewhere). |
| `Scopes` / `DefaultScopes` | empty | `offline_access` is always registered. |
| `AlwaysIssueRefreshToken` | `true` | Adds `offline_access` when the client has the refresh grant. |
| `LoginUrl`, `LoginReturnUrlParameter` | required, `returnUrl` | |
| `ConsentUrl`, `ConsentRequestParameter` | required, `request` | |
| `AuthenticationScheme`, `UserIdClaimType` | Identity cookie, `NameIdentifier` | |
| `AccessTokenLifetime` | 15 minutes | |
| `RefreshTokenLifetime` | 30 days | Rotating, no reuse leeway. |
| `AuthorizationCodeLifetime` | 5 minutes | |
| `ConsentLifetime` | 10 minutes | |
| `DeveloperApps` | approval off, 10 apps, 10 redirects | See [Developer apps](#developer-apps-optional). |
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

- **No OpenID Connect yet.** There are no ID tokens, no `userinfo` or end-session (logout) endpoints, and no `email`, `email_verified`, or `amr` claims. The `openid` scope is rejected. Access tokens carry `sub`, plus whatever your principal factory adds.
- **Only this server validates tokens.** Access tokens are reference tokens, so an API in another process cannot validate them. There is no introspection endpoint and no JWT access token option yet.
- **Issued access tokens outlive a user change.** A locked-out user or a changed password stops the grant at the next code exchange or refresh. An access token that was already issued works until it expires. See [When the user changes](#when-the-user-changes).
- **Fixed routes.** The endpoints are always under `/connect` and `/.well-known` (see `OAuthServerConstants`), relative to the app's `PathBase`.
- **Cookie sign-in only at the authorize step.** The user is read from `AuthenticationScheme` (the Identity cookie by default). Password, two-factor, passkey, and cookie-mode external sign-in all end with that cookie. A sign-in that is still waiting for a second factor, or an external sign-in that has not been completed, does not count.

An OIDC client for AuthEndpoints (the other direction) is tracked separately in issue #380.
