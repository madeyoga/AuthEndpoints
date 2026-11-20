# The consent step

The authorize endpoint never shows a page. When the user is signed in, it stores a pending request and redirects to:

```
{ConsentUrl}?request={id}
```

When the user is signed out, it redirects to:

```
{LoginUrl}?returnUrl=/connect/authorize?client_id=…
```

`returnUrl` is a path on this server, rebuilt from the incoming request. After sign-in, send the browser there (prefix it with the server's origin if your login page is on another origin) and the flow resumes. The user is read from `AuthenticationScheme` (default: the Identity application cookie), so bearer-only apps need the cookie enabled for this step. `prompt=none` returns `login_required` or `consent_required` to the client instead of a page.

## Option A: the built-in JSON consent API

`MapOAuthServer()` maps (or `MapOAuthConsentEndpoints("/oauth")` without the recipe), for the signed-in user:

| Route | Response |
| --- | --- |
| `GET /oauth/requests/{id}` | `{ id, clientId, clientName, redirectHost, scopes, scopeDetails, resource, expiresAt, homepageUrl, description, confidential, owner, clientHost }` |
| `POST /oauth/requests/{id}/approve` | `{ redirectUrl }` with `code`, `state`, and `iss` |
| `POST /oauth/requests/{id}/deny` | `{ redirectUrl }` with `error=access_denied` |

The POSTs require a CSRF token from every caller, an OAuth access token included (`RequireAntiforgery(allowBearer: false)`). Unknown, expired, used, and other users' requests are all `404`. Your consent page shows `clientName` and `redirectHost`, then sends the browser to `redirectUrl`. For a client identified by a client ID metadata document, `clientHost` is the host of its `client_id` URL; show it next to the name, because that domain published the name. It is `null` for other clients. See [Client ID metadata documents](clients.md#client-id-metadata-documents-optional).

The client is checked again when the user answers, because it can be deleted or edited, or a developer app disabled or sent back to review, after `/connect/authorize` stored the request. A request whose client no longer exists, whose developer app is not `Active`, or whose redirect URI is no longer registered for the client (with the same loopback any-port rule as authorize), is also `404` on all three routes (`OAuthConsentStatus.NotFound` from `IOAuthConsentService`). No code is issued, and deny does not redirect to that client. Approve and deny consume the request, so re-enabling the app does not revive it; the user starts a new authorize request. The card fetch does not consume it.

### Scope descriptions

A person approving a client should read "Read your reports", not `reports.read`. Describe each scope once, in code or `appsettings`, optionally per culture:

```json
{
  "OAuthServer": {
    "Scopes": [ "reports.read" ],
    "ScopeDefinitions": [
      {
        "Name": "reports.read",
        "DisplayName": "Read your reports",
        "Description": "See the reports you can open. It cannot change them.",
        "DisplayNames": { "fr": "Lire vos rapports" },
        "Descriptions": { "fr": "Voir les rapports que vous pouvez ouvrir. Il ne peut pas les modifier." }
      },
      { "Name": "offline_access", "DisplayName": "Stay connected", "Description": "Keep access when you are not using the app." }
    ]
  }
}
```

The card then has `scopeDetails` next to `scopes`, in the same order:

```json
"scopes": [ "reports.read", "offline_access" ],
"scopeDetails": [
  { "name": "reports.read", "displayName": "Read your reports", "description": "See the reports you can open. It cannot change them." },
  { "name": "offline_access", "displayName": "Stay connected", "description": "Keep access when you are not using the app." }
]
```

- `scopes` stays a list of names, so existing consent pages keep working. Read `scopeDetails` for the words.
- The text is resolved for the request culture (`CultureInfo.CurrentUICulture`, which `UseRequestLocalization` sets from `Accept-Language`, a cookie, or the query string): the culture (`pt-BR`), then its parents (`pt`), then `DisplayName` and `Description`. A scope without a definition gets its name as `displayName` and `null` as `description`.
- Each `Name` must be in `Scopes`, or be `offline_access`, and appear once. Culture keys must be culture names. A wrong entry fails at startup.
- `OAuthPendingRequest.ScopeDetails` has the same list for `IOAuthConsentService.FindAsync` and principal factories.
- The text comes from your configuration, never from the client, so a client cannot change what the card says a scope does.

### Developer app details on the card

When the client is a [developer app](developer-apps.md), the card also tells the user what they are approving, since another user built it:

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

## Option B: your own approve endpoint

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
}).RequireAuthorization().RequireAntiforgery(allowBearer: false);
```

The service uses the scoped DbContext, so your transaction also covers the OpenIddict rows. Keep `RevokeAuthorizationAsync(authorizationId)` for a "disconnect app" button: it revokes the authorization and every token from it.

## Who is the token subject

By default `sub` is the Identity user id. Replace it for every approval:

```csharp
builder.Services.AddOAuthServer<AppUser, AppDbContext>(…)
    .AddPrincipalFactory<MyPrincipalFactory>();
```

`IOAuthPrincipalFactory.CreateAsync` gets the signed-in user id and the pending request, and returns the principal (or `null` to decline without consuming the request). The principal needs a `sub` claim. Other claims reach the access token only when you call `SetDestinations` on them.

With OpenID Connect, the ID token `sub` is the same `sub`, so a custom factory changes both. See [Claims](openid-connect.md#claims).

With `AccessTokenClaims` on, the user's roles and id are added only while `sub` is the approving user's id. See [Roles and the user id on tokens](settings.md#roles-and-the-user-id-on-tokens).

## Connected apps

A signed-in person can see which clients they connected and disconnect one. `MapOAuthServer` maps two JSON routes for that, at `/oauth/authorizations` (`parts.ConnectedApps`, `parts.ConnectedAppsPrefix`):

| Route | Response |
| --- | --- |
| `GET /oauth/authorizations` | `[{ authorizationId, clientId, clientName, clientKind, clientHost, scopes, scopeDetails, resource, createdAt, lastUsedAt }]`, newest first |
| `DELETE /oauth/authorizations/{authorizationId}` | `204`, or `404` when the grant is unknown, someone else's, or already revoked |

- Only live grants are listed: not revoked, and still holding a valid token. A grant whose refresh token expired drops off.
- A grant belongs to the user who approved it, even when a principal factory issued its tokens for another `sub`.
- `clientKind` is `configured`, `dynamic`, `metadata_document`, or `developer_app` (`OAuthClientKinds`). `clientHost` is the host of a metadata document client's URL, or of a developer app's homepage, and `null` for other clients, whose names are self-asserted.
- `lastUsedAt` is `null` unless [`RecordLastUsed`](settings.md#last-used) is on.
- The routes authenticate with `AuthenticationScheme` (the Identity cookie), so an OAuth access token cannot list or revoke grants. The `DELETE` needs a CSRF token (`RequireAntiforgery(allowBearer: false)`).
- Disconnecting revokes the grant and every token from it, and raises `AuthorizationRevoked` with `RevokedBy = User`.

For your own page, or for an admin page about another user, call `IOAuthConnectedAppService`. The package does not decide who is an admin: check that first.

```csharp
app.MapDelete("/admin/users/{userId}/connected-apps/{authorizationId}", async (
        string userId, string authorizationId, ClaimsPrincipal admin, IOAuthConnectedAppService apps) =>
    await apps.RevokeAsync(userId, authorizationId, OAuthRevokedBy.Admin, admin.FindFirstValue(ClaimTypes.NameIdentifier))
        ? Results.NoContent()
        : Results.NotFound())
    .RequireAuthorization("admin")
    .RequireAntiforgery(allowBearer: false);
```

`ListAsync(userId)` returns the same items as the `GET` route.
