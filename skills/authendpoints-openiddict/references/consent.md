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
| `GET /oauth/requests/{id}` | `{ id, clientId, clientName, redirectHost, scopes, resource, expiresAt, homepageUrl, description, confidential, owner }` |
| `POST /oauth/requests/{id}/approve` | `{ redirectUrl }` with `code`, `state`, and `iss` |
| `POST /oauth/requests/{id}/deny` | `{ redirectUrl }` with `error=access_denied` |

The POSTs require a CSRF token for cookie callers (the same filter as other AuthEndpoints cookie routes). Unknown, expired, used, and other users' requests are all `404`. Your consent page shows `clientName` and `redirectHost`, then sends the browser to `redirectUrl`.

The client is checked again when the user answers, because it can be deleted or edited, or a developer app disabled or sent back to review, after `/connect/authorize` stored the request. A request whose client no longer exists, whose developer app is not `Active`, or whose redirect URI is no longer registered for the client (with the same loopback any-port rule as authorize), is also `404` on all three routes (`OAuthConsentStatus.NotFound` from `IOAuthConsentService`). No code is issued, and deny does not redirect to that client. Approve and deny consume the request, so re-enabling the app does not revive it; the user starts a new authorize request. The card fetch does not consume it.

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
}).RequireAuthorization().RequireAntiforgery();
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
