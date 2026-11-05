# Map the routes

## Turning parts off

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

`MapOAuthServer` returns the consent and developer app groups (`null` when off). Turning off the consent API does not turn off consent: `/connect/authorize` still sends users to `ConsentUrl`, and your page approves through `IOAuthConsentService` ([option B](consent.md#option-b-your-own-approve-endpoint)).

## Without the recipe

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
