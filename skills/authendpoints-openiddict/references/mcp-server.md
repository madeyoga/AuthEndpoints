# Expose an MCP server with per-user OAuth

An AI assistant or other MCP client connects to an MCP server your app hosts, and each person signs in as themselves. The assistant's token carries that person's roles and only the scopes they approved. The [full guide](https://authendpoints.harten.id/guides/mcp-server-oauth) walks through every step. In short, for an app that serves `/api` to cookie users and `/mcp` to assistants:

```csharp
builder.Services.AddOAuthServer<AppUser, AppDbContext>(options =>
{
    options.Issuer = new Uri("https://app.example.com/");
    options.Audience = "https://app.example.com/api";
    options.AdditionalResources.Add("https://app.example.com/mcp");
    options.AcceptedAudiences.Add("https://app.example.com/mcp");
    options.Scopes.Add("mcp");
    options.Scopes.Add("reports.read");
    options.LoginUrl = "https://app.example.com/sign-in";
    options.ConsentUrl = "https://app.example.com/oauth/consent";
    options.Certificates.Path = "/var/lib/myapp/oauth-keys";

    options.ClientMetadataDocuments.Enabled = true; // preferred by the MCP spec
    options.DynamicRegistration.Enabled = true;     // fallback
    options.DynamicRegistration.AllowedScopes.Add("mcp");
    options.DynamicRegistration.AllowedScopes.Add("reports.read");

    options.ProtectedResource.Enabled = true;
    options.ProtectedResource.Resources.Add(new OAuthProtectedResourceDefinition
    {
        Resource = "https://app.example.com/mcp",
        ResourceName = "Example MCP server",
        Scopes = { "mcp", "reports.read" },
        ChallengePaths = { "/mcp" },
    });

    options.AccessTokenClaims.Roles = true;
    options.AccessTokenClaims.UserId = true;
});

builder.Services.AddAuthorization(options => options.AddPolicy("mcp", policy => policy
    .RequireOAuthAudience("https://app.example.com/mcp")
    .RequireOAuthScope("mcp")
    .RequireRole("Member")));

app.UseOAuthResourceChallenge();
app.UseAuthEndpoints();
app.MapOAuthServer();
app.MapMcp("/mcp").RequireAuthorization("mcp"); // or your own MCP endpoint
```

- **Discovery.** A `401` on `/mcp` points at `/.well-known/oauth-protected-resource/mcp`, which names this authorization server.
- **Identification.** The assistant uses a client ID metadata document or registers. Both are public clients held to `DynamicRegistration.AllowedScopes`, so keep first-party scopes out of that list.
- **Consent.** Your page shows `clientName` with `clientHost` (or `redirectHost`), and the scopes from `scopeDetails`. Describe them in `ScopeDefinitions`.
- **Tokens.** The assistant asks for `resource=https://app.example.com/mcp`. `RequireOAuthAudience` keeps that token on `/mcp`, `RequireOAuthScope` checks the grant, and the role check is the one cookie users go through. Inside tool handlers, use `User.IsOAuthDelegated()` and `User.HasOAuthScope(...)`.
- **Shared routes.** On routes that cookie users also call, use `RequireOAuthScopeWhenDelegated(...)` next to the existing role check, and check the audience only for token callers. A refused token caller gets `403`, not the cookie's redirect (`BearerRequestsSkipCookieRedirects`, on by default).
- **Disconnecting.** `IOAuthConsentService.RevokeAuthorizationAsync(authorizationId)` ends one grant. `UserManager.UpdateSecurityStampAsync(user)` ends every grant at its next refresh.

A scope never widens what the person may do: keep every route's existing role or policy check.
