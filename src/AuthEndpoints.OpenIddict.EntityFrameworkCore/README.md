# AuthEndpoints.OpenIddict.EntityFrameworkCore

EF Core storage for [AuthEndpoints.OpenIddict](https://www.nuget.org/packages/AuthEndpoints.OpenIddict). It registers OpenIddict's EF Core stores and the AuthEndpoints stores for pending consent requests and developer apps, all in your `DbContext`.

```cs
builder.Services.AddOAuthServer<AppUser>(oauth =>
    {
        oauth.Issuer = new Uri("https://localhost:5001/");
    })
    .AddEntityFrameworkStores<AppDbContext>();
```

Map the tables in `OnModelCreating`, then add a migration:

```cs
protected override void OnModelCreating(ModelBuilder builder)
{
    base.OnModelCreating(builder);
    builder.UseAuthEndpointsOpenIddict<AppUser>();
}
```

To use other storage, skip this package and register OpenIddict's stores (`IOpenIddictApplicationStore<>`, `IOpenIddictAuthorizationStore<>`, `IOpenIddictScopeStore<>`, `IOpenIddictTokenStore<>`) and the AuthEndpoints ones (`IOAuthRequestStore<TKey>`, `IOAuthDeveloperAppStore<TKey>`, `IOAuthServerQueries`, `IOAuthServerEventTransactions`, `IOAuthAuthorizationRefresher`).

Docs: https://authendpoints.harten.id
