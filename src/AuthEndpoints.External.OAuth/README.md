# AuthEndpoints.External.OAuth

Forwarding shim for AuthEndpoints 4.0. The external OAuth endpoints now live in `AuthEndpoints.dll`, in the same namespace `AuthEndpoints.External.OAuth`.

Remove this package reference. Code that already uses `AuthEndpoints.External.OAuth` compiles unchanged. A project that still references this package gets warning `AE4001`.

`AuthEndpoints.External.OAuth` 3.0.0-preview.5 defines those types itself. Using it with AuthEndpoints 4.0 fails the build with `AE4000`. Upgrade this package to 4.0.0 or remove it.

GitHub and Google 4.0.0 only register providers. Map the routes from the core package:

```csharp
builder.Services.AddExternalAuthEndpoints<AppUser>()
    .AddGitHub(o =>
    {
        o.ClientId = "...";
        o.ClientSecret = "...";
    });

app.MapGroup("/auth/external").MapExternalAuthProvider<AppUser>("GitHub");
app.MapGroup("/auth/external").MapExternalAccountEndpoints<AppUser>();
```

`MapExternalAuthEndpoints` and `MapExternalAuthProvider` take `session:` (`Cookie`, `IdentityBearer`, or `Jwt`) and finish through the shared sign-in completer. External sign-in has no two-factor step. `Jwt` with `RefreshTokenTransport.Body` fails because the callback only redirects.
