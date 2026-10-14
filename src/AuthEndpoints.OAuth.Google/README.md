# AuthEndpoints.OAuth.Google

Google provider for [AuthEndpoints](https://www.nuget.org/packages/AuthEndpoints/). This package registers the handler. It does not map routes.

```bash
dotnet add package AuthEndpoints.OAuth.Google
```

```csharp
builder.Services.AddExternalAuthEndpoints<AppUser>()
    .AddGoogle(o =>
    {
        o.ClientId = "...";
        o.ClientSecret = "...";
    });

app.MapGroup("/auth/external").MapExternalAuthProvider<AppUser>("Google");
```

`email_verified` is read from the Google userinfo payload.
