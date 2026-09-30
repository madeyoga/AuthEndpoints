# AuthEndpoints.OAuth.Google

Google provider for [AuthEndpoints.External.OAuth](https://www.nuget.org/packages/AuthEndpoints.External.OAuth/). Compose-only. Not part of `MapAuthEndpoints`.

```bash
dotnet add package AuthEndpoints.OAuth.Google --prerelease
```

```csharp
builder.Services.AddExternalAuthEndpoints<AppUser>()
    .AddGoogle(o =>
    {
        o.ClientId = "...";
        o.ClientSecret = "...";
    });

app.MapGroup("/auth/external").MapGoogleAuthEndpoints<AppUser>();
```

`email_verified` is read from the Google userinfo payload.
