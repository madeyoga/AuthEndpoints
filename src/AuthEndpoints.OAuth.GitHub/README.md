# AuthEndpoints.OAuth.GitHub

GitHub provider for [AuthEndpoints.External.OAuth](https://www.nuget.org/packages/AuthEndpoints.External.OAuth/). Compose-only. Not part of `MapAuthEndpoints`.

```bash
dotnet add package AuthEndpoints.OAuth.GitHub --prerelease
```

```csharp
builder.Services.AddExternalAuthEndpoints<AppUser>()
    .AddGitHub(o =>
    {
        o.ClientId = "...";
        o.ClientSecret = "...";
    });

app.MapGroup("/auth/external").MapGitHubAuthEndpoints<AppUser>();
```

Sign-in uses a verified address from GitHub `GET /user/emails`. An unverified profile email is not treated as verified.
