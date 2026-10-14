# AuthEndpoints.OAuth.GitHub

GitHub provider for [AuthEndpoints](https://www.nuget.org/packages/AuthEndpoints/). This package registers the handler. It does not map routes.

```bash
dotnet add package AuthEndpoints.OAuth.GitHub
```

```csharp
builder.Services.AddExternalAuthEndpoints<AppUser>()
    .AddGitHub(o =>
    {
        o.ClientId = "...";
        o.ClientSecret = "...";
    });

app.MapGroup("/auth/external").MapExternalAuthProvider<AppUser>("GitHub");
```

Sign-in uses a verified address from GitHub `GET /user/emails`. An unverified profile email is not treated as verified.
