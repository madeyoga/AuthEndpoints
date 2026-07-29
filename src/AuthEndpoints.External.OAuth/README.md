[WIP] AuthEndpoints.External

Modular external OAuth endpoints (cookie completion by default).

## Layout

- `Core/` — shared options, provisioning, pluggable completer, shared handlers
- `GitHub/` — `AddGitHub` / `MapGitHubAuthEndpoints`
- `Google/` — `AddGoogle` / `MapGoogleAuthEndpoints`

## Usage

```csharp
using AuthEndpoints.External;
using AuthEndpoints.External.GitHub;
using AuthEndpoints.External.Google;

builder.Services.AddExternalAuthEndpoints<AppUser>()
    .AddGitHub(o =>
    {
        o.ClientId = builder.Configuration["Authentication:GitHub:ClientId"]!;
        o.ClientSecret = builder.Configuration["Authentication:GitHub:ClientSecret"]!;
    })
    .AddGoogle(o =>
    {
        o.ClientId = builder.Configuration["Authentication:Google:ClientId"]!;
        o.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"]!;
    });

// Map individually:
var external = app.MapGroup("/auth/external").WithTags("External");
external.MapGitHubAuthEndpoints<AppUser>();
external.MapGoogleAuthEndpoints<AppUser>();

// Or map every registered provider:
// app.MapGroup("/auth/external").MapExternalAuthEndpoints<AppUser>();
```

Routes (under your group prefix):

| Provider | Login | Callback |
|----------|-------|----------|
| GitHub | `GET .../login/github` | `GET .../login/github/callback` |
| Google | `GET .../login/google` | `GET .../login/google/callback` |

OAuth middleware callbacks remain `/signin-github` and `/signin-google` (register those URLs with the IdP).

## Completer

Default: Identity application cookie via `CookieExternalLoginCompleter<TUser>`.

Replace later for JWT (or other) completion:

```csharp
builder.Services.AddExternalAuthEndpoints<AppUser>()
    .AddCompleter<MyJwtExternalLoginCompleter<AppUser>>()
    .AddGitHub(...);
```

Optional `ExternalAuthOptions.SignInScheme` overrides the cookie completer scheme; leave null to use SignInManager's default (`Identity.Application`).
