# AuthEndpoints.External.OAuth

Preview package: modular external OAuth endpoints for AuthEndpoints (cookie completion by default; pluggable JWT completer).

## Layout

- `Core/` — shared options, provisioning, completers, login/link handlers
- `GitHub/` — `AddGitHub` / `MapGitHubAuthEndpoints`
- `Google/` — `AddGoogle` / `MapGoogleAuthEndpoints`

This package references **both** GitHub and Google OAuth handler packages. Splitting into per-provider NuGets may come in a later release.

## Install

```bash
dotnet add package AuthEndpoints.External.OAuth --version 3.0.0-preview.2
```

Requires [AuthEndpoints](https://www.nuget.org/packages/AuthEndpoints/) (Identity host). Does not use Identity management HTTP APIs.

## Usage

```csharp
using AuthEndpoints.External.OAuth;
using AuthEndpoints.External.OAuth.GitHub;
using AuthEndpoints.External.OAuth.Google;

builder.Services.AddExternalAuthEndpoints<AppUser>(o =>
{
    o.RequireVerifiedEmail = true;
    o.AutoLinkByEmail = true;
    o.ErrorPath = "/auth/external/error";
})
.AddGitHub(o =>
{
    o.ClientId = "...";
    o.ClientSecret = "...";
})
.AddGoogle(o =>
{
    o.ClientId = "...";
    o.ClientSecret = "...";
});

// JWT completion (requires AddJwtEndpoints):
// .AddCompleter<JwtExternalLoginCompleter<AppUser>>()

var external = app.MapGroup("/auth/external").WithTags("External");
external.MapGitHubAuthEndpoints<AppUser>();
external.MapGoogleAuthEndpoints<AppUser>();
external.MapExternalAccountEndpoints<AppUser>();
```

## Completers

| Type | Behavior |
|------|----------|
| `CookieExternalLoginCompleter<TUser>` (default) | Identity cookie + clear External scheme + redirect |
| `JwtExternalLoginCompleter<TUser>` | Refresh cookie + clear External + redirect (SPA uses JWT refresh for access token) |

## Docs

See [External OAuth](https://madeyoga.github.io/AuthEndpoints/modules/external-oauth).
