# AuthEndpoints.External.OAuth

**Docs:** [https://authendpoints.harten.id](https://authendpoints.harten.id)

Preview package: modular external OAuth endpoints for AuthEndpoints (cookie completion by default; pluggable JWT completer). Compose-only. Not part of `MapAuthEndpoints`.

GitHub and Google handlers are separate packages so this nupkg does not reference both.

## Packages

| Package | Role |
| --- | --- |
| `AuthEndpoints.External.OAuth` | Options, provisioning, login/link/unlink endpoints, cookie and JWT completers |
| `AuthEndpoints.OAuth.GitHub` | `AddGitHub` / `MapGitHubAuthEndpoints` |
| `AuthEndpoints.OAuth.Google` | `AddGoogle` / `MapGoogleAuthEndpoints` |

## Install

[![nuget](https://img.shields.io/nuget/vpre/AuthEndpoints.External.OAuth?label=External.OAuth&logo=NuGet&style=flat-square)](https://www.nuget.org/packages/AuthEndpoints.External.OAuth/)
[![nuget](https://img.shields.io/nuget/v/AuthEndpoints?label=AuthEndpoints&logo=NuGet&style=flat-square)](https://www.nuget.org/packages/AuthEndpoints/)

```bash
dotnet add package AuthEndpoints.OAuth.GitHub --prerelease
dotnet add package AuthEndpoints.OAuth.Google --prerelease
```

Each provider package depends on this core package. Install only the providers you use. Use `--prerelease` while these packages publish preview builds. They need a published [AuthEndpoints](https://www.nuget.org/packages/AuthEndpoints/) Identity host. See the [changelog](https://authendpoints.harten.id/changelog) for the core version this preview targets. Does not use Identity management HTTP APIs.

## Usage

```csharp
using AuthEndpoints.External.OAuth;
using AuthEndpoints.OAuth.GitHub;
using AuthEndpoints.OAuth.Google;

builder.Services.AddExternalAuthEndpoints<AppUser>(o =>
{
    o.RequireVerifiedEmail = true;   // default
    o.AutoLinkByEmail = false;       // default; opt in only for verified provider email + confirmed local email
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

Host a page at `ErrorPath`. Login and link failures clear the `Identity.External` cookie before redirecting there.

## Completers

| Type | Behavior |
|------|----------|
| `CookieExternalLoginCompleter<TUser>` (default) | Identity cookie via `SignInAsync` + clear External scheme + redirect |
| `JwtExternalLoginCompleter<TUser>` | Refresh cookie + clear External + redirect (client uses JWT refresh for access token) |

Cookie completion follows Identity UI: it signs the user in directly and does not run the two-factor challenge.

## Docs

See [External OAuth](https://authendpoints.harten.id/modules/external-oauth).
