<p align="center">
  <img src="https://raw.githubusercontent.com/madeyoga/AuthEndpoints/main/.github/assets/banner.png" alt="AuthEndpoints: authentication library for ASP.NET Core Identity" width="100%">
</p>

# AuthEndpoints

[![nuget](https://img.shields.io/nuget/v/AuthEndpoints?label=version&logo=NuGet&style=flat-square)](https://www.nuget.org/packages/AuthEndpoints/)
[![oauth](https://img.shields.io/nuget/vpre/AuthEndpoints.External.OAuth?label=External.OAuth&logo=NuGet&style=flat-square)](https://www.nuget.org/packages/AuthEndpoints.External.OAuth/)
[![issues](https://img.shields.io/github/issues/madeyoga/AuthEndpoints?color=blue&logo=github&style=flat-square)](https://github.com/madeyoga/AuthEndpoints/issues)
[![downloads](https://img.shields.io/nuget/dt/AuthEndpoints?color=blue&style=flat-square&logo=nuget)](https://www.nuget.org/packages/AuthEndpoints/)
![workflow](https://github.com/madeyoga/AuthEndpoints/actions/workflows/dotnet.yml/badge.svg)
[![license](https://img.shields.io/github/license/madeyoga/AuthEndpoints?color=blue&style=flat-square&logo=github)](https://github.com/madeyoga/AuthEndpoints/blob/main/LICENSE)

AuthEndpoints is an authentication library for ASP.NET Core Identity that gives you ready-made login, register, refresh, 2FA, passkey and password reset endpoints. It is for your own web and mobile clients. You keep ASP.NET Core Identity, your user type, and your database.

- Cookie sessions for browser apps, and JWT bearer sessions for token clients, including refresh
- Two-factor authentication with authenticator codes and recovery codes
- Passkeys (WebAuthn) for passwordless register and login
- Email-code sign-in. Account creation and magic links stay off until you enable them
- Password facade with `AddPasswordAuth`, `UseAuthEndpoints`, and `MapPasswordAuth`. Cookie is the default session. Set `AuthEndpointsSession.Jwt` for a JWT bearer session
- Account lifecycle: register, confirm email, forgot and reset password, manage account info, and step-up ReAuth
- Hardening on the routes: rate limits, antiforgery, lockout-aware login, and hashed JWT refresh tokens with reuse detection
- GitHub and Google sign-in through `AuthEndpoints.OAuth.GitHub` and `AuthEndpoints.OAuth.Google`. The endpoints live in the core package. Compose them. The password facade does not map them. See [External OAuth](https://authendpoints.harten.id/modules/external-oauth/)

## Why not MapIdentityApi?

`MapIdentityApi` maps one fixed set of Identity API endpoints. AuthEndpoints covers register, login, refresh, and password reset, and adds cookie sessions, JWT bearer sessions, passkeys, logout, and a choice of which routes to map.

The route-by-route comparison is in [AuthEndpoints compared with MapIdentityApi](https://authendpoints.harten.id/concepts/compare/).

## Getting started

Requires .NET 10, ASP.NET Core Identity, and EF Core.

```bash
dotnet add package AuthEndpoints
```

```cs
builder.Services.AddDbContext<AppDbContext>(/* your provider */);

builder.Services.AddPasswordAuth<AppUser, AppDbContext>(o =>
{
    o.Passkeys.ServerDomain = "example.com"; // omit to leave passkeys off
});

builder.Services.AddTransient<IEmailSender<AppUser>, MyEmailSender>();

var app = builder.Build();

app.UseAuthEndpoints();
app.MapPasswordAuth<AppUser>();

app.Run();
```

## Documentation

Guides, route tables, and production setup are at [https://authendpoints.harten.id](https://authendpoints.harten.id).

## AI agents

Add the coding-agent skill from this repository:

```bash
npx skills add madeyoga/AuthEndpoints
```

See [AI agents](https://authendpoints.harten.id/getting-started/ai-agents/).

## Contribute

Issues and pull requests are welcome. Open an issue at [madeyoga/AuthEndpoints](https://github.com/madeyoga/AuthEndpoints/issues) to report bugs or propose changes.

## License

This project is licensed under the [MIT License](https://github.com/madeyoga/AuthEndpoints/blob/main/LICENSE).
