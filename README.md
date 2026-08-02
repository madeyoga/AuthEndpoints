# AuthEndpoints

[![nuget](https://img.shields.io/nuget/v/AuthEndpoints?label=version&logo=NuGet&style=flat-square)](https://www.nuget.org/packages/AuthEndpoints/)
[![issues](https://img.shields.io/github/issues/madeyoga/AuthEndpoints?color=blue&logo=github&style=flat-square)](https://github.com/madeyoga/AuthEndpoints/issues)
[![downloads](https://img.shields.io/nuget/dt/AuthEndpoints?color=blue&style=flat-square&logo=nuget)](https://www.nuget.org/packages/AuthEndpoints/)
![workflow](https://github.com/madeyoga/AuthEndpoints/actions/workflows/dotnet.yml/badge.svg)
[![license](https://img.shields.io/github/license/madeyoga/AuthEndpoints?color=blue&style=flat-square&logo=github)](https://github.com/madeyoga/AuthEndpoints/blob/main/LICENSE)

AuthEndpoints is an ASP.NET Core library of ready-made auth API endpoints on top of ASP.NET Core Identity. It fits a first-party auth API for web and mobile clients (React, Next.js, Vue, Nuxt, Svelte, native apps, and similar) with email/password, cookies, JWT, and/or passkeys.

- Ready-made endpoints for registration, login, password reset, 2FA, and session/token flows
- Opinionated quick start with `AddAuthEndpoints` / `UseAuthEndpoints` / `MapAuthEndpoints`
- Account lifecycle: register, confirm email, forgot/reset password, manage info and 2FA, step-up ReAuth
- Sign-in stacks you choose: cookie sessions, Identity bearer tokens, or Simple JWT
- Passkeys (WebAuthn) for passwordless register and login
- Built-in hardening: rate limiting, antiforgery, lockout-aware login, hashed JWT refresh tokens with reuse detection
- Optional package [`AuthEndpoints.External.OAuth`](https://madeyoga.github.io/AuthEndpoints/modules/external-oauth) for GitHub/Google OAuth

## Getting started

Requires .NET 10, ASP.NET Core Identity, and EF Core.

```bash
dotnet add package AuthEndpoints --version 3.0.0-rc.3
```

```cs
builder.Services.AddDbContext<AppDbContext>(/* your provider */);

builder.Services.AddAuthEndpoints<AppUser, AppDbContext>(o =>
{
    o.Passkeys.ServerDomain = "example.com"; // required in Production
});

builder.Services.AddTransient<IEmailSender<AppUser>, MyEmailSender>();

var app = builder.Build();

app.UseAuthEndpoints();
app.MapAuthEndpoints<AppUser>();

app.Run();
```

## Documentation

For configuration, composable modules, route tables, and production guidance, see the [AuthEndpoints documentation](https://madeyoga.github.io/AuthEndpoints/).

## Contribute

Issues and pull requests are welcome. Open an issue at [madeyoga/AuthEndpoints](https://github.com/madeyoga/AuthEndpoints/issues) to report bugs or propose changes.

## License

This project is licensed under the [MIT License](LICENSE).
