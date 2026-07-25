# AuthEndpoints
[![nuget](https://img.shields.io/nuget/v/AuthEndpoints?label=version&logo=NuGet&style=flat-square)](https://www.nuget.org/packages/AuthEndpoints/)
[![issues](https://img.shields.io/github/issues/madeyoga/AuthEndpoints?color=blue&logo=github&style=flat-square)](https://github.com/madeyoga/AuthEndpoints/issues)
[![downloads](https://img.shields.io/nuget/dt/AuthEndpoints?color=blue&style=flat-square&logo=nuget)](https://www.nuget.org/packages/AuthEndpoints/)
![workflow](https://github.com/madeyoga/AuthEndpoints/actions/workflows/dotnet.yml/badge.svg)
[![license](https://img.shields.io/github/license/madeyoga/AuthEndpoints?color=blue&style=flat-square&logo=github)](https://github.com/madeyoga/AuthEndpoints/blob/main/LICENSE)

A simple auth library for ASP.NET Core. AuthEndpoints provides minimal API endpoints for registration, email verification, password reset, login/logout, 2FA, JWT, and passkeys (WebAuthn).

![swagger_authendpoints](https://res.cloudinary.com/dhqbr2d4l/image/upload/v1760597936/chrome_2025-10-16_14-55-57_g5qvtc.jpg)

## Endpoints

- **Opinionated bundle** (`AddAuthEndpoints` / `UseAuthEndpoints` / `MapAuthEndpoints`)
  - Cookie Identity at `/identity` + passkeys at `/account` by default
  - Secure Identity defaults, antiforgery, ReAuth, rate limiting
- **Cookie / Bearer Identity** (`MapCookieAuthEndpoints` / `MapBearerAuthEndpoints`) — advanced composition
  - register, confirm email, login, logout
  - forgot / reset password, account info, 2FA, reauth
- **Simple JWT** (`MapJwtAuthEndpoints`) — advanced composition
- **Passkeys** (`MapPasskeyEndpoints`) — advanced composition

## Installing via NuGet

```
dotnet add package AuthEndpoints --version 3.0.0-alpha.11
```

## Quick start (recommended)

```cs
// Program.cs
builder.Services.AddDbContext<AppDbContext>(/* your provider */);

builder.Services.AddAuthEndpoints<AppUser, AppDbContext>(o =>
{
    o.Passkeys.ServerDomain = "example.com"; // required in Production
});

// Required in Production (Identity's no-op sender is rejected).
builder.Services.AddTransient<IEmailSender<AppUser>, MyEmailSender>();

var app = builder.Build();

app.UseAuthEndpoints(); // authentication, authorization, rate limiting, antiforgery
app.MapAuthEndpoints<AppUser>(); // /identity (cookie) + /account (passkeys)

app.Run();
```

Use HTTPS in Production. The facade fails startup in Production if `Passkeys.ServerDomain` is missing (when passkeys are enabled) or if no real `IEmailSender<TUser>` is registered.

### Reauthentication (step-up)

Mapped with cookie Identity:

1. `GET /identity/manage/authMethods`
2. `POST /identity/confirmIdentity` with exactly one of: `password`, `twoFactorCode`, `twoFactorRecoveryCode`, `credentialJson`
3. Cookie clients receive an `AuthEndpoints.ReAuth` cookie; API clients also get `reauthToken` for the `X-AuthEndpoints-Reauth` header

### Passkey passwordless flow

1. `POST /account/passkeys/register/options` with `{ "email": "..." }`
2. Browser `navigator.credentials.create(...)`
3. `POST /account/passkeys/register` with `{ "email": "...", "credentialJson": "..." }`

## Advanced composition

Compose modules yourself when you need bearer Identity, custom paths, or JWT:

```cs
builder.Services
    .AddIdentityApiEndpoints<AppUser>(o =>
    {
        o.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
    })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAntiforgery();
builder.Services.AddCookieAuthEndpoints();
builder.Services.AddPasskeyEndpoints();
builder.Services.AddJwtEndpoints<AppUser, AppDbContext>(o =>
{
    o.SigningOptions.SymmetricKey = builder.Configuration["Jwt:SymmetricKey"];
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.UseAntiforgery();

app.MapGroup("/identity").MapCookieAuthEndpoints<AppUser>();
app.MapGroup("/identity/bearer").MapBearerAuthEndpoints<AppUser>();
app.MapGroup("/account").MapPasskeyEndpoints<AppUser>();
app.MapGroup("/auth").MapJwtAuthEndpoints<AppUser>();
```

## Documentations

Documentation is available at [https://madeyoga.github.io/AuthEndpoints/](https://madeyoga.github.io/AuthEndpoints/).
