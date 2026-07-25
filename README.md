# AuthEndpoints
[![nuget](https://img.shields.io/nuget/v/AuthEndpoints?label=version&logo=NuGet&style=flat-square)](https://www.nuget.org/packages/AuthEndpoints/)
[![issues](https://img.shields.io/github/issues/madeyoga/AuthEndpoints?color=blue&logo=github&style=flat-square)](https://github.com/madeyoga/AuthEndpoints/issues)
[![downloads](https://img.shields.io/nuget/dt/AuthEndpoints?color=blue&style=flat-square&logo=nuget)](https://www.nuget.org/packages/AuthEndpoints/)
![workflow](https://github.com/madeyoga/AuthEndpoints/actions/workflows/dotnet.yml/badge.svg)
[![license](https://img.shields.io/github/license/madeyoga/AuthEndpoints?color=blue&style=flat-square&logo=github)](https://github.com/madeyoga/AuthEndpoints/blob/main/LICENSE)

A simple auth library for ASP.NET Core. AuthEndpoints provides minimal API endpoints for registration, email verification, password reset, login/logout, 2FA, JWT, and passkeys (WebAuthn).

## Endpoints

- **Opinionated bundle** (`AddAuthEndpoints` / `UseAuthEndpoints` / `MapAuthEndpoints`)
  - Identity management + cookie sign-in at `/identity` + passkeys at `/account` by default
  - Optional JWT via `Jwt.Enabled`
  - Secure Identity defaults, antiforgery, ReAuth, rate limiting
- **Identity management** (`MapIdentityManagementApi`) — register, confirm/resend, forgot/reset, manage, ReAuth
- **Cookie / Bearer sign-in** (`MapCookieAuthEndpoints` / `MapBearerAuthEndpoints`) — login stacks
- **Simple JWT** (`MapJwtAuthEndpoints`) — create, refresh, verify, logout
- **Passkeys** (`MapPasskeyEndpoints`)

## Installing via NuGet

```
dotnet add package AuthEndpoints --version 3.0.0-rc.1
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
app.MapAuthEndpoints<AppUser>(); // /identity (management + cookie) + /account (passkeys)

app.Run();
```

Use HTTPS in Production. The facade fails startup in Production if `Passkeys.ServerDomain` is missing (when passkeys are enabled) or if no real `IEmailSender<TUser>` is registered.

### Enable JWT (facade opt-in)

```cs
builder.Services.AddAuthEndpoints<AppUser, AppDbContext>(o =>
{
    o.Passkeys.ServerDomain = "example.com";
    o.Jwt.Enabled = true;
    o.Jwt.Path = "/auth";
    o.Jwt.Configure = jwt =>
    {
        jwt.Issuer = "https://example.com";
        jwt.Audience = "https://example.com";
        jwt.SigningOptions.SymmetricKey = builder.Configuration["Jwt:SymmetricKey"];
    };
});
```

### Reauthentication (step-up)

Mapped with Identity management:

1. `GET /identity/manage/authMethods`
2. `POST /identity/confirmIdentity` with exactly one of: `password`, `twoFactorCode`, `twoFactorRecoveryCode`, `credentialJson`
3. Cookie clients receive an `AuthEndpoints.ReAuth` cookie; API clients also get `reauthToken` for the `X-AuthEndpoints-Reauth` header

### Passkey passwordless flow

1. `POST /account/passkeys/register/options` with `{ "email": "..." }`
2. Browser `navigator.credentials.create(...)`
3. `POST /account/passkeys/register` with `{ "email": "...", "credentialJson": "..." }`

## Advanced composition

Compose modules yourself when you need bearer Identity, custom paths, or JWT-only:

```cs
builder.Services
    .AddIdentityApiEndpoints<AppUser>(o =>
    {
        o.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
    })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAntiforgery();
builder.Services.AddCookieAuthEndpoints(); // rate limits + ReAuth schemes
builder.Services.AddPasskeyEndpoints();
builder.Services.AddJwtEndpoints<AppUser, AppDbContext>(o =>
{
    o.Issuer = "https://example.com";
    o.Audience = "https://example.com";
    o.SigningOptions.SymmetricKey = builder.Configuration["Jwt:SymmetricKey"];
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.UseAntiforgery();

// Cookie SPA
app.MapGroup("/identity").MapIdentityManagementApi<AppUser>();
app.MapGroup("/identity").MapCookieAuthEndpoints<AppUser>();

// Or Identity bearer
// app.MapGroup("/identity").MapIdentityManagementApi<AppUser>();
// app.MapGroup("/identity").MapBearerAuthEndpoints<AppUser>();

// Or JWT-only (no cookie login)
// app.MapGroup("/account").MapIdentityManagementApi<AppUser>();
// app.MapGroup("/auth").MapJwtAuthEndpoints<AppUser>();

app.MapGroup("/account").MapPasskeyEndpoints<AppUser>();
```

Map management **once** in production hosts. Refresh-token storage uses hashed values with family reuse detection; recreate the `AuthEndpointsRefreshTokens` table if upgrading from plaintext storage.

## Documentations

Documentation is available at [https://madeyoga.github.io/AuthEndpoints/](https://madeyoga.github.io/AuthEndpoints/).
