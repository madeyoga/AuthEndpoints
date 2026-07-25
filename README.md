# AuthEndpoints
[![nuget](https://img.shields.io/nuget/v/AuthEndpoints?label=version&logo=NuGet&style=flat-square)](https://www.nuget.org/packages/AuthEndpoints/)
[![issues](https://img.shields.io/github/issues/madeyoga/AuthEndpoints?color=blue&logo=github&style=flat-square)](https://github.com/madeyoga/AuthEndpoints/issues)
[![downloads](https://img.shields.io/nuget/dt/AuthEndpoints?color=blue&style=flat-square&logo=nuget)](https://www.nuget.org/packages/AuthEndpoints/)
![workflow](https://github.com/madeyoga/AuthEndpoints/actions/workflows/dotnet.yml/badge.svg)
[![license](https://img.shields.io/github/license/madeyoga/AuthEndpoints?color=blue&style=flat-square&logo=github)](https://github.com/madeyoga/AuthEndpoints/blob/main/LICENSE)

AuthEndpoints is an ASP.NET Core library that gives you ready-made auth API endpoints on top of ASP.NET Core Identity. 
It is a good fit for a single-backend API serving a SPA or frontend app with first-party email/password, cookies, JWT, and/or passkeys - not for running a full OAuth/OIDC identity provider. 
Instead of wiring registration, login, password reset, 2FA, and session/token flows yourself, you map a small set of composable endpoints (or use the opinionated facade) and ship.

It provides a number of features that make it easy to build first-party auth fast, keep defaults safer for production, and compose only what you need, including:

- **Opinionated quick start** - `AddAuthEndpoints` / `UseAuthEndpoints` / `MapAuthEndpoints` for cookie Identity + passkeys with secure defaults
- **Account lifecycle** - register, email confirm/resend, forgot/reset password, manage info and 2FA, step-up ReAuth
- **Sign-in stacks you choose** - cookie sessions, Identity bearer tokens, or simple JWT (create / refresh / verify / logout)
- **Passkeys (WebAuthn)** - passwordless register and login endpoints
- **Built-in hardening** - rate limiting, antiforgery for cookie flows, lockout-aware login, hashed JWT refresh tokens with reuse detection

## Installing via NuGet

```
dotnet add package AuthEndpoints --version 3.0.0-rc.2
```

**Requirements:** .NET 10, ASP.NET Core Identity, and EF Core for the user store.

## Quick start (recommended)

Your frontend is a separate SPA that calls these routes on the ASP.NET Core API.

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

### Default routes (facade)

| Area | Path prefix | Main routes |
| --- | --- | --- |
| Management + cookie | `/identity` | `register`, `login`, `logout`, `csrfToken`, confirm/forgot/reset, `manage/*`, `confirmIdentity` |
| Passkeys | `/account` | passkeys register/login options + complete |
| JWT (if enabled) | `/auth` | `create`, `refresh`, `verify`, `logout`, `csrfToken` |

### SPA usage notes

**Cookie stack**

- Send cookies with credentials (`credentials: "include"` / Axios `withCredentials`).
- Call `GET /identity/csrfToken`, then send the token as `RequestVerificationToken` on unsafe methods (`POST` / `PUT` / `PATCH` / `DELETE`).

**JWT stack** (when enabled)

- `POST /auth/create` returns an access token; send it as `Authorization: Bearer …`.
- Refresh token is an HttpOnly cookie; `POST /auth/refresh` and `POST /auth/logout` need CSRF (`GET /auth/csrfToken` + `RequestVerificationToken`).

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

Mapped with Identity management under `/identity`:

1. `GET /identity/manage/authMethods`
2. `POST /identity/confirmIdentity` with exactly one of: `password`, `twoFactorCode`, `twoFactorRecoveryCode`, `credentialJson`
3. Cookie clients receive an `AuthEndpoints.ReAuth` cookie; API clients also get `reauthToken` for the `X-AuthEndpoints-Reauth` header

### Passkey passwordless flow

1. `POST /account/passkeys/register/options` with `{ "email": "..." }`
2. Browser `navigator.credentials.create(...)`
3. `POST /account/passkeys/register` with `{ "email": "...", "credentialJson": "..." }`

## Advanced composition

Compose modules yourself when you need bearer Identity, custom paths, or JWT-only. Map management **once** in production hosts.

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

## Production checklist

- Use **HTTPS**
- Register a real **`IEmailSender<TUser>`** (Identity's no-op sender is rejected in Production)
- Set **`Passkeys.ServerDomain`** when passkeys are enabled
- For JWT: non-default **issuer/audience** and a symmetric key of at least **256 bits** (32 UTF-8 bytes) in Production
- Recreate the **`AuthEndpointsRefreshTokens`** table if upgrading from plaintext refresh-token storage (tokens are stored hashed with family reuse detection)
