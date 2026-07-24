# AuthEndpoints
[![nuget](https://img.shields.io/nuget/v/AuthEndpoints?label=version&logo=NuGet&style=flat-square)](https://www.nuget.org/packages/AuthEndpoints/)
[![issues](https://img.shields.io/github/issues/madeyoga/AuthEndpoints?color=blue&logo=github&style=flat-square)](https://github.com/madeyoga/AuthEndpoints/issues)
[![downloads](https://img.shields.io/nuget/dt/AuthEndpoints?color=blue&style=flat-square&logo=nuget)](https://www.nuget.org/packages/AuthEndpoints/)
![workflow](https://github.com/madeyoga/AuthEndpoints/actions/workflows/dotnet.yml/badge.svg)
[![CodeFactor](https://codefactor.io/repository/github/madeyoga/authendpoints/badge)](https://www.codefactor.io/repository/github/madeyoga/authendpoints)
[![license](https://img.shields.io/github/license/madeyoga/AuthEndpoints?color=blue&style=flat-square&logo=github)](https://github.com/madeyoga/AuthEndpoints/blob/main/LICENSE)

A simple auth library for ASP.NET Core. AuthEndpoints provides minimal API endpoints for registration, email verification, password reset, login/logout, 2FA, JWT, and passkeys (WebAuthn).

![swagger_authendpoints](https://res.cloudinary.com/dhqbr2d4l/image/upload/v1760597936/chrome_2025-10-16_14-55-57_g5qvtc.jpg)

## Endpoints

- **Cookie / Bearer Identity** (`MapCookieAuthEndpoints` / `MapBearerAuthEndpoints`)
  - register, confirm email, login, logout
  - forgot / reset password, account info
  - 2FA manage
  - reauth (`confirmIdentity`, `confirmIdentity/passkeyOptions`, `manage/authMethods`)
- **Simple JWT** (`MapJwtAuthEndpoints`)
  - create (login), refresh, verify
  - when 2FA is enabled, `create` requires `twoFactorCode` or `twoFactorRecoveryCode`
- **Passkeys** (`MapPasskeyEndpoints`)
  - creation / request options
  - passwordless register + login
  - list / add / rename / delete credentials

## Installing via NuGet

```
dotnet add package AuthEndpoints --version 3.0.0-alpha.10
```

## Quick start

```cs
// Program.cs
builder.Services
    .AddIdentityApiEndpoints<AppUser>(o =>
    {
        o.Stores.SchemaVersion = IdentitySchemaVersions.Version3; // required for passkeys
    })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

builder.Services.Configure<IdentityPasskeyOptions>(options =>
{
    options.ServerDomain = "example.com"; // your relying-party domain
});

builder.Services.AddJwtEndpoints<AppUser, AppDbContext>(options =>
{
    // Required: set a stable secret (do not leave unset).
    options.SigningOptions.SymmetricKey = builder.Configuration["Jwt:SymmetricKey"];
});

builder.Services.AddAntiforgery();
builder.Services.AddCookieAuthEndpoints(); // ReAuth + login rate limits
builder.Services.AddPasskeyEndpoints();    // passkey rate limits (+ ReAuth if not already added)

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.UseAntiforgery();

app.MapGroup("/identity").MapCookieAuthEndpoints<AppUser>();
app.MapGroup("/auth").MapJwtAuthEndpoints<AppUser>();
app.MapGroup("/account").MapPasskeyEndpoints<AppUser>();

app.Run();
```

### Passkey passwordless flow

1. `POST /account/passkeys/register/options` with `{ "email": "..." }` → WebAuthn creation options  
2. Browser `navigator.credentials.create(...)`  
3. `POST /account/passkeys/register` with `{ "email": "...", "credentialJson": "..." }` → account + passkey  

Sign-in after register/login matches Identity password login:

- Default (no query flags): Identity **bearer** tokens (`AccessTokenResponse`)
- `?useCookies=true`: persistent application cookie
- `?useSessionCookies=true`: session application cookie

CSRF (antiforgery) is required on these endpoints for anonymous and cookie-authenticated clients. Bearer-only authenticated calls (Identity bearer or JWT `Bearer`) may omit the CSRF token on endpoints that use `RequireAntiforgery`. This does **not** issue Simple JWT — call `/auth/create` separately if you use `MapJwtAuthEndpoints`.

For an existing signed-in user (with reauth): `POST /account/passkeys/creationOptions` then `POST /account/passkeys`.

### Reauthentication (step-up)

Mapped automatically with cookie/bearer Identity groups:

1. `GET /identity/manage/authMethods` — which proofs the user can use (`password`, `authenticator`, `recoveryCodes`, `passkeys`)
2. For passkey step-up: `POST /identity/confirmIdentity/passkeyOptions` → WebAuthn `get` → `POST /identity/confirmIdentity` with `{ "credentialJson": "..." }`
3. Or confirm with exactly one of: `password`, `twoFactorCode`, `twoFactorRecoveryCode`, `credentialJson`

Success issues a short-lived `AuthEndpoints.ReAuth` cookie (5 minutes) for endpoints that use `RequireReauth()`.

## Documentations

Documentation is available at [https://madeyoga.github.io/AuthEndpoints/](https://madeyoga.github.io/AuthEndpoints/).
