# AuthEndpoints
[![nuget](https://img.shields.io/nuget/v/AuthEndpoints?label=version&logo=NuGet&style=flat-square)](https://www.nuget.org/packages/AuthEndpoints/)
[![issues](https://img.shields.io/github/issues/madeyoga/AuthEndpoints?color=blue&logo=github&style=flat-square)](https://github.com/madeyoga/AuthEndpoints/issues)
[![downloads](https://img.shields.io/nuget/dt/AuthEndpoints?color=blue&style=flat-square&logo=nuget)](https://www.nuget.org/packages/AuthEndpoints/)
![workflow](https://github.com/madeyoga/AuthEndpoints/actions/workflows/dotnet.yml/badge.svg)
[![CodeFactor](https://www.codefactor.io/repository/github/madeyoga/authendpoints/badge)](https://www.codefactor.io/repository/github/madeyoga/authendpoints)
[![license](https://img.shields.io/github/license/madeyoga/AuthEndpoints?color=blue&style=flat-square&logo=github)](https://github.com/madeyoga/AuthEndpoints/blob/main/LICENSE)

A simple jwt authentication library for ASP.Net 6. AuthEndpoints library provides a set of Web API controllers and minimal api endpoints to handle basic web & JWT authentication actions such as registration, email verification, reset password, create jwt, etc. It works with [custom identity user model](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/customize-identity-model?view=aspnetcore-6.0#custom-user-data). AuthEndpoints is built with the aim of increasing developer productivity.

## Features
- Supported endpoints:
  - sign-up
  - sign-in (create jwt)
  - email verification
  - refresh jwt
  - verify jwt
  - user profile (retrieving)
  - reset password
  - change password
  - enable 2fa & login 2fa (via email)
- JWT support
- Works with a symmetric key (shared secret) or asymmetric keys (the private key of a private–public pair).
- Works with custom identity user

## Current limitations
- Only works with IdentityUser or custom identity user
- No session based auth support
- 2fa via email

## Installing via NuGet
The easiest way to install AuthEndpoints is via [NuGet](https://www.nuget.org/packages/AuthEndpoints.MinimalApi/)

Install the library using the following .net cli command:

```
dotnet add package AuthEndpoints.MinimalApi
```

or in Visual Studio's Package Manager Console, enter the following command:

```
Install-Package AuthEndpoints.MinimalApi
```

## Quick start

Add the required identity services:

```cs
builder.Services
  .AddIdentityCore<MyCustomIdentityUser>() // <-- or `AddIdentity<,>`
  .AddEntityFrameworkStores<MyDbContext>() // <-- required
  .AddDefaultTokenProviders();             // <-- required
```

Next, let's add auth endpoints services and jwt bearer authentication scheme:

```cs
builder.Services
  // When no options provided, 
  // AuthEndpoints will automatically create a secret key and use single security key
  // for each access jwt and refresh jwt (symmetric encryption).
  // Secrets will be created under `keys/` directory.
  .AddAuthEndpoints<string, MyCustomIdentityUser>() // <TUserKey, TUser>
  .AddAllEndpointDefinitions() // Add endpoint definitions
  .AddJwtBearerAuthScheme();
```

then finally, call `app.MapAuthEndpoints()` before `app.Run()`:

```cs

var app = builder.Build();

...

app.UseAuthentication();
app.UseAuthorization();

...

app.MapAuthEndpoints(); // <--

app.Run();
```

Checkout [docs](https://madeyoga.github.io/AuthEndpoints/wiki/get-started.html) for more info.

## Documentations
Documentation is available at [https://madeyoga.github.io/AuthEndpoints/](https://madeyoga.github.io/AuthEndpoints/) and in [docs](https://github.com/madeyoga/AuthEndpoints/tree/main/docs) directory.

## Contributing
Your contributions are always welcome! simply send a pull request! The [up-for-grabs](https://github.com/madeyoga/AuthEndpoints/labels/up-for-grabs) label is a great place to start. If you find a flaw, please open an issue or a PR and let's sort things out.

The documentation is far from perfect so every bit of help is more than welcome.
