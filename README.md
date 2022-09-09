# AuthEndpoints
[![nuget](https://img.shields.io/nuget/v/AuthEndpoints?label=version&logo=NuGet&style=flat-square)](https://www.nuget.org/packages/AuthEndpoints/)
[![issues](https://img.shields.io/github/issues/madeyoga/AuthEndpoints?color=blue&logo=github&style=flat-square)](https://github.com/madeyoga/AuthEndpoints/issues)
[![downloads](https://img.shields.io/nuget/dt/AuthEndpoints?color=blue&style=flat-square&logo=nuget)](https://www.nuget.org/packages/AuthEndpoints/)
![workflow](https://github.com/madeyoga/AuthEndpoints/actions/workflows/dotnet.yml/badge.svg)
[![CodeFactor](https://www.codefactor.io/repository/github/madeyoga/authendpoints/badge)](https://www.codefactor.io/repository/github/madeyoga/authendpoints)
[![license](https://img.shields.io/github/license/madeyoga/AuthEndpoints?color=blue&style=flat-square&logo=github)](https://github.com/madeyoga/AuthEndpoints/blob/main/LICENSE)

A simple jwt authentication library for ASP.Net 6. AuthEndpoints library provides a set of Web API controllers and minimal api endpoints to handle basic web & JWT authentication actions such as registration, email verification, reset password, create jwt, etc. It works with [custom identity user model](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/customize-identity-model?view=aspnetcore-6.0#custom-user-data). AuthEndpoints is built with the aim of increasing developer productivity.

## Supported endpoints
- Basic authentication actions:
  - sign-up
  - email verification
  - user profile (retrieving)
  - reset password
  - change password
  - enable 2fa
  - login 2fa
- TokenAuth:
  - Create (login)
  - Destroy (logout)
- Simple JWT:
  - Create (login)
  - Refresh
  - Verify

## Current limitations
- Only works with IdentityUser or custom identity user
- No session based auth support
- 2fa via email

## Installing via NuGet
The easiest way to install AuthEndpoints is via [NuGet](https://www.nuget.org/packages/AuthEndpoints.MinimalApi/)

Install the library using the following .net cli command:

```
dotnet add package AuthEndpoints
```

or in Visual Studio's Package Manager Console, enter the following command:

```
Install-Package AuthEndpoints
```

## Quick start

```cs
// MyDbContext.cs


using AuthEndpoints.SimpleJwt.Core.Models;

public class MyDbContext : DbContext
{
  public DbSet<RefreshToken>? RefreshTokens { get; set; } // <--
  public MyDbContext(DbContextOptions<MyDbContext> options) : base(options) { }
}
```

```cs
// Program.cs


// Required services
builder.Services.AddIdentityCore<IdentityUser>(); // <--

// Add core & basic authentication endpoints
builder.Services.AddAuthEndpointsCore<IdentityUser, MyDbContext>() // <--
                .AddBasicAuthenticationEndpoints()
                .Add2FAEndpoints();

// Add jwt endpoints
builder.Services.AddSimpleJwtEndpoints<IdentityUser, MyDbContext>();

var app = builder.Build();

...

app.UseAuthentication(); // <--
app.UseAuthorization(); // <--

...

app.MapEndpoints(); // <--

app.Run();
```

Checkout [docs](https://madeyoga.github.io/AuthEndpoints/wiki/get-started.html) for more info.

## Documentations
Documentation is available at [https://madeyoga.github.io/AuthEndpoints/](https://madeyoga.github.io/AuthEndpoints/) and in [docs](https://github.com/madeyoga/AuthEndpoints/tree/main/docs) directory.

## Contributing
Your contributions are always welcome! simply send a pull request! The [up-for-grabs](https://github.com/madeyoga/AuthEndpoints/labels/up-for-grabs) label is a great place to start. If you find a flaw, please open an issue or a PR and let's sort things out.

The documentation is far from perfect so every bit of help is more than welcome.
