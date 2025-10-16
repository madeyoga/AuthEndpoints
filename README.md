# AuthEndpoints
[![nuget](https://img.shields.io/nuget/v/AuthEndpoints?label=version&logo=NuGet&style=flat-square)](https://www.nuget.org/packages/AuthEndpoints/)
[![issues](https://img.shields.io/github/issues/madeyoga/AuthEndpoints?color=blue&logo=github&style=flat-square)](https://github.com/madeyoga/AuthEndpoints/issues)
[![downloads](https://img.shields.io/nuget/dt/AuthEndpoints?color=blue&style=flat-square&logo=nuget)](https://www.nuget.org/packages/AuthEndpoints/)
![workflow](https://github.com/madeyoga/AuthEndpoints/actions/workflows/dotnet.yml/badge.svg)
[![CodeFactor](https://www.codefactor.io/repository/github/madeyoga/authendpoints/badge)](https://www.codefactor.io/repository/github/madeyoga/authendpoints)
[![license](https://img.shields.io/github/license/madeyoga/AuthEndpoints?color=blue&style=flat-square&logo=github)](https://github.com/madeyoga/AuthEndpoints/blob/main/LICENSE)

A simple auth library for aspnetcore. AuthEndpoints library provides a set of minimal api endpoints to handle basic & authentication actions such as registration, email verification, reset password, login, logout, etc.

![swagger_authendpoints](https://res.cloudinary.com/dhqbr2d4l/image/upload/v1760597936/chrome_2025-10-16_14-55-57_g5qvtc.jpg)

## Endpoints
- Identity api:
  - sign-up
  - email verification
  - account info
  - reset password
  - forgot password
  - enable 2fa
  - login 
  - logout 
  - confirm identity
- Simple JWT:
  - Create (login)
  - Refresh
  - Verify

## Installing via NuGet
The easiest way to install AuthEndpoints is via [NuGet](https://www.nuget.org/packages/AuthEndpoints/)

Install the library using the following dotnet cli command:

```
dotnet add package AuthEndpoints --version 3.0.0-alpha.1
```

or in Visual Studio's Package Manager Console, enter the following command:

```
Install-Package AuthEndpoints
```

## Quick start

```cs
// Program.cs

builder.Services
    .AddIdentityApiEndpoints<AppUser>() // <--
    .AddRoles<AppRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

var app = builder.Build();

...

app.UseAuthentication(); // <--
app.UseAuthorization(); // <--

...

app.MapAuthEndpointsIdentityApi(); // <--

app.Run();
```

## Documentations
Documentation is available at [https://madeyoga.github.io/AuthEndpoints/](https://madeyoga.github.io/AuthEndpoints/) and in [docs](https://github.com/madeyoga/AuthEndpoints/tree/main/docs) directory.
