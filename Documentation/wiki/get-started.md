# Getting started

Follow steps below to install and use AuthEndpoints.

## Create a project

Create a web api ASP.NET Core project

```
dotnet new webapi -n MyNewWebApp
```


## Install nuget package
Install the library using the following .net cli command:

```
dotnet add package AuthEndpoints
```

or with nuget package manager:

```
Install-Package AuthEndpoints
```


## Quick Start

Edit `Program.cs`, Add the required identity services:

```cs
builder.Services.AddAuthorization();
builder.Services.AddDbContext<MyDbContext>(options => { });
builder.Services.AddIdentityCore<MyCustomIdentityUser>()
  .AddEntityFrameworkStores<MyDbContext>()
  .AddDefaultTokenProviders();
```

then add auth endpoints services and jwt bearer authentication scheme:

```cs
builder.Services
  .AddAuthEndpoints<string, MyCustomIdentityUser>() // Use the default and minimum config
  .AddJwtBearerAuthScheme();
```

then call `UseAuthentication` and `UseAuthorization`:

```cs
...

var app = builder.Build();

...

app.UseAuthentication();
app.UseAuthorization();

...

app.Run();
```

## Map endpoints using the controller

### Add Base Authentication Endpoints

Create a new controller called `MyBaseAuthController.cs` then add the following:

```cs
public class MyBaseAuthController : BasicAuthenticationController<string, MyCustomIdentityUser>
{}
```

See what endpoints included in [BaseEndpointsController](base-endpoints.md)

### Add Jwt Endpoints

Create a new controller called `MyJwtController.cs` then add the following:

```cs
public class MyJwtController : JwtController<string, MyCustomIdentityUser>
{}
```

See what endpoints included in [JwtController](jwt-endpoints.md)

## Map endpoints using the minimal api

Install [AuthEndpoints.MinimalApi](https://www.nuget.org/packages/AuthEndpoints.MinimalApi) package and add endpoint definitions:

```cs
builder.Services
  .AddAuthEndpoints<string, MyCustomIdentityUser>()
  .AddAllEndpointDefinitions() // Add endpoint definitions
  .AddJwtBearerAuthScheme();
```

then call `app.MapAuthEndpoints()` before `app.Run()`:

```cs
...

var app = builder.Build();

...

app.UseAuthentication();
app.UseAuthorization();

...

app.MapAuthEndpoints();

app.Run();
```

## Available Endpoints

- `/users`
- `/users/me`
- `/users/delete`
- `/users/verify_email`
- `/users/verify_email_confirm`
- `/users/set_password`
- `/users/reset_password`
- `/users/reset_password_confirm`
- `/users/enable_2fa`
- `/users/enable_2fa_confirm`
- `/users/two_step_verification_login`
- `/users/two_step_verification_confirm`
- `/jwt/create`
- `/jwt/refresh`
- `/jwt/verify`


Checkout documentation for more details:

- [Basic authentication endpoints](/wiki/base-endpoints.html)
- [JWT endpoints](/wiki/jwt-endpoints.html)
- [2FA endpoints](/wiki/2fa-endpoints.html)
