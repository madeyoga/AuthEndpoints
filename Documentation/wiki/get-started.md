# Getting started

Follow steps below to install and use AuthEndpoints.

## Create a project

Create an empty ASP.NET Core project

```
dotnet new web -n MyNewWebApp
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

Edit `Program.cs`, then add auth endpoints services and jwt bearer authentication scheme:

```cs
var accessValidationParam = new TokenValidationParameters()
{
  IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("1234567890qwerty")),
  ValidIssuer = "https://localhost:8000",
  ValidAudience = "https://localhost:8000",
  ValidateIssuerSigningKey = true,
  ClockSkew = TimeSpan.Zero,
};

services.AddAuthEndpoints<string, IdentityUser>(options => 
{
  AccessSigningOptions = new JwtSigningOptions()
  {
    // SigningKey for verifying jwts will also be used for signing jwts
    SigningKey = accessValidationParam.IssuerSigningKey,
    Algorithm = SecurityAlgorithms.HmacSha256,
    ExpirationMinutes = 120, // Expires in 2 hours
  },
  RefreshSigningOptions = new JwtSigningOptions()
  {
    SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("qwerty0987654321")),
    Algorithm = SecurityAlgorithms.HmacSha256,
    ExpirationMinutes = 2880, // Expires in 2 days
  },
  Audience = "https://localhost:8000",
  Issuer = "https://localhost:8000",
})
.AddJwtBearerAuthScheme();
```

## Add Base Authentication Endpoints

Create a new directory called `Controllers` then create a new controller called `MyBaseAuthController.cs` then add the following:

```cs
public class MyBaseAuthController: BaseEndpointsController<string, IdentityUser>
{}
```

See what endpoints included in [BaseEndpointsController](base-endpoints.md)

## Add Jwt Endpoints

Create a new controller called `MyJwtController.cs` then add the following:

```cs
public class MyJwtController : JwtController<string, IdentityUser>
{}
```

See what endpoints included in [JwtController](jwt-endpoints.md)
