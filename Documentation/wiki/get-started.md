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
services.AddAuthEndpoints<string, IdentityUser>(options => 
{
  // These secrets will be used for signing jwts
  options.AccessSecret = "...",
  options.RefreshSecret = "...",
  options.Issuer = "...",
  options.Audience = "...",
  options.AccessExpirationMinutes = 120; // Access token expires in 2 hours
  options.AccessExpirationMinutes = 2880; // Refresh token expires in 2 days

  // These validation parameters will be used for verifying/validating jwts
  options.AccessValidationParameters = new TokenValidationParameters()
  { ... }
  options.RefreshValidationParameters = new TokenValidationParameters()
  { ... }
}).AddJwtBearerAuthScheme(AccessValidationParameters);
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
