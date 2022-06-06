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

Edit `Program.cs`, Add required identity services:

```cs
builder.Services.AddIdentity<MyCustomIdentityUser>()
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

app.UseAuthentication();
app.UseAuthorization();

...

app.Run();
```

## Add Base Authentication Endpoints

Create a new controller called `MyBaseAuthController.cs` then add the following:

```cs
public class MyBaseAuthController : BaseEndpointsController<string, IdentityUser>
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
