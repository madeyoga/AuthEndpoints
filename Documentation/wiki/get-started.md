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

First, let's create `MyDbContext`:

```cs
// Data/MyDbContext.cs
using AuthEndpoints.Core.Models;
using Microsoft.EntityFrameworkCore;

namespace MyNewWebApp.Data;

public class MyDbContext : DbContext
{
  DbSet<IdentityUser>? Users { get; set; }
  DbSet<RefreshToken>? RefreshTokens { get; set; }

  public MyDbContext(DbContextOptions<MyDbContext> options) : base(options) { }
}
```

Configure database provider for `MyDbContext` and then add the required identity services:

```cs
// Program.cs

builder.Services.AddDbContext<MyDbContext>(options => 
{ 
  // Configure database provider for `MyDbContext`
});

builder.Services
  .AddIdentityCore<IdentityUser>()         // <-- or `AddIdentity<,>`
  .AddEntityFrameworkStores<MyDbContext>() // <--
  .AddDefaultTokenProviders();             // <--
```

Next, let's add auth endpoints services and jwt bearer authentication scheme:

```cs
// Program.cs

builder.Services
  // When no options provided, 
  // AuthEndpoints will automatically create a secret key and use single security key
  // for each access jwt and refresh jwt (symmetric encryption).
  // Secrets will be created under `keys/` directory.
  .AddAuthEndpointsCore<IdentityUser>() // <TUserKey, TUser>
  .AddRefreshTokenStore<MyDbContext>() // <-- 
  .AddAuthEndpointDefinitions(); // Add endpoint definitions
```

then finally, call `app.MapAuthEndpoints()` before `app.Run()`:

```cs
// Program.cs

...

var app = builder.Build();

...

app.UseAuthentication();
app.UseAuthorization();

...

app.MapEndpoints(); // <--

app.Run();
```

Run it and you should see auth endpoints available on swagger docs!

![authendpoints swagger](https://imgur.com/YT7htMW.png "authendpoints swagger")


## Full Source Code

```cs
// Program.cs

using AuthEndpoints.Core;
using AuthEndpoints.Infrastructure;
using AuthEndpoints.MinimalApi;
using Microsoft.AspNetCore.Identity;
using MyNewWebApp.Data;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<MyDbContext>(options => 
{ 
    // Configure database provider for `MyDbContext` here
    // ...
});

builder.Services
    .AddIdentityCore<IdentityUser>()
    .AddEntityFrameworkStores<MyDbContext>()
    .AddDefaultTokenProviders();

builder.Services
  // When no options provided, 
  // AuthEndpoints will automatically create a secret key and use single security key
  // for each access jwt and refresh jwt (symmetric encryption).
  // Secrets will be created under `keys/` directory.
  .AddAuthEndpointsCore<IdentityUser>() // <-- 
  .AddRefreshTokenStore<MyDbContext>() // <-- 
  .AddAuthEndpointDefinitions(); // Add endpoint definitions

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.MapEndpoints(); // <-- Map minimal api endpoints

app.Run();
```


## Available Endpoints
Checkout endpoints definition [docs](endpoints/definitions.md)

- [Basic authentication endpoints](endpoints/basic-authentication.md)
- [JWT endpoints](endpoints/jwt.md)
- [2FA endpoints](endpoints/2fa.md)
