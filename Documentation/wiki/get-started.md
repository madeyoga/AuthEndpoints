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
dotnet add package AuthEndpoints.MinimalApi
```

or with nuget package manager:

```
Install-Package AuthEndpoints.MinimalApi
```


## Quick Start

First, let's create `MyDbContext`:

```cs
// Data/MyDbContext.cs

using Microsoft.EntityFrameworkCore;

namespace MyNewWebApp.Data;

public class MyDbContext : DbContext
{
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
  .AddIdentityCore<IdentityUser>() // <-- or `AddIdentity<,>`
  .AddEntityFrameworkStores<MyDbContext>() // <-- required
  .AddDefaultTokenProviders();             // <-- required
```

Next, let's add auth endpoints services and jwt bearer authentication scheme:

```cs
// Program.cs

builder.Services
  // When no options provided, 
  // AuthEndpoints will automatically create a secret key and use single security key
  // for each access jwt and refresh jwt (symmetric encryption).
  // Secrets will be created under `keys/` directory.
  .AddAuthEndpoints<string, IdentityUser>() // <TUserKey, TUser>
  .AddAllEndpointDefinitions() // Add endpoint definitions
  .AddJwtBearerAuthScheme();
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

app.MapAuthEndpoints(); // <--

app.Run();
```

Run it and you should see auth endpoints available on swagger docs!

![authendpoints swagger](/images/swagger.png "authendpoints swagger")


## Full Source Code

```cs
// Program.cs

using AuthEndpoints;
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
  .AddAuthEndpoints<string, IdentityUser>()
  .AddAllEndpointDefinitions() // Add endpoint definitions
  .AddJwtBearerAuthScheme(); // Add jwt bearer auth

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

app.MapAuthEndpoints(); // <-- Map minimal api endpoints

app.Run();
```


## Available Endpoints

- [Basic authentication endpoints](/wiki/base-endpoints.html)
- [JWT endpoints](/wiki/jwt-endpoints.html)
- [2FA endpoints](/wiki/2fa-endpoints.html)
