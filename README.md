# AuthEndpoints
A simple jwt authentication library for ASP.Net 6. AuthEndpoints library provides a set of Web API controllers to handle basic web & JWT authentication actions such as registration, login, refresh, and verify. It works with [custom identity user model](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/customize-identity-model?view=aspnetcore-6.0#custom-user-data).

## Installation
### NuGet
- tbd

## Basic Usage
```cs
// in your Program.cs

var accessParameters = new TokenValidationParameters()
{
	...
};

var refreshParameters = new TokenValidationParameters()
{
	...
};

builder.Services.AddAuthEndpoints<string, IdentityUser>(new AuthEndpointsOptions()
{
	AccessTokenSecret = "<accesstoken_secret_key>",
	RefreshTokenSecret = "<refreshtoken_secret_key>",
	AccessTokenExpirationMinutes = 15,
	RefreshTokenExpirationMinutes = 6000,
	Audience = "https://localhost:8000",
	Issuer = "https://localhost:8000",
	AccessTokenValidationParameters = accessParameters,
	RefreshTokenValidationParameters = refreshParameters
}).AddJwtBearerAuthenticationScheme(accessParameters);


// Now create a controller, then simply inherit
public class AuthenticationController : JwtController<string, IdentityUser>
{}

public class UserController : BasicEndpointsController<string, IdentityUser>
{}
```

## Documentations
Documentation is available at tbd and in tbd directory.

## Contributing
To start developing on AuthEndpoints, simply clone the repo:
```
$ git clone https://github.com/nano-devs/AuthEndpoints.git
```
& start hacking :)
