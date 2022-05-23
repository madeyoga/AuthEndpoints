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
}).AddJwtBearerAuthScheme(accessParameters);


// Create a controller, then simply inherit

public class AuthenticationController : JwtController<string, IdentityUser>
{}

public class UserController : BaseEndpointsController<string, IdentityUser>
{}
```

## Documentations
Documentation is available at tbd and in [docs](https://github.com/madeyoga/AuthEndpoints/tree/main/docs) directory.

## Contributing
Your contributions are always welcome! simply send a pull request! The [up-for-grabs](https://github.com/madeyoga/AuthEndpoints/labels/up-for-grabs) label is a great place to start.

The documentation is far from perfect so every bit of help is more than welcome.
