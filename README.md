# AuthEndpoints
A simple authentication library for ASP.Net 6. AuthEndpoints library provides a set of Web API controllers to handle basic web & JWT authentication actions such as registration, login, refresh, verify, etc. It works with [custom identity user model](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/customize-identity-model?view=aspnetcore-6.0#custom-user-data).

## Installation
### NuGet
- tbd

## Basic Usage
```cs
// in your Program.cs

var accessTokenValidationParameters = new TokenValidationParameters()
{
	IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("<accesstoken_secret_key>")),
	ValidIssuer = "https://localhost:8000",
	ValidAudience = "https://localhost:8000",
	ValidateIssuerSigningKey = true,
	ValidateIssuer = true,
	ValidateAudience = true,
	ClockSkew = TimeSpan.Zero,
};

var refreshTokenValidationParameters = new TokenValidationParameters()
{
	IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("<refreshtoken_secret_key>")),
	ValidIssuer = "https://localhost:8000",
	ValidAudience = "https://localhost:8000",
	ValidateIssuerSigningKey = true,
	ValidateIssuer = true,
	ValidateAudience = true,
	ClockSkew = TimeSpan.Zero,
};

builder.Services.AddAuthEndpoints<string, IdentityUser>(new AuthEndpointsOptions()
{
	AccessTokenSecret = "<accesstoken_secret_key>",
	RefreshTokenSecret = "<refreshtoken_secret_key>",
	AccessTokenExpirationMinutes = 15,
	RefreshTokenExpirationMinutes = 6000,
	Audience = "https://localhost:8000",
	Issuer = "https://localhost:8000",
	AccessTokenValidationParameters = accessTokenValidationParameters,
	RefreshTokenValidationParameters = refreshTokenValidationParameters
}).AddJwtBearerAuthenticationScheme(accessTokenValidationParameters);


// Now create a controller, then simply inherit
public class AuthenticationController : JwtController<string, IdentityUser>
{}

public class UserController : BasicEndpointsController<string, IdentityUser>
{}
```

JwtController<,> contains
- (post) /jwt/create
- (post) /jwt/refresh
- (post) /jwt/verify

BasicEndpoints<,> contains
- (post) /users
- (get)  /users/me
- (post) /set_password

## Documentations
Documentation is available at tbd and in tbd directory.

## Contributing
To start developing on AuthEndpoints, simply clone the repo:
```
$ git clone https://github.com/nano-devs/AuthEndpoints.git
```
& start hacking :)
