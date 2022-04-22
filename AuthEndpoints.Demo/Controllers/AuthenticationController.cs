using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using AuthEndpoints.Demo.Models;
using AuthEndpoints.Services.Repositories;
using AuthEndpoints.Services.Authenticators;
using AuthEndpoints.Controllers;
using AuthEndpoints.Services.TokenValidators;

namespace AuthEndpoints.Demo.Controllers;

[ApiController]
[Route("jwt/")]
[Tags("JSON Web Token")]
public class AuthenticationController : JwtEndpointsController<string, MyCustomIdentityUser, RefreshToken>
{
    public AuthenticationController(UserManager<MyCustomIdentityUser> userRepository, IRefreshTokenRepository<string, RefreshToken> refreshTokenRepository,
        UserAuthenticator<string, MyCustomIdentityUser, RefreshToken> authenticator, ITokenValidator refreshTokenValidator, IdentityErrorDescriber errorDescriber)
        : base(userRepository, refreshTokenRepository, authenticator, refreshTokenValidator, errorDescriber)
    {
    }
}
