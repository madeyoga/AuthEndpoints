using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using AuthEndpoints.Jwt.Services.Authenticators;
using AuthEndpoints.Jwt.Services.Repositories;
using AuthEndpoints.Jwt.Controllers;
using AuthEndpoints.Jwt.Services.TokenValidators;
using AuthEndpoints.Demo.Models;

namespace AuthEndpoints.Demo.Controllers;

[ApiController]
public class AuthenticationController : JwtController<string, User, RefreshToken>
{
    public AuthenticationController(UserManager<User> userRepository, IRefreshTokenRepository<string, RefreshToken> refreshTokenRepository,
        UserAuthenticator<string, User, RefreshToken> authenticator, ITokenValidator refreshTokenValidator, IdentityErrorDescriber errorDescriber)
        : base(userRepository, refreshTokenRepository, authenticator, refreshTokenValidator, errorDescriber)
    {
    }
}
