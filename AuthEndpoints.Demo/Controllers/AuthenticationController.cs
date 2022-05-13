using AuthEndpoints.Controllers;
using AuthEndpoints.Demo.Models;
using AuthEndpoints.Models.Requests;
using AuthEndpoints.Services.Authenticators;
using AuthEndpoints.Services.TokenValidators;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthEndpoints.Demo.Controllers;

[ApiController]
[Route("jwt/")]
[Tags("JSON Web Token")]
public class AuthenticationController : JwtController<string, MyCustomIdentityUser>
{
    public AuthenticationController(UserManager<MyCustomIdentityUser> userRepository, 
        JwtUserAuthenticator<MyCustomIdentityUser> authenticator, 
        ITokenValidator refreshTokenValidator)
        : base(userRepository, authenticator, refreshTokenValidator)
    {
    }

    [HttpPost("create")]
    public override async Task<IActionResult> Create([FromBody] LoginRequest loginRequest)
    {
        return await base.Create(loginRequest);
    }
}
