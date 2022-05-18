using AuthEndpoints.Controllers;
using AuthEndpoints.Demo.Models;
using AuthEndpoints.Models;
using AuthEndpoints.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthEndpoints.Demo.Controllers;

[ApiController]
[Tags("JSON Web Token")]
public class AuthenticationController : JwtController<string, MyCustomIdentityUser>
{
    public AuthenticationController(UserManager<MyCustomIdentityUser> userManager, 
        IAuthenticator<MyCustomIdentityUser> authenticator, 
        IAccessTokenValidator accessTokenValidator, 
        IRefreshTokenValidator refreshTokenValidator) : base(userManager, authenticator, accessTokenValidator, refreshTokenValidator)
    {
    }

    /// <summary>
    /// Use this endpoint to obtain jwt
    /// </summary>
    /// <remarks>Use this endpoint to obtain jwt</remarks>
    /// <response code="200">Valid username and password, return: access and refresh token</response>
    /// <response code="400">Invalid model state</response>
    /// <response code="401">Invalid username or password</response>
    [ProducesResponseType(200)]
    [ProducesResponseType(typeof(LoginRequest), 400)]
    [ProducesResponseType(typeof(LoginRequest), 401)]
    public override async Task<IActionResult> Create([FromBody] LoginRequest request)
    {
        return await base.Create(request);
    }
}
