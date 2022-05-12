using AuthEndpoints.Models.Requests;
using AuthEndpoints.Models.Responses;
using AuthEndpoints.Services.Authenticators;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthEndpoints.Controllers;

[ApiController]
[Route("token/")]
public class TokenEndpointsController<TUserKey, TUser> : ControllerBase
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>, new()
{
    private readonly UserManager<TUser> userManager;
    private readonly TokenUserAuthenticator<TUser> authenticator;

    public TokenEndpointsController(UserManager<TUser> userRepository, TokenUserAuthenticator<TUser> authenticator)
    {
        this.userManager = userRepository;
        this.authenticator = authenticator;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        TUser user = await userManager.FindByNameAsync(request.Username);

        if (user == null)
        {
            return Unauthorized();
        }

        bool correctPassword = await userManager.CheckPasswordAsync(user, request.Password);

        if (!correctPassword)
        {
            return Unauthorized();
        }

        AuthenticatedTokenResponse response = await authenticator.Authenticate(user);

        return Ok();
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var user = await userManager.GetUserAsync(HttpContext.User);

        return NoContent();
    }

    private IActionResult BadRequestModelState()
    {
        IEnumerable<string> errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
        return BadRequest(new ErrorResponse(errors));
    }
}
