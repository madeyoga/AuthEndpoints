using System.IdentityModel.Tokens.Jwt;
using AuthEndpoints.Core;
using AuthEndpoints.Core.Contracts;
using AuthEndpoints.Core.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.Controllers;

/// <summary>
/// Inherit this base class to define endpoints that contain simple jwt auth actions such as create and refresh.
/// </summary>
/// <typeparam name="TUserKey"></typeparam>
/// <typeparam name="TUser"></typeparam>
[Route("jwt/")]
[ApiController]
public class JwtController<TUserKey, TUser> : ControllerBase
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>
{
    protected readonly UserManager<TUser> userManager;
    protected readonly IRefreshTokenValidator tokenValidator;
    protected readonly IAuthenticator<TUser> authenticator;
    protected readonly IOptions<AuthEndpointsOptions> options;

    public JwtController(UserManager<TUser> userManager,
        IAuthenticator<TUser> authenticator,
        IRefreshTokenValidator tokenValidator,
        IOptions<AuthEndpointsOptions> options)
    {
        this.userManager = userManager;
        this.authenticator = authenticator;
        this.tokenValidator = tokenValidator;
        this.options = options;
    }

    /// <summary>
    /// Use this endpoint to obtain jwt
    /// </summary>
    /// <remarks>Use this endpoint to obtain jwt</remarks>
    /// <response code="200">Valid username and password, return: access and refresh Token</response>
    /// <response code="400">Invalid model state</response>
    /// <response code="401">Invalid username or password</response>
    [HttpPost("create")]
    public virtual async Task<IActionResult> Create([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        TUser? user = await authenticator.Authenticate(request.Username!, request.Password!);

        if (user == null)
        {
            return Unauthorized("Invalid credentials");
        }

        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            return Ok(new
            {
                AuthSuccess = false,
                TwoStepVerificationRequired = true,
            });
        }

        AuthenticatedUserResponse response = await authenticator.Login(user);

        return Ok(response);
    }

    /// <summary>
    /// Use this endpoint to refresh jwt
    /// </summary>
    [HttpPost("refresh")]
    public virtual async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        TokenValidationResult result = await tokenValidator.ValidateRefreshTokenAsync(request.RefreshToken!);

        if (!result.IsValid)
        {
            // Token may be expired, invalid, etc. but this good enough for now.
            return BadRequest(new ErrorResponse("Invalid refresh token. Token may be expired or invalid."));
        }

        JwtSecurityToken? jwt = result.SecurityToken as JwtSecurityToken;
        string userId = jwt!.Claims.First(claim => claim.Type == "id").Value;
        TUser user = await userManager.FindByIdAsync(userId);

        if (user == null)
        {
            return NotFound(new ErrorResponse("User not found."));
        }

        AuthenticatedUserResponse response = await authenticator.Login(user);
        response.RefreshToken = "";
        return Ok(response);
    }

    /// <summary>
    /// Use this endpoint to verify access jwt
    /// </summary>
    [Authorize(AuthenticationSchemes = "jwt")]
    [HttpGet("verify")]
    public virtual IActionResult Verify()
    {
        return Ok();
    }

    private IActionResult BadRequestModelState()
    {
        IEnumerable<string> errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));

        return BadRequest(new ErrorResponse(errors));
    }
}
