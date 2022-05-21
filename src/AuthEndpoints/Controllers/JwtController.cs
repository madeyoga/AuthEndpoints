using AuthEndpoints.Models;
using AuthEndpoints.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;

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
    protected readonly IJwtValidator jwtValidator;
    protected readonly IAuthenticator<TUser> authenticator;
    protected readonly IOptions<AuthEndpointsOptions> options;

    public JwtController(UserManager<TUser> userManager,
        IAuthenticator<TUser> authenticator,
        IJwtValidator jwtValidator,
        IOptions<AuthEndpointsOptions> options)
    {
        this.userManager = userManager;
        this.authenticator = authenticator;
        this.jwtValidator = jwtValidator;
        this.options = options;
    }

    /// <summary>
    /// Use this endpoint to obtain jwt
    /// </summary>
    /// <remarks>Use this endpoint to obtain jwt</remarks>
    /// <response code="200">Valid username and password, return: access and refresh token</response>
    /// <response code="400">Invalid model state</response>
    /// <response code="401">Invalid username or password</response>
    /// <inheritdoc/>
    [HttpPost("create")]
    public virtual async Task<IActionResult> Create([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        TUser? user = await authenticator.Authenticate(request.Username, request.Password);

        if (user == null)
        {
            return Unauthorized();
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

        bool isValidRefreshToken = jwtValidator.Validate(request.RefreshToken, 
            options.Value.RefreshTokenValidationParameters!);

        if (!isValidRefreshToken)
        {
            // token may be expired, invalid, etc. but this good enough for now.
            return BadRequest(new ErrorResponse("Invalid refresh token. Token may be expired or invalid."));
        }

        JwtSecurityToken jwt = jwtValidator.ReadJwtToken(request.RefreshToken);
        string userId = jwt.Claims.First(claim => claim.Type == "id").Value;
        TUser user = await userManager.FindByIdAsync(userId);

        if (user == null)
        {
            return NotFound(new ErrorResponse("User not found."));
        }

        AuthenticatedUserResponse response = await authenticator.Login(user);

        return Ok(response);
    }

    /// <summary>
    /// Use this endpoint to verify jwt
    /// </summary>
    [HttpPost("verify")]
    public virtual async Task<IActionResult> Verify([FromBody] VerifyRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        if (await jwtValidator.ValidateAsync(request.Token!, options.Value.AccessTokenValidationParameters!))
        {
            return Ok();
        }

        if (await jwtValidator.ValidateAsync(request.Token!, options.Value.RefreshTokenValidationParameters!))
        {
            return Ok();
        }

        return Unauthorized();
    }

    private IActionResult BadRequestModelState()
    {
        IEnumerable<string> errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));

        return BadRequest(new ErrorResponse(errors));
    }
}
