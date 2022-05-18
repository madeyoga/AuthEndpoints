using AuthEndpoints.Models;
using AuthEndpoints.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;

namespace AuthEndpoints.Controllers;

/// <summary>
/// Use this base class for defnining endpoints that contain simple jwt actions such as create and refresh.
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
    protected readonly ITokenValidator refreshTokenValidator;
    protected readonly IAuthenticator<TUser> authenticator;

    public JwtController(UserManager<TUser> userManager,
        IAuthenticator<TUser> authenticator,
        ITokenValidator refreshTokenValidator)
    {
        this.userManager = userManager;
        this.authenticator = authenticator;
        this.refreshTokenValidator = refreshTokenValidator;
    }

    /// <summary>
    /// Use this endpoint to obtain jwt
    /// </summary>
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

        bool isValidRefreshToken = refreshTokenValidator.Validate(request.RefreshToken);

        if (!isValidRefreshToken)
        {
            // token may be expired, invalid, etc. but this good enough for now.
            return BadRequest(new ErrorResponse("Invalid refresh token. Token may be expired or invalid."));
        }

        JwtSecurityToken jwt = refreshTokenValidator.ReadJwtToken(request.RefreshToken);
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
    [Authorize]
    [HttpPost("verify")]
    public virtual IActionResult Verify([FromBody] VerifyRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        string headerToken = Request.Headers[HeaderNames.Authorization].ToString().Replace("Bearer ", "");

        if (headerToken == request.Token!)
        {
            return Ok();
        }

        bool isValidRefreshToken = refreshTokenValidator.Validate(request.Token!);

        if (isValidRefreshToken)
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
