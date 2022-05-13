using AuthEndpoints.Models.Requests;
using AuthEndpoints.Models.Responses;
using AuthEndpoints.Services.Authenticators;
using AuthEndpoints.Services.TokenValidators;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

namespace AuthEndpoints.Controllers;

/// <summary>
/// Contain jwt endpoints
/// </summary>
/// <typeparam name="TUserKey"></typeparam>
/// <typeparam name="TUser"></typeparam>
public class JwtController<TUserKey, TUser> : ControllerBase
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>
{
    private readonly ITokenValidator refreshTokenValidator;
    private readonly UserManager<TUser> userRepository;
    private readonly JwtUserAuthenticator<TUser> authenticator;

    public JwtController(UserManager<TUser> userRepository,
        JwtUserAuthenticator<TUser> authenticator,
        ITokenValidator refreshTokenValidator)
    {
        this.userRepository = userRepository;
        this.authenticator = authenticator;
        this.refreshTokenValidator = refreshTokenValidator;
    }

    /// <summary>
    /// Use this endpoint to obtain jwt
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    /// <response code="200">Valid username and password, return: access and refresh token</response>
    /// <response code="400">Invalid model state</response>
    /// <response code="401">Invalid username or password</response>
    [HttpPost("create")]
    public virtual async Task<IActionResult> Create([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        TUser user = await userRepository.FindByNameAsync(request.Username);

        if (user == null)
        {
            return Unauthorized();
        }

        bool correctPassword = await userRepository.CheckPasswordAsync(user, request.Password);

        if (!correctPassword)
        {
            return Unauthorized();
        }

        AuthenticatedJwtResponse response = await authenticator.Authenticate(user);

        return Ok(response);
    }


    /// <summary>
    /// Use this endpoint to refresh jwt
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    /// <response code="200">Valid refresh token, return an new: access and refresh token</response>
    /// <response code="400">Invalid model state or Invalid token. Token may be expired or invalid</response>
    /// <response code="404">User associated by this token is not found</response>
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

        var jwt = refreshTokenValidator.ReadJwtToken(request.RefreshToken);
        string userId = jwt.Claims.First(claim => claim.Type == "id").Value;
        TUser user = await userRepository.FindByIdAsync(userId);

        if (user == null)
        {
            return NotFound(new ErrorResponse("User not found."));
        }

        AuthenticatedJwtResponse response = await authenticator.Authenticate(user);

        return Ok(response);
    }

    /// <summary>
    /// Use this endpoint to verify jwt
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    /// <response code="200">Valid jwt</response>
    /// <response code="400">Invalid model state</response>
    /// <response code="401">Invalid jwt</response>
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
