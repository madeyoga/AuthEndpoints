using AuthEndpoints.Jwt.Models;
using AuthEndpoints.Jwt.Models.Requests;
using AuthEndpoints.Jwt.Models.Responses;
using AuthEndpoints.Jwt.Services.Authenticators;
using AuthEndpoints.Jwt.Services.Repositories;
using AuthEndpoints.Jwt.Services.TokenValidators;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using System.Security.Claims;

namespace AuthEndpoints.Jwt.Controllers;

public class JwtEndpointsController<TUserKey, TUser, TRefreshToken> : ControllerBase
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>, new()
    where TRefreshToken : GenericRefreshToken<TUser, TUserKey>, new()
{
    private readonly IRefreshTokenRepository<TUserKey, TRefreshToken> refreshTokenRepository;
    private readonly ITokenValidator refreshTokenValidator;
    private readonly UserManager<TUser> userRepository;
    private readonly UserAuthenticator<TUserKey, TUser, TRefreshToken> authenticator;

    public JwtEndpointsController(UserManager<TUser> userRepository,
        IRefreshTokenRepository<TUserKey, TRefreshToken> refreshTokenRepository,
        UserAuthenticator<TUserKey, TUser, TRefreshToken> authenticator,
        ITokenValidator refreshTokenValidator,
        IdentityErrorDescriber errorDescriber)
    {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.authenticator = authenticator;
        this.refreshTokenValidator = refreshTokenValidator;
    }

    [HttpPost("create")]
    public async Task<IActionResult> Create([FromBody] LoginRequest loginRequest)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        TUser user = await userRepository.FindByNameAsync(loginRequest.Username);

        if (user == null)
        {
            return Unauthorized();
        }

        bool correctPassword = await userRepository.CheckPasswordAsync(user, loginRequest.Password);

        if (!correctPassword)
        {
            return Unauthorized();
        }

        AuthenticatedUserResponse response = await authenticator.Authenticate(user);

        return Ok(response);
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest refreshRequest)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        bool isValidRefreshToken = refreshTokenValidator.Validate(refreshRequest.RefreshToken);

        if (!isValidRefreshToken)
        {
            // token may be expired, invalid, etc. but this good enough for now.
            return BadRequest(new ErrorResponse("Invalid refresh token. Token may be expired or invalid."));
        }

        TRefreshToken? refreshTokenDTO = await refreshTokenRepository.GetByToken(refreshRequest.RefreshToken);

        if (refreshTokenDTO == null)
        {
            return NotFound(new ErrorResponse("Invaliid refresh token. Token is not registered in repository."));
        }

        await refreshTokenRepository.Delete(refreshTokenDTO.Id);
        TUser user = await userRepository.FindByIdAsync(refreshTokenDTO.UserId!.ToString());

        if (user == null)
        {
            return NotFound(new ErrorResponse("IdentityUser not found."));
        }

        AuthenticatedUserResponse response = await authenticator.Authenticate(user);
        return Ok(response);
    }

    [Authorize]
    [HttpPost("verify")]
    public IActionResult Verify([FromBody] VerifyRequest verifyRequest)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }
        
        string headerToken = Request.Headers[HeaderNames.Authorization].ToString().Replace("Bearer ", "");

        if (headerToken == verifyRequest.Token!)
        {
            return Ok();
        }

        bool isValidRefreshToken = refreshTokenValidator.Validate(verifyRequest.Token!);

        if (isValidRefreshToken)
        {
            return Ok();
        }

        return Unauthorized();
    }

    [Authorize]
    [HttpDelete("logout")]
    public async Task<IActionResult> Logout()
    {
        string rawUserId = HttpContext.User.FindFirstValue("id");
        
        TUserKey key = (TUserKey) Convert.ChangeType(rawUserId, typeof(TUserKey));

        await refreshTokenRepository.DeleteAll(key);
        return NoContent();
    }

    private IActionResult BadRequestModelState()
    {
        IEnumerable<string> errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
        return BadRequest(new ErrorResponse(errors));
    }
}
