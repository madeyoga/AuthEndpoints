using AuthEndpoints.Jwt.Models;
using AuthEndpoints.Jwt.Models.Requests;
using AuthEndpoints.Jwt.Models.Responses;
using AuthEndpoints.Jwt.Services.Authenticators;
using AuthEndpoints.Jwt.Services.Repositories;
using AuthEndpoints.Jwt.Services.TokenValidators;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthEndpoints.Jwt.Controllers;

public class JwtController<TUserKey, TUser, TRefreshToken> : ControllerBase
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>, new()
    where TRefreshToken : GenericRefreshToken<TUser, TUserKey>, new()
{
    private readonly IRefreshTokenRepository<TUserKey, TRefreshToken> refreshTokenRepository;
    private readonly ITokenValidator refreshTokenValidator;
    private readonly UserManager<TUser> userRepository;
    private readonly UserAuthenticator<TUserKey, TUser, TRefreshToken> authenticator;
    private readonly IdentityErrorDescriber errorDescriber;

    public JwtController(UserManager<TUser> userRepository,
        IRefreshTokenRepository<TUserKey, TRefreshToken> refreshTokenRepository,
        UserAuthenticator<TUserKey, TUser, TRefreshToken> authenticator,
        ITokenValidator refreshTokenValidator,
        IdentityErrorDescriber errorDescriber)
    {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.authenticator = authenticator;
        this.refreshTokenValidator = refreshTokenValidator;
        this.errorDescriber = errorDescriber;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest registerRequest)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        if (registerRequest.Password != registerRequest.ConfirmPassword)
        {
            return BadRequest(new ErrorResponse("Password not match confirm password."));
        }

        TUser registrationUser = new TUser();
        registrationUser.Email = registerRequest.Email;
        registrationUser.UserName = registerRequest.Username;
        IdentityResult result = await userRepository.CreateAsync(registrationUser, registerRequest.Password);

        if (!result.Succeeded)
        {
            IdentityError? primaryError = result.Errors.FirstOrDefault();

            if (primaryError!.Code == nameof(errorDescriber.DuplicateEmail))
            {
                return Conflict(new ErrorResponse("Email already exists."));
            }
            else if (primaryError?.Code == nameof(errorDescriber.DuplicateUserName))
            {
                return Conflict(new ErrorResponse("Username already exists."));
            }
            else
            {
                return Conflict(new ErrorResponse("Error response. !result.Succeeded"));
            }
        }

        return Ok();
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest loginRequest)
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
    [HttpDelete("logout")]
    public async Task<IActionResult> Logout()
    {
        string rawUserId = HttpContext.User.FindFirstValue("id");
        TUserKey key = (TUserKey)Convert.ChangeType(rawUserId, typeof(TUserKey));
        // Validate Key
        // ...
        await refreshTokenRepository.DeleteAll(key);
        return NoContent();
    }

    private IActionResult BadRequestModelState()
    {
        IEnumerable<string> errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
        return BadRequest(new ErrorResponse(errors));
    }
}
