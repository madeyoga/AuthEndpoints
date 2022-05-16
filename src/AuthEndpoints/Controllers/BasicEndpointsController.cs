using AuthEndpoints.Models.Responses;
using AuthEndpoints.Models.Requests;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthEndpoints.Controllers;

[Route("users/")]
public class BasicEndpointsController<TUserKey, TUser> : ControllerBase
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>, new()
{
    private readonly UserManager<TUser> userRepository;
    private readonly IdentityErrorDescriber errorDescriber;

    public BasicEndpointsController(UserManager<TUser> userRepository, IdentityErrorDescriber errorDescriber)
    {
        this.userRepository = userRepository;
        this.errorDescriber = errorDescriber;
    }

    /// <summary>
    /// Use this endpoint to register new user
    /// </summary>
    [HttpPost("")]
    public virtual async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
        {
            IEnumerable<string> errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
            return BadRequest(new ErrorResponse(errors));
        }

        if (request.Password != request.ConfirmPassword)
        {
            return BadRequest(new ErrorResponse("Password not match confirm password."));
        }

        TUser registrationUser = new TUser()
        {
            Email = request.Email,
            UserName = request.Username
        };
        IdentityResult result = await userRepository.CreateAsync(registrationUser, request.Password);

        if (!result.Succeeded)
        {
            IdentityError? primaryError = result.Errors.FirstOrDefault();

            if (primaryError!.Code == nameof(errorDescriber.DuplicateEmail))
            {
                return Conflict(new ErrorResponse("Email already exists."));
            }
            else if (primaryError!.Code == nameof(errorDescriber.DuplicateUserName))
            {
                return Conflict(new ErrorResponse("Username already exists."));
            }
            else
            {
                return Conflict(new ErrorResponse($"Error code: {primaryError!.Code}\n{string.Join(", ", result.Errors.Select(e => e.Description))}"));
            }
        }

        return Ok();
    }


    /// <summary>
    /// Use this endpoint to retrieve the authenticated user
    /// </summary>
    [Authorize]
    [HttpGet("me")]
    public virtual async Task<IActionResult> GetMe()
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        string identity = HttpContext.User.FindFirstValue("id");
        TUser currentUser = await userRepository.FindByIdAsync(identity);

        return Ok(currentUser);
    }

    /// <summary>
    /// Use this endpoint to change user password
    /// </summary>
    [Authorize]
    [HttpPost("set_password")]
    public virtual async Task<IActionResult> SetPassword([FromBody] SetPasswordRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        if (request.NewPassword != request.ConfirmNewPassword)
        {
            return BadRequest(new ErrorResponse("New password not match confirm password"));
        }

        if (request.CurrentPassword == request.NewPassword)
        {
            return BadRequest(new ErrorResponse("New password cannot be the same as current password"));
        }

        string identity = HttpContext.User.FindFirstValue("id");
        TUser currentUser = await userRepository.FindByIdAsync(identity);

        if (await userRepository.CheckPasswordAsync(currentUser, request.CurrentPassword) is false)
        {
            return BadRequest(new ErrorResponse("Invalid current password"));
        }

        var token = await userRepository.GeneratePasswordResetTokenAsync(currentUser);
        var result = await userRepository.ResetPasswordAsync(currentUser, token, request.NewPassword);

        if (!result.Succeeded)
        {
            return Conflict($"Error occured while updating password. Code: {result.Errors.First().Code}");
        }

        return NoContent();
    }

    private IActionResult BadRequestModelState()
    {
        IEnumerable<string> errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
        return BadRequest(new ErrorResponse(errors));
    }
}
