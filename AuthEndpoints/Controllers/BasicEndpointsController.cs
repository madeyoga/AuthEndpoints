using AuthEndpoints.Models.Responses;
using AuthEndpoints.Models.Requests;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthEndpoints.Controllers;

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

    [HttpPost("users")]
    public virtual async Task<IActionResult> Register([FromBody] RegisterRequest registerRequest)
    {
        if (!ModelState.IsValid)
        {
            IEnumerable<string> errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
            return BadRequest(new ErrorResponse(errors));
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

    [Authorize]
    [HttpGet("users/me")]
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

    [Authorize]
    [HttpPost("users/set_password")]
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

        return Ok();
    }

    private IActionResult BadRequestModelState()
    {
        IEnumerable<string> errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
        return BadRequest(new ErrorResponse(errors));
    }
}
