using AuthEndpoints.Models;
using AuthEndpoints.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Web;

namespace AuthEndpoints.Controllers;

/// <summary>
/// Inherit this base class to define endpoints that contain base authentication actions such as registration, set password, etc.
/// </summary>
/// <typeparam name="TUserKey"></typeparam>
/// <typeparam name="TUser"></typeparam>
[Route("users/")]
[ApiController]
public class BasicAuthenticationController<TUserKey, TUser> : ControllerBase
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>, new()
{
    protected readonly UserManager<TUser> userManager;
    protected readonly IdentityErrorDescriber errorDescriber;
    protected readonly AuthEndpointsOptions options;
    protected readonly IEmailSender emailSender;
    protected readonly IEmailFactory emailFactory;

    public BasicAuthenticationController(UserManager<TUser> userManager, IdentityErrorDescriber errorDescriber, IOptions<AuthEndpointsOptions> options, IEmailSender emailSender, IEmailFactory emailFactory)
    {
        this.userManager = userManager;
        this.errorDescriber = errorDescriber;
        this.options = options.Value;
        this.emailSender = emailSender;
        this.emailFactory = emailFactory;
    }

    /// <summary>
    /// Use this endpoint to register a new user
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
        IdentityResult result = await userManager.CreateAsync(registrationUser, request.Password);

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
    /// Use this endpoints to send email verification link via email
    /// You should provide site in your frontend application (configured by <see cref="AuthEndpointsOptions.EmailConfirmationUrl"/>) 
    /// which will send POST request to verify email confirmation endpoint.
    /// </summary>
    /// <returns></returns>
    [Authorize(AuthenticationSchemes = "jwt")]
    [HttpGet("verify_email")]
    public virtual async Task<IActionResult> EmailVerification()
    {
        string identity = HttpContext.User.FindFirstValue("id");
        TUser user = await userManager.FindByIdAsync(identity);
        
        if (user.EmailConfirmed)
        {
            return Unauthorized();
        }

        var token = await userManager.GenerateEmailConfirmationTokenAsync(user);

        var link = options.EmailConfirmationUrl!
            .Replace("{uid}", identity)
            .Replace("{token}", HttpUtility.UrlEncode(token));

        // send email
        var email = emailFactory.CreateConfirmationEmail(
            new EmailData(new string[] { user.Email }, "Email Confirmation", link)
        );
        await emailSender.SendEmailAsync(email).ConfigureAwait(false);

        return NoContent();
    }

    /// <summary>
    /// Use this endpoint to confirm user email. 
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [HttpPost("verify_email_confirm")]
    public virtual async Task<IActionResult> EmailVerificationConfirm([FromBody] ConfirmEmailRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        if (request.Identity == null || request.Token == null)
        {
            return BadRequest();
        }

        var user = await userManager.FindByIdAsync(request.Identity);

        if (user == null)
        {
            return BadRequest();
        }

        if (user.EmailConfirmed)
        {
            return Unauthorized();
        }

        var result = await userManager.ConfirmEmailAsync(user, request.Token);

        if (result.Succeeded)
        {
            return NoContent();
        }

        IEnumerable<string> errors = result.Errors.Select(error => error.Description);
        return Conflict(errors);
    }

    /// <summary>
    /// Use this endpoint to retrieve the authenticated user
    /// </summary>
    [Authorize(AuthenticationSchemes = "jwt")]
    [HttpGet("me")]
    public virtual async Task<IActionResult> GetMe()
    {
        string identity = HttpContext.User.FindFirstValue("id");
        TUser currentUser = await userManager.FindByIdAsync(identity);

        return Ok(currentUser);
    }

    /// <summary>
    /// Use this endpoint to delete authenticated user.
    /// </summary>
    /// <returns></returns>
    [Authorize(AuthenticationSchemes = "jwt")]
    [HttpDelete("delete")]
    public virtual async Task<IActionResult> Delete()
    {
        var identity = HttpContext.User.FindFirstValue("id");
        TUser user = await userManager.FindByIdAsync(identity);
        var result = await userManager.DeleteAsync(user);

        if (result.Succeeded)
        {
            return NoContent();
        }

        IEnumerable<string> errors = result.Errors.Select(error => error.Description);
        return Conflict(errors);
    }

    /// <summary>
    /// Use this endpoint to change user's username
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [Authorize(AuthenticationSchemes = "jwt")]
    [HttpPost("set_username")]
    public virtual async Task<IActionResult> SetUsername([FromBody] SetUsernameRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        string identity = HttpContext.User.FindFirstValue("id");
        TUser user = await userManager.FindByIdAsync(identity);

        if (await userManager.CheckPasswordAsync(user, request.CurrentPassword) is false)
        {
            return BadRequest(new ErrorResponse("Invalid current password"));
        }

        user.UserName = request.NewUsername;
        await userManager.UpdateAsync(user);

        return NoContent();
    }

    /// <summary>
    /// Use this endpoint to change user password
    /// </summary>
    [Authorize(AuthenticationSchemes = "jwt")]
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
        TUser user = await userManager.FindByIdAsync(identity);

        if (await userManager.CheckPasswordAsync(user, request.CurrentPassword) is false)
        {
            return BadRequest(new ErrorResponse("Invalid current password"));
        }

        var token = await userManager.GeneratePasswordResetTokenAsync(user);
        var result = await userManager.ResetPasswordAsync(user, token, request.NewPassword);

        if (!result.Succeeded)
        {
            return Conflict($"Error occured while updating password. Code: {result.Errors.First().Code}");
        }

        return NoContent();
    }

    /// <summary>
    /// Use this endpoint to send email to user with password reset link.
    /// You should provide site in your frontend application (configured by <see cref="AuthEndpointsOptions.PasswordResetUrl"/>) 
    /// which will send POST request to reset password confirmation endpoint.
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [HttpPost("reset_password")]
    public virtual async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        TUser user = await userManager.FindByEmailAsync(request.Email);

        if (user == null)
        {
            return NotFound();
        }

        if (!user.EmailConfirmed)
        {
            return Unauthorized();
        }

        var token = await userManager.GeneratePasswordResetTokenAsync(user);

        // generate link to the frontend application that contains Identity and Token.
        // e.g. "#password-reset/{uid}/{Token}"
        var link = options.PasswordResetUrl!
            .Replace("{uid}", user.Id.ToString())
            .Replace("{token}", HttpUtility.UrlEncode(token))
            .Trim();

        // send email
        var email = emailFactory.CreateResetPasswordEmail(
            new EmailData(new string[] { user.Email }, "Password Reset", link)
        );
        await emailSender.SendEmailAsync(email).ConfigureAwait(false);

        return NoContent();
    }

    /// <summary>
    /// Use this endpoint to finish reset password process.
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [HttpPost("reset_password_confirm")]
    public virtual async Task<IActionResult> ResetPasswordConfirm([FromBody] ResetPasswordConfirmRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequestModelState();
        }

        TUser user = await userManager.FindByIdAsync(request.Identity);

        if (user == null)
        {
            return NotFound();
        }

        var result = await userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);

        if (result.Succeeded)
        {
            return NoContent();
        }

        IEnumerable<string> errors = result.Errors.Select(error => error.Description);
        return Conflict(errors);
    }

    private IActionResult BadRequestModelState()
    {
        IEnumerable<string> errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
        return BadRequest(new ErrorResponse(errors));
    }
}
