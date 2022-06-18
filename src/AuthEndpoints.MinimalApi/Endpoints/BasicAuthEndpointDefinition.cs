using System.Security.Claims;
using System.Web;
using AuthEndpoints.Models;
using AuthEndpoints.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.MinimalApi;

public class BasicAuthEndpointDefinition<TKey, TUser> : IEndpointDefinition, IBasicAuthEndpointDefinition<TKey, TUser> 
    where TKey : IEquatable<TKey>
    where TUser : IdentityUser<TKey>, new()
{
    public void MapEndpoints(WebApplication app)
    {
        string baseUrl = "/users";
        app.MapPost($"{baseUrl}", Register);
        app.MapGet($"{baseUrl}/me", GetMe);
        app.MapGet($"{baseUrl}/verify_email", EmailVerification);
        app.MapPost($"{baseUrl}/verify_email_confirm", EmailVerificationConfirm);
        app.MapPost($"{baseUrl}/set_username", SetUsername);
        app.MapPost($"{baseUrl}/set_password", SetPassword);
        app.MapPost($"{baseUrl}/reset_password", ResetPassword);
        app.MapPost($"{baseUrl}/reset_password_confirm", ResetPasswordConfirm);
        app.MapDelete($"{baseUrl}/delete", Delete);
    }

    /// <summary>
    /// Use this endpoint to register a new user
    /// </summary>
    public virtual async Task<IResult> Register([FromBody] RegisterRequest request, UserManager<TUser> userManager, IdentityErrorDescriber errorDescriber)
    {
        // validate model state

        if (request.Password != request.ConfirmPassword)
        {
            return Results.BadRequest(new ErrorResponse("Password not match confirm password."));
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
                return Results.Conflict(new ErrorResponse("Email already exists."));
            }
            else if (primaryError!.Code == nameof(errorDescriber.DuplicateUserName))
            {
                return Results.Conflict(new ErrorResponse("Username already exists."));
            }
            else
            {
                return Results.Conflict(new ErrorResponse($"Error code: {primaryError!.Code}\n{string.Join(", ", result.Errors.Select(e => e.Description))}"));
            }
        }

        return Results.Ok();
    }

    /// <summary>
    /// Use this endpoint to retrieve the authenticated user
    /// </summary>
    [Authorize(AuthenticationSchemes = "jwt")]
    [HttpGet("me")]
    public virtual async Task<IResult> GetMe(HttpContext context, UserManager<TUser> userManager)
    {
        string identity = context.User.FindFirstValue("id");
        TUser currentUser = await userManager.FindByIdAsync(identity);

        return Results.Ok(currentUser);
    }

    /// <summary>
    /// Use this endpoints to send email verification link via email
    /// You should provide site in your frontend application (configured by <see cref="AuthEndpointsOptions.EmailConfirmationUrl"/>) 
    /// which will send POST request to verify email confirmation endpoint.
    /// </summary>
    /// <returns></returns>
    [Authorize(AuthenticationSchemes = "jwt")]
    [HttpGet("verify_email")]
    public virtual async Task<IResult> EmailVerification(HttpContext context,
        UserManager<TUser> userManager,
        IOptions<AuthEndpointsOptions> opt,
        IEmailFactory emailFactory,
        IEmailSender emailSender)
    {
        AuthEndpointsOptions options = opt.Value;

        string identity = context.User.FindFirstValue("id");
        TUser user = await userManager.FindByIdAsync(identity);

        if (user.EmailConfirmed)
        {
            return Results.Unauthorized();
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

        return Results.NoContent();
    }

    /// <summary>
    /// Use this endpoint to confirm user email. 
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [HttpPost("verify_email_confirm")]
    public virtual async Task<IResult> EmailVerificationConfirm([FromBody] ConfirmEmailRequest request,
        UserManager<TUser> userManager)
    {
        //if (!ModelState.IsValid)
        //{
        //    return BadRequestModelState();
        //}

        if (request.Identity == null || request.Token == null)
        {
            return Results.BadRequest();
        }

        var user = await userManager.FindByIdAsync(request.Identity);

        if (user == null)
        {
            return Results.BadRequest();
        }

        if (user.EmailConfirmed)
        {
            return Results.Unauthorized();
        }

        var result = await userManager.ConfirmEmailAsync(user, request.Token);

        if (result.Succeeded)
        {
            return Results.NoContent();
        }

        IEnumerable<string> errors = result.Errors.Select(error => error.Description);
        return Results.Conflict(errors);
    }

    /// <summary>
    /// Use this endpoint to change user's username
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [Authorize(AuthenticationSchemes = "jwt")]
    [HttpPost("set_username")]
    public virtual async Task<IResult> SetUsername([FromBody] SetUsernameRequest request,
        HttpContext context,
        UserManager<TUser> userManager)
    {
        //if (!ModelState.IsValid)
        //{
        //    return BadRequestModelState();
        //}

        string identity = context.User.FindFirstValue("id");
        TUser user = await userManager.FindByIdAsync(identity);

        if (await userManager.CheckPasswordAsync(user, request.CurrentPassword) is false)
        {
            return Results.BadRequest(new ErrorResponse("Invalid current password"));
        }

        user.UserName = request.NewUsername;
        await userManager.UpdateAsync(user);

        return Results.NoContent();
    }

    /// <summary>
    /// Use this endpoint to change user password
    /// </summary>
    [Authorize(AuthenticationSchemes = "jwt")]
    [HttpPost("set_password")]
    public virtual async Task<IResult> SetPassword([FromBody] SetPasswordRequest request,
        HttpContext context,
        UserManager<TUser> userManager)
    {
        //if (!ModelState.IsValid)
        //{
        //    return BadRequestModelState();
        //}

        if (request.NewPassword != request.ConfirmNewPassword)
        {
            return Results.BadRequest(new ErrorResponse("New password not match confirm password"));
        }

        if (request.CurrentPassword == request.NewPassword)
        {
            return Results.BadRequest(new ErrorResponse("New password cannot be the same as current password"));
        }

        string identity = context.User.FindFirstValue("id");
        TUser user = await userManager.FindByIdAsync(identity);

        if (await userManager.CheckPasswordAsync(user, request.CurrentPassword) is false)
        {
            return Results.BadRequest(new ErrorResponse("Invalid current password"));
        }

        var token = await userManager.GeneratePasswordResetTokenAsync(user);
        var result = await userManager.ResetPasswordAsync(user, token, request.NewPassword);

        if (!result.Succeeded)
        {
            return Results.Conflict($"Error occured while updating password. Code: {result.Errors.First().Code}");
        }

        return Results.NoContent();
    }

    /// <summary>
    /// Use this endpoint to send email to user with password reset link.
    /// You should provide site in your frontend application (configured by <see cref="AuthEndpointsOptions.PasswordResetUrl"/>) 
    /// which will send POST request to reset password confirmation endpoint.
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [HttpPost("reset_password")]
    public virtual async Task<IResult> ResetPassword([FromBody] ResetPasswordRequest request,
        UserManager<TUser> userManager,
        IOptions<AuthEndpointsOptions> opt,
        IEmailFactory emailFactory,
        IEmailSender emailSender)
    {
        //if (!ModelState.IsValid)
        //{
        //    return BadRequestModelState();
        //}
        AuthEndpointsOptions options = opt.Value;

        TUser user = await userManager.FindByEmailAsync(request.Email);

        if (user == null)
        {
            return Results.NotFound();
        }

        if (!user.EmailConfirmed)
        {
            return Results.Unauthorized();
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

        return Results.NoContent();
    }

    /// <summary>
    /// Use this endpoint to finish reset password process.
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [HttpPost("reset_password_confirm")]
    public virtual async Task<IResult> ResetPasswordConfirm([FromBody] ResetPasswordConfirmRequest request,
        UserManager<TUser> userManager)
    {
        //if (!ModelState.IsValid)
        //{
        //    return BadRequestModelState();
        //}

        TUser user = await userManager.FindByIdAsync(request.Identity);

        if (user == null)
        {
            return Results.NotFound();
        }

        var result = await userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);

        if (result.Succeeded)
        {
            return Results.NoContent();
        }

        IEnumerable<string> errors = result.Errors.Select(error => error.Description);
        return Results.Conflict(errors);
    }

    /// <summary>
    /// Use this endpoint to delete authenticated user.
    /// </summary>
    /// <returns></returns>
    [Authorize(AuthenticationSchemes = "jwt")]
    [HttpDelete("delete")]
    public virtual async Task<IResult> Delete(HttpContext context, UserManager<TUser> userManager)
    {
        var identity = context.User.FindFirstValue("id");
        TUser user = await userManager.FindByIdAsync(identity);
        var result = await userManager.DeleteAsync(user);

        if (result.Succeeded)
        {
            return Results.NoContent();
        }

        IEnumerable<string> errors = result.Errors.Select(error => error.Description);
        return Results.Conflict(errors);
    }
}
