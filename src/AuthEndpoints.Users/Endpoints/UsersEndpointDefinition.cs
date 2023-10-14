using System.Security.Claims;
using System.Web;
using AuthEndpoints.Core;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Users;

public class UsersEndpointDefinition<TUser> : IEndpointDefinition
    where TUser : class, new()
{
    public virtual void MapEndpoints(WebApplication app)
    {
        var baseUrl = "/users";
        var groupName = "Users";
        app.MapPost($"{baseUrl}", Register).WithTags(groupName);
        app.MapGet($"{baseUrl}/me", GetMe).WithTags(groupName);
        app.MapGet($"{baseUrl}/verify_email", EmailVerification).WithTags(groupName);
        app.MapPost($"{baseUrl}/verify_email_confirm", EmailVerificationConfirm).WithTags(groupName);
        app.MapPost($"{baseUrl}/set_username", SetUsername).WithTags(groupName);
        app.MapPost($"{baseUrl}/set_password", SetPassword).WithTags(groupName);
        app.MapPost($"{baseUrl}/reset_password", ResetPassword).WithTags(groupName);
        app.MapPost($"{baseUrl}/reset_password_confirm", ResetPasswordConfirm).WithTags(groupName);
        app.MapDelete($"{baseUrl}/delete", Delete).WithTags(groupName);
    }

    /// <summary>
    /// Use this endpoint to register a new user
    /// </summary>
    public virtual async Task<IResult> Register([FromBody] RegisterRequest request, 
        UserManager<TUser> userManager, 
        IdentityErrorDescriber errorDescriber, 
        IUserStore<TUser> userStore)
    {
        if (request.Password != request.ConfirmPassword)
        {
            return Results.BadRequest(new ErrorResponse("Password not match confirm password."));
        }

        var emailStore = (IUserEmailStore<TUser>)userStore;

        var user = new TUser();
        await userStore.SetUserNameAsync(user, request.Username, CancellationToken.None);
        await emailStore.SetEmailAsync(user, request.Email, CancellationToken.None);
        var result = await userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded)
        {
            var primaryError = result.Errors.FirstOrDefault();

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
    [Authorize(AuthenticationSchemes = "Bearer")]
    public virtual async Task<IResult> GetMe(HttpContext context, UserManager<TUser> userManager)
    {
        var id = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        var currentUser = await userManager.FindByIdAsync(id);

        return Results.Ok(currentUser);
    }

    /// <summary>
    /// Use this endpoints to send email verification link via email
    /// You should provide site in your frontend application (configured by <see cref="UserEndpointsOptions.EmailConfirmationUrl"/>) 
    /// which will send POST request to verify email confirmation endpoint.
    /// </summary>
    /// <returns></returns>
    [Authorize(AuthenticationSchemes = "Bearer")]
    public virtual async Task<IResult> EmailVerification(HttpContext context,
        UserManager<TUser> userManager,
        IOptions<UserEndpointsOptions> opt,
        IEmailSender<TUser> emailSender)
    {
        var options = opt.Value;

        var identity = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = await userManager.FindByIdAsync(identity);
        var isEmailConfirmed = await userManager.IsEmailConfirmedAsync(user);
        if (!isEmailConfirmed)
        {
            return Results.Unauthorized();
        }

        var token = await userManager.GenerateEmailConfirmationTokenAsync(user);

        var link = options.EmailConfirmationUrl!
            .Replace("{uid}", identity)
            .Replace("{token}", HttpUtility.UrlEncode(token));

        await emailSender.SendConfirmationLinkAsync(user, await userManager.GetEmailAsync(user), link);

        return Results.NoContent();
    }

    /// <summary>
    /// Use this endpoint to confirm user email. 
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    public virtual async Task<IResult> EmailVerificationConfirm([FromBody] ConfirmEmailRequest request,
        UserManager<TUser> userManager)
    {
        if (request.Identity == null || request.Token == null)
        {
            return Results.BadRequest();
        }

        var user = await userManager.FindByIdAsync(request.Identity);

        if (user == null)
        {
            return Results.BadRequest();
        }

        if (await userManager.IsEmailConfirmedAsync(user) == false)
        {
            return Results.Unauthorized();
        }

        var result = await userManager.ConfirmEmailAsync(user, request.Token);

        if (result.Succeeded)
        {
            return Results.NoContent();
        }

        var errors = result.Errors.Select(error => error.Description);
        return Results.Conflict(errors);
    }

    /// <summary>
    /// Use this endpoint to change user's username
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [Authorize(AuthenticationSchemes = "Bearer")]
    public virtual async Task<IResult> SetUsername([FromBody] SetUsernameRequest request,
        HttpContext context,
        UserManager<TUser> userManager)
    {
        var identity = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = await userManager.FindByIdAsync(identity);

        if (await userManager.CheckPasswordAsync(user, request.CurrentPassword) is false)
        {
            return Results.BadRequest(new ErrorResponse("Invalid current password"));
        }

        await userManager.SetUserNameAsync(user, request.NewUsername);

        return Results.NoContent();
    }

    /// <summary>
    /// Use this endpoint to change user password
    /// </summary>
    [Authorize(AuthenticationSchemes = "Bearer")]
    public virtual async Task<IResult> SetPassword([FromBody] SetPasswordRequest request,
        HttpContext context,
        UserManager<TUser> userManager)
    {
        if (request.NewPassword != request.ConfirmNewPassword)
        {
            return Results.BadRequest(new ErrorResponse("New password not match confirm password"));
        }

        if (request.CurrentPassword == request.NewPassword)
        {
            return Results.BadRequest(new ErrorResponse("New password cannot be the same as current password"));
        }

        var identity = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = await userManager.FindByIdAsync(identity);

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
    /// You should provide site in your frontend application (configured by <see cref="UserEndpointsOptions.PasswordResetUrl"/>) 
    /// which will send POST request to reset password confirmation endpoint.
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    public virtual async Task<IResult> ResetPassword([FromBody] ResetPasswordRequest request,
        UserManager<TUser> userManager,
        IOptions<UserEndpointsOptions> opt,
        IEmailSender<TUser> emailSender)
    {
        var options = opt.Value;

        var user = await userManager.FindByEmailAsync(request.Email);

        if (user == null)
        {
            return Results.NotFound();
        }

        if (!await userManager.IsEmailConfirmedAsync(user))
        {
            return Results.Unauthorized();
        }

        var token = await userManager.GeneratePasswordResetTokenAsync(user);

        // generate link to the frontend application that contains Identity and Token.
        // e.g. "#password-reset/{uid}/{Token}"
        var link = options.PasswordResetUrl!
            .Replace("{uid}", await userManager.GetUserIdAsync(user))
            .Replace("{token}", HttpUtility.UrlEncode(token))
            .Trim();

        await emailSender.SendPasswordResetLinkAsync(user, await userManager.GetEmailAsync(user), link);

        return Results.NoContent();
    }

    /// <summary>
    /// Use this endpoint to finish reset password process.
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    public virtual async Task<IResult> ResetPasswordConfirm([FromBody] ResetPasswordConfirmRequest request,
        UserManager<TUser> userManager)
    {
        var user = await userManager.FindByIdAsync(request.Identity);

        if (user == null)
        {
            return Results.NotFound();
        }

        var result = await userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);

        if (result.Succeeded)
        {
            return Results.NoContent();
        }

        var errors = result.Errors.Select(error => error.Description);
        return Results.Conflict(errors);
    }

    /// <summary>
    /// Use this endpoint to delete authenticated user.
    /// </summary>
    /// <returns></returns>
    [Authorize(AuthenticationSchemes = "Bearer")]
    public virtual async Task<IResult> Delete(HttpContext context, UserManager<TUser> userManager)
    {
        var identity = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = await userManager.FindByIdAsync(identity);
        var result = await userManager.DeleteAsync(user);

        if (result.Succeeded)
        {
            return Results.NoContent();
        }

        var errors = result.Errors.Select(error => error.Description);
        return Results.Conflict(errors);
    }
}
