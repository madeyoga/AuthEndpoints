using System.Security.Claims;
using AuthEndpoints.Models;
using AuthEndpoints.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthEndpoints.MinimalApi;

public class TwoFactorEndpointDefinition<TKey, TUser> : IEndpointDefinition
    where TKey : IEquatable<TKey>
    where TUser : IdentityUser<TKey>, new()
{
    public void MapEndpoints(WebApplication app)
    {
        app.MapGet("/users/enable_2fa", EnableTwoStepVerification);
        app.MapPost("/users/enable_2fa_confirm", EnableTwoStepVerificationConfirm);
        app.MapPost("/users/two_step_verification_login", TwoStepVerificationLogin);
        app.MapPost("/users/two_step_verification_confirm", TwoStepVerificationConfirm);
    }

    /// <summary>
    /// Use this endpoint to send email to user with 2fa token
    /// </summary>
    /// <returns></returns>
    [Authorize(AuthenticationSchemes = "jwt")]
    public virtual async Task<IResult> EnableTwoStepVerification(HttpContext context, 
        UserManager<TUser> userManager,
        IEmailFactory emailFactory,
        IEmailSender emailSender)
    {
        string identity = context.User.FindFirstValue("id");
        TUser user = await userManager.FindByIdAsync(identity);

        if (!user.EmailConfirmed)
        {
            return Results.BadRequest("Email is not verified.");
        }

        // Already enabled
        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            return Results.Unauthorized();
        }

        // return a qrcode url for token totp authenticator.

        var token = await userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);

        var data = new EmailData(new string[] { user.Email }, "Enabling two-factor authentication (2FA) on your user account", token);
        var message = emailFactory.CreateEnable2faEmail(data);
        await emailSender.SendEmailAsync(message).ConfigureAwait(false);

        return Results.Ok();
    }

    /// <summary>
    /// Use this endpoint to finish enable 2fa process.
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [Authorize(AuthenticationSchemes = "jwt")]
    public virtual async Task<IResult> EnableTwoStepVerificationConfirm([FromBody] TwoStepVerificationConfirmRequest request,
        HttpContext context,
        UserManager<TUser> userManager)
    {
        //if (!ModelState.IsValid)
        //{
        //    return BadRequest();
        //}

        string identity = context.User.FindFirstValue("id");
        TUser user = await userManager.FindByIdAsync(identity);

        if (user == null)
        {
            return Results.Unauthorized();
        }

        if (!user.EmailConfirmed)
        {
            return Results.BadRequest("Email is not confirmed");
        }

        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            return Results.Unauthorized();
        }

        if (!await userManager.VerifyTwoFactorTokenAsync(user, request.Provider, request.Token))
        {
            return Results.BadRequest("Invalid two factor token");
        }

        await userManager.SetTwoFactorEnabledAsync(user, true);

        return Results.Ok();
    }

    /// <summary>
    /// Use this endpoint to login with 2fa process
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [HttpPost("two_step_verification_login")]
    public virtual async Task<IResult> TwoStepVerificationLogin([FromBody] TwoStepVerificationLoginRequest request,
        IAuthenticator<TUser> authenticator,
        UserManager<TUser> userManager,
        IEmailFactory emailFactory,
        IEmailSender emailSender)
    {
        //if (!ModelState.IsValid)
        //{
        //    return BadRequest();
        //}

        TUser? user = await authenticator.Authenticate(request.Username, request.Password);

        if (user == null)
        {
            return Results.BadRequest("Invalid credentials");
        }

        if (!await userManager.GetTwoFactorEnabledAsync(user))
        {
            return Results.Unauthorized();
        }

        if (!user.EmailConfirmed)
        {
            return Results.BadRequest("Email is not verified");
        }

        var providers = await userManager.GetValidTwoFactorProvidersAsync(user);

        if (!providers.Contains(request.Provider))
        {
            return Results.BadRequest();
        }

        if (request.Provider == "Email")
        {
            var token = await userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);

            // send email
            var data = new EmailData(new string[] { user.Email }, "Login verification code", token);
            var message = emailFactory.Create2faEmail(data);
            await emailSender.SendEmailAsync(message).ConfigureAwait(false);
        }

        return Results.Ok();
    }

    /// <summary>
    /// Use this endpoint to finish two step verification login process.
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [HttpPost("two_step_verification_confirm")]
    public virtual async Task<IResult> TwoStepVerificationConfirm([FromBody] TwoStepVerificationConfirmRequest request,
        UserManager<TUser> userManager,
        IAuthenticator<TUser> authenticator)
    {
        //if (!ModelState.IsValid)
        //{
        //    return BadRequest();
        //}

        var user = await userManager.FindByEmailAsync(request.Email);

        if (user == null)
        {
            return Results.BadRequest();
        }

        if (!await userManager.GetTwoFactorEnabledAsync(user))
        {
            return Results.Unauthorized();
        }

        var validToken = await userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, request.Token);

        if (!validToken)
        {
            return Results.BadRequest("Invalid token");
        }

        var response = await authenticator.Login(user);

        return Results.Ok(response);
    }
}
