using System.Security.Claims;
using AuthEndpoints.Models;
using AuthEndpoints.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthEndpoints.Controllers;

/// <summary>
/// Inherit this base class to define endpoints that contain 2fa process actions such as enable 2fa and login.
/// </summary>
/// <typeparam name="TUserKey"></typeparam>
/// <typeparam name="TUser"></typeparam>
[ApiController]
[Route("users/")]
public class TwoStepVerificationController<TUserKey, TUser> : ControllerBase
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>
{
    protected readonly UserManager<TUser> userManager;
    protected readonly IAuthenticator<TUser> authenticator;
    protected readonly IEmailSender emailSender;
    protected readonly IEmailFactory emailFactory;

    public TwoStepVerificationController(UserManager<TUser> userManager, IAuthenticator<TUser> authenticator, IEmailSender emailSender, IEmailFactory emailFactory)
    {
        this.userManager = userManager;
        this.authenticator = authenticator;
        this.emailSender = emailSender;
        this.emailFactory = emailFactory;
    }

    /// <summary>
    /// Use this endpoint to send email to user with 2fa token
    /// </summary>
    /// <returns></returns>
    [Authorize(AuthenticationSchemes = "jwt")]
    [HttpGet("enable_2fa")]
    public virtual async Task<IActionResult> EnableTwoStepVerification()
    {
        string identity = HttpContext.User.FindFirstValue("id");
        TUser user = await userManager.FindByIdAsync(identity);

        if (!user.EmailConfirmed)
        {
            return BadRequest("Email is not verified.");
        }

        // Already enabled
        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            return Unauthorized();
        }
        
        // return a qrcode url for token totp authenticator.

        var token = await userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);

        var data = new EmailData(new string[] { user.Email }, "Enabling two-factor authentication (2FA) on your user account", token);
        var message = emailFactory.CreateEnable2faEmail(data);
        await emailSender.SendEmailAsync(message).ConfigureAwait(false);

        return Ok();
    }

    /// <summary>
    /// Use this endpoint to finish enable 2fa process.
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [Authorize(AuthenticationSchemes = "jwt")]
    [HttpPost("enable_2fa_confirm")]
    public virtual async Task<IActionResult> EnableTwoStepVerificationConfirm([FromBody] TwoStepVerificationConfirmRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest();
        }

        string identity = HttpContext.User.FindFirstValue("id");
        TUser user = await userManager.FindByIdAsync(identity);

        if (user == null)
        {
            return Unauthorized("Invalid user");
        }

        if (!user.EmailConfirmed)
        {
            return BadRequest("Email is not confirmed");
        }

        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            return Unauthorized();
        }

        if (!await userManager.VerifyTwoFactorTokenAsync(user, request.Provider, request.Token))
        {
            return BadRequest("Invalid two factor token");
        }

        await userManager.SetTwoFactorEnabledAsync(user, true);

        return Ok();
    }

    /// <summary>
    /// Use this endpoint to login with 2fa process
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [HttpPost("two_step_verification_login")]
    public virtual async Task<IActionResult> TwoStepVerificationLogin([FromBody] TwoStepVerificationLoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest();
        }

        TUser? user = await authenticator.Authenticate(request.Username, request.Password);

        if (user == null)
        {
            return Unauthorized("Invalid credentials");
        }

        if (!await userManager.GetTwoFactorEnabledAsync(user))
        {
            return Unauthorized();
        }

        if (!user.EmailConfirmed)
        {
            return BadRequest("Email is not verified");
        }

        var providers = await userManager.GetValidTwoFactorProvidersAsync(user);

        if (!providers.Contains(request.Provider))
        {
            return BadRequest();
        }

        if (request.Provider == "Email")
        {
            var token = await userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);

            // send email
            var data = new EmailData(new string[] { user.Email }, "Login verification code", token);
            var message = emailFactory.Create2faEmail(data);
            await emailSender.SendEmailAsync(message).ConfigureAwait(false);
        }

        return Ok();
    }

    /// <summary>
    /// Use this endpoint to finish two step verification login process.
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [HttpPost("two_step_verification_confirm")]
    public virtual async Task<IActionResult> TwoStepVerificationConfirm([FromBody] TwoStepVerificationConfirmRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest();
        }

        var user = await userManager.FindByEmailAsync(request.Email);

        if (user == null)
        {
            return BadRequest();
        }

        if (!await userManager.GetTwoFactorEnabledAsync(user))
        {
            return Unauthorized();
        }

        var validToken = await userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, request.Token);

        if (!validToken)
        {
            return BadRequest("Invalid token");
        }

        var response = await authenticator.Login(user);

        return Ok(response);
    }
}
