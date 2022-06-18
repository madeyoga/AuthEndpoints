using AuthEndpoints.Models;
using AuthEndpoints.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.MinimalApi;
public interface IBasicAuthEndpointDefinition<TKey, TUser>
    where TKey : IEquatable<TKey>
    where TUser : IdentityUser<TKey>, new()
{
    Task<IResult> Delete(HttpContext context, UserManager<TUser> userManager);
    Task<IResult> EmailVerification(HttpContext context, UserManager<TUser> userManager, IOptions<AuthEndpointsOptions> opt, IEmailFactory emailFactory, IEmailSender emailSender);
    Task<IResult> EmailVerificationConfirm([FromBody] ConfirmEmailRequest request, UserManager<TUser> userManager);
    Task<IResult> GetMe(HttpContext context, UserManager<TUser> userManager);
    Task<IResult> Register([FromBody] RegisterRequest request, UserManager<TUser> userManager, IdentityErrorDescriber errorDescriber);
    Task<IResult> ResetPassword([FromBody] ResetPasswordRequest request, UserManager<TUser> userManager, IOptions<AuthEndpointsOptions> opt, IEmailFactory emailFactory, IEmailSender emailSender);
    Task<IResult> ResetPasswordConfirm([FromBody] ResetPasswordConfirmRequest request, UserManager<TUser> userManager);
    Task<IResult> SetPassword([FromBody] SetPasswordRequest request, HttpContext context, UserManager<TUser> userManager);
    Task<IResult> SetUsername([FromBody] SetUsernameRequest request, HttpContext context, UserManager<TUser> userManager);
}
