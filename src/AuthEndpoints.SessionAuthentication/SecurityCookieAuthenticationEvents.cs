using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Session;

public class SecurityCookieAuthenticationEvents<TUser> : CookieAuthenticationEvents
    where TUser : class
{
    public const string LastChangedClaim = "LastChanged";

    private readonly UserManager<TUser> _userManager;

    public SecurityCookieAuthenticationEvents(UserManager<TUser> userManager)
    {
        _userManager = userManager;
    }

    public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
    {
        var user = context.Principal;
        var username = user?.Identity?.Name;

        // Validate last changed
        if (username == null)
        {
            context.RejectPrincipal();

            await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }

    private Task<bool> ValidateLastChanged(string username, string lastChanged)
    {
        return Task.FromResult(true);
    }

    public override Task RedirectToLogin(RedirectContext<CookieAuthenticationOptions> context)
        => SendStatus(context, StatusCodes.Status401Unauthorized);

    public override Task RedirectToAccessDenied(RedirectContext<CookieAuthenticationOptions> context)
        => SendStatus(context, StatusCodes.Status403Forbidden);

    private Task SendStatus(RedirectContext<CookieAuthenticationOptions> context, int statusCode)
    {
        context.Response.StatusCode = statusCode;

        return Task.CompletedTask;
    }
}
