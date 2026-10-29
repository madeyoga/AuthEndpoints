using System.Security.Claims;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.ReAuth;

/// <summary>
/// Keeps the caller's identity confirmation valid after an account change that rotates the security stamp.
/// The renewed proof keeps the original confirmation time and expiry, so it never extends the confirmation window.
/// </summary>
internal static class ReAuthProofRenewal
{
    public static async Task<AuthenticateResult?> CaptureAsync(HttpContext context)
    {
        var schemes = context.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
        if (await schemes.GetSchemeAsync(AuthEndpointsConstants.ReAuthScheme) is null)
        {
            return null;
        }

        var result = await context.AuthenticateAsync(AuthEndpointsConstants.ReAuthScheme);
        return result.Succeeded && result.Principal?.HasClaim("Reauth", "true") == true ? result : null;
    }

    public static async Task RenewAsync<TUser>(
        HttpContext context,
        UserManager<TUser> userManager,
        TUser user,
        AuthenticateResult? captured,
        string? stampBefore)
        where TUser : class
    {
        if (captured?.Principal is null || !userManager.SupportsUserSecurityStamp)
        {
            return;
        }

        var stampClaimType = userManager.Options.ClaimsIdentity.SecurityStampClaimType;
        if (!string.Equals(captured.Principal.FindFirst(stampClaimType)?.Value, stampBefore, StringComparison.Ordinal))
        {
            return;
        }

        var stampNow = await userManager.GetSecurityStampAsync(user);
        if (string.IsNullOrEmpty(stampNow) || string.Equals(stampNow, stampBefore, StringComparison.Ordinal))
        {
            return;
        }

        var claims = captured.Principal.Claims
            .Where(c => !string.Equals(c.Type, stampClaimType, StringComparison.Ordinal))
            .Select(c => new Claim(c.Type, c.Value))
            .Append(new Claim(stampClaimType, stampNow));
        var properties = new AuthenticationProperties
        {
            IsPersistent = false,
            ExpiresUtc = captured.Properties?.ExpiresUtc,
        };

        var scheme = AuthEndpointsConstants.ReAuthScheme;
        await context.SignInAsync(scheme, new ClaimsPrincipal(new ClaimsIdentity(claims, scheme)), properties);
    }
}
