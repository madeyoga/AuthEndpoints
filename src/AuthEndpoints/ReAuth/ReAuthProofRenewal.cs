using System.Security.Claims;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.ReAuth;

/// <summary>
/// Keeps the caller's identity confirmation valid after an account change that rotates the security stamp.
/// A ReAuth cookie is reissued; a proof sent in the <c>X-AuthEndpoints-Reauth</c> header is returned renewed
/// in the same response header. The renewed proof keeps the original expiry, so it never extends the confirmation window.
/// </summary>
internal static class ReAuthProofRenewal
{
    internal sealed record CapturedProof(AuthenticateResult? Cookie, AuthenticateResult? Header);

    public static async Task<CapturedProof?> CaptureAsync(HttpContext context)
    {
        var schemes = context.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
        var cookie = await AuthenticateProofAsync(context, schemes, AuthEndpointsConstants.ReAuthScheme);
        var header = await AuthenticateProofAsync(context, schemes, AuthEndpointsConstants.ReAuthBearerScheme);
        return cookie is null && header is null ? null : new CapturedProof(cookie, header);
    }

    public static async Task RenewAsync<TUser>(
        HttpContext context,
        UserManager<TUser> userManager,
        TUser user,
        CapturedProof? captured,
        string? stampBefore)
        where TUser : class
    {
        if (captured is null || !userManager.SupportsUserSecurityStamp)
        {
            return;
        }

        var stampNow = await userManager.GetSecurityStampAsync(user);
        if (string.IsNullOrEmpty(stampNow) || string.Equals(stampNow, stampBefore, StringComparison.Ordinal))
        {
            return;
        }

        var stampClaimType = userManager.Options.ClaimsIdentity.SecurityStampClaimType;
        if (RenewedClaims(captured.Cookie, stampClaimType, stampBefore, stampNow) is { } cookieClaims)
        {
            var properties = new AuthenticationProperties
            {
                IsPersistent = false,
                ExpiresUtc = captured.Cookie!.Properties?.ExpiresUtc,
            };
            var scheme = AuthEndpointsConstants.ReAuthScheme;
            await context.SignInAsync(scheme, new ClaimsPrincipal(new ClaimsIdentity(cookieClaims, scheme)), properties);
        }

        if (RenewedClaims(captured.Header, stampClaimType, stampBefore, stampNow) is { } headerClaims
            && captured.Header!.Properties?.ExpiresUtc is { } expires)
        {
            var tokens = context.RequestServices.GetRequiredService<ReAuthTokenService>();
            context.Response.Headers[AuthEndpointsConstants.ReAuthHeaderName] = tokens.CreateToken(headerClaims, expires);
        }
    }

    private static async Task<AuthenticateResult?> AuthenticateProofAsync(
        HttpContext context,
        IAuthenticationSchemeProvider schemes,
        string scheme)
    {
        if (await schemes.GetSchemeAsync(scheme) is null)
        {
            return null;
        }

        var result = await context.AuthenticateAsync(scheme);
        return result.Succeeded && result.Principal?.HasClaim("Reauth", "true") == true ? result : null;
    }

    private static List<Claim>? RenewedClaims(
        AuthenticateResult? proof,
        string stampClaimType,
        string? stampBefore,
        string stampNow)
    {
        if (proof?.Principal is not { } principal
            || !string.Equals(principal.FindFirst(stampClaimType)?.Value, stampBefore, StringComparison.Ordinal))
        {
            return null;
        }

        return principal.Claims
            .Where(c => !string.Equals(c.Type, stampClaimType, StringComparison.Ordinal))
            .Select(c => new Claim(c.Type, c.Value))
            .Append(new Claim(stampClaimType, stampNow))
            .ToList();
    }
}
