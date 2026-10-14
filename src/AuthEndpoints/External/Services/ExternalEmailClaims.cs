using System.Security.Claims;

namespace AuthEndpoints.External.OAuth;

/// <summary>
/// Helpers for reading email claims from external login principals.
/// </summary>
public static class ExternalEmailClaims
{
    public const string EmailVerifiedClaimType = "email_verified";

    /// <summary>
    /// Returns whether the principal has a verified email according to <c>email_verified=true</c>
    /// (OIDC / Google) or an equivalent claim value.
    /// </summary>
    public static bool IsEmailVerified(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var value = principal.FindFirstValue(EmailVerifiedClaimType)
            ?? principal.FindFirstValue("email_verified");

        return string.Equals(value, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "True", StringComparison.Ordinal);
    }

    public static string? GetEmail(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return principal.FindFirstValue(ClaimTypes.Email)
            ?? principal.FindFirstValue("email");
    }
}
