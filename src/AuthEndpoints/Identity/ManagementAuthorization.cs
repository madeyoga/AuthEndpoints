using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Identity;

/// <summary>
/// Sign-in schemes a host may register: application cookie, Identity bearer, and JWT bearer.
/// </summary>
internal static class SignInSchemes
{
    /// <summary>
    /// Identity type on a principal produced by the JWT bearer handler.
    /// It is not the <c>Bearer</c> scheme name.
    /// </summary>
    public const string JwtIdentityType = "AuthenticationTypes.Federation";

    public static readonly string[] Primary =
    [
        IdentityConstants.ApplicationScheme,
        IdentityConstants.BearerScheme,
        JwtBearerDefaults.AuthenticationScheme,
    ];

    public static string Application => Primary[0];

    public static IEnumerable<string> Bearer => Primary.Skip(1);

    public static bool IsPrimaryIdentity(ClaimsIdentity identity)
    {
        if (!identity.IsAuthenticated || string.IsNullOrEmpty(identity.AuthenticationType))
        {
            return false;
        }

        return Primary.Contains(identity.AuthenticationType, StringComparer.Ordinal)
            || string.Equals(identity.AuthenticationType, JwtIdentityType, StringComparison.Ordinal);
    }
}

internal static class ManagementAuthorization
{
    /// <summary>
    /// Builds an authorize attribute for cookie, Identity bearer, and JWT Bearer schemes
    /// that are actually registered on the host.
    /// </summary>
    public static AuthorizeAttribute CreateAuthorizeAttribute(IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var authOptions = endpoints.ServiceProvider.GetService<IOptions<AuthenticationOptions>>()?.Value;
        var registered = authOptions?.Schemes
            .Select(s => s.Name)
            .ToHashSet(StringComparer.Ordinal) ?? [];

        var schemes = SignInSchemes.Primary.Where(registered.Contains);

        return new AuthorizeAttribute
        {
            AuthenticationSchemes = string.Join(',', schemes)
        };
    }
}
