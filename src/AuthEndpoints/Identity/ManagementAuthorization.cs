using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace AuthEndpoints.Identity;

internal static class SignInSchemes
{
    // JwtBearer leaves AuthenticationType at TokenValidationParameters.DefaultAuthenticationType, not the Bearer scheme name.
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

    public static bool HasBearerAuthorizationHeader(HttpRequest request)
    {
        var values = request.Headers.Authorization;
        if (StringValues.IsNullOrEmpty(values))
        {
            return false;
        }

        foreach (var value in values)
        {
            if (string.IsNullOrEmpty(value))
            {
                continue;
            }

            const string prefix = "Bearer ";
            if (value.Length > prefix.Length
                && value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(value[prefix.Length..]))
            {
                return true;
            }
        }

        return false;
    }

    public static async Task<bool> IsAuthenticatedAsync(HttpContext httpContext, string scheme)
    {
        var schemeProvider = httpContext.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
        if (await schemeProvider.GetSchemeAsync(scheme) is null)
        {
            return false;
        }

        var result = await httpContext.AuthenticateAsync(scheme);
        return result.Succeeded && result.Principal?.Identity?.IsAuthenticated == true;
    }
}

internal static class ManagementAuthorization
{
    public static AuthorizeAttribute CreateAuthorizeAttribute(IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return CreateAttribute(endpoints.ServiceProvider);
    }

    internal static AuthorizeAttribute CreateAttribute(IServiceProvider services)
    {
        var authOptions = services.GetService<IOptions<AuthenticationOptions>>()?.Value;
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
