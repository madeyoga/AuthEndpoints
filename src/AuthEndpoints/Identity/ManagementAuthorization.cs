using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Identity;

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

        var schemes = new[]
        {
            IdentityConstants.ApplicationScheme,
            IdentityConstants.BearerScheme,
            JwtBearerDefaults.AuthenticationScheme
        }.Where(registered.Contains);

        return new AuthorizeAttribute
        {
            AuthenticationSchemes = string.Join(',', schemes)
        };
    }
}
