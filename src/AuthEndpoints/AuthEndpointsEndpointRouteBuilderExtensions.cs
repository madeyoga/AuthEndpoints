using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints;

public static class AuthEndpointsEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the opinionated auth surface: Identity management + cookie sign-in at
    /// <see cref="AuthEndpointsOptions.IdentityPath"/>, passkeys at
    /// <see cref="AuthEndpointsOptions.PasskeyPath"/> when enabled, and JWT when
    /// <see cref="AuthEndpointsJwtOptions.Enabled"/> is true.
    /// For advanced composition use <c>MapIdentityManagementApi</c>, <c>MapCookieAuthEndpoints</c>,
    /// <c>MapBearerAuthEndpoints</c>, <c>MapPasskeyEndpoints</c>, or <c>MapJwtAuthEndpoints</c>.
    /// </summary>
    public static IEndpointConventionBuilder MapAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<AuthEndpointsOptions>>().Value;

        var identity = endpoints.MapGroup(options.IdentityPath).WithTags("Identity");
        identity.MapIdentityManagementApi<TUser>();
        identity.MapCookieAuthEndpoints<TUser>();

        if (options.Passkeys.Enabled)
        {
            endpoints.MapGroup(options.PasskeyPath)
                .MapPasskeyEndpoints<TUser>()
                .WithTags("Passkeys");
        }

        if (options.Jwt.Enabled)
        {
            endpoints.MapGroup(options.Jwt.Path)
                .MapJwtAuthEndpoints<TUser>()
                .WithTags("Jwt");
        }

        return identity;
    }
}
