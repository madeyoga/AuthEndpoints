using AuthEndpoints.Identity;
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
    /// Maps the opinionated auth surface: cookie Identity at <see cref="AuthEndpointsOptions.IdentityPath"/>
    /// and (when enabled) passkeys at <see cref="AuthEndpointsOptions.PasskeyPath"/>.
    /// For advanced composition use <c>MapCookieAuthEndpoints</c>, <c>MapBearerAuthEndpoints</c>,
    /// <c>MapPasskeyEndpoints</c>, or <c>MapJwtAuthEndpoints</c> instead.
    /// </summary>
    public static IEndpointRouteBuilder MapAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<AuthEndpointsOptions>>().Value;

        endpoints.MapGroup(options.IdentityPath)
            .MapCookieAuthEndpoints<TUser>()
            .WithTags("Identity");

        if (options.Passkeys.Enabled)
        {
            endpoints.MapGroup(options.PasskeyPath)
                .MapPasskeyEndpoints<TUser>()
                .WithTags("Passkeys");
        }

        return endpoints;
    }
}
