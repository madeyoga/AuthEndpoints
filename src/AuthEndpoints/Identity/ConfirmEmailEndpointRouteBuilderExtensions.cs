using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Identity;

public static class ConfirmEmailEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps <c>GET /confirmEmail</c> and <c>POST /resendConfirmationEmail</c>.
    /// The confirm route is named <paramref name="confirmEmailEndpointName"/>, or
    /// <see cref="AuthEndpointsEndpointNames.ConfirmEmail{TUser}"/> when the argument is null.
    /// A name that is already mapped in this app is left in place.
    /// </summary>
    public static IEndpointConventionBuilder MapConfirmEmailEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var name = confirmEmailEndpointName ?? AuthEndpointsEndpointNames.ConfirmEmail<TUser>();
        if (!ConfirmEmailEndpointRegistry.TryAdd(endpoints.ServiceProvider, name))
        {
            return EmptyEndpointConventionBuilder.Instance;
        }

        if (endpoints.ServiceProvider.GetService<AccountAbuseRateLimitMarker>() is null)
        {
            AuthEndpointsModules.Log(
                endpoints,
                "AddAccountAbuseRateLimiting was not called before MapConfirmEmailEndpoints.");
        }

        return IdentityEndpointRoutes.MapConfirmEmail<TUser>(endpoints, name);
    }

    internal static void EnsureConfirmEmailMapped<TUser>(
        IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName)
        where TUser : class, new()
    {
        endpoints.MapConfirmEmailEndpoints<TUser>(confirmEmailEndpointName);
    }
}
