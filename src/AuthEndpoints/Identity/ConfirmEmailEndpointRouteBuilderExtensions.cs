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
    /// A name that is already mapped in this app is left in place, and this method returns a no-op builder.
    /// Conventions added to that no-op builder, such as <c>WithTags</c> or <c>RequireCors</c>, do not reach the existing route.
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

        return IdentityEndpointRoutes.MapConfirmEmail<TUser>(endpoints, name, nameof(MapConfirmEmailEndpoints));
    }
}
