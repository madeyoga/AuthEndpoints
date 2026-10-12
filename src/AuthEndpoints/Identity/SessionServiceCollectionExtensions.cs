using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Identity;

public static class SessionServiceCollectionExtensions
{
    /// <summary>
    /// Registers authorization and antiforgery for cookie logout and <c>GET /csrfToken</c>.
    /// Safe to call more than once.
    /// </summary>
    public static IServiceCollection AddCookieSessionEndpoints(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.HasModule<CookieSessionEndpointsModule>())
        {
            return services;
        }

        services.AddModule<CookieSessionEndpointsModule>();
        services.AddAuthEndpointsAuthorizationAndAntiforgery();
        return services;
    }

    /// <summary>
    /// Registers the marker for Identity bearer refresh and logout.
    /// Safe to call more than once. Authorization is registered by the sign-in or account <c>Add*</c> methods.
    /// </summary>
    public static IServiceCollection AddBearerSessionEndpoints(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.HasModule<BearerSessionEndpointsModule>())
        {
            return services;
        }

        services.AddModule<BearerSessionEndpointsModule>();
        return services;
    }
}
