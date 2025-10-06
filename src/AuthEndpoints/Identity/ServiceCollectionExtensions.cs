using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Identity;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAuthEndpointsIdentity(this IServiceCollection services)
    {
        services.AddReAuthScheme();
        return services;
    }

    public static IServiceCollection AddReAuthScheme(this IServiceCollection services)
    {
        services.AddAuthentication()
            .AddCookie(AuthEndpointsConstants.ReAuthScheme);

        return services;
    }
}
