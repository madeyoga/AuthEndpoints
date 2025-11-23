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
            .AddCookie(AuthEndpointsConstants.ReAuthScheme, options =>
            {
                options.Cookie.Name = AuthEndpointsConstants.ReAuthScheme;
                options.Cookie.HttpOnly = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                options.SlidingExpiration = false;
            });

        return services;
    }
}
