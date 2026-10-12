using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace AuthEndpoints.Identity;

internal sealed class AuthEndpointsModule<TModule>
    where TModule : class;

internal static class AuthEndpointsModules
{
    public const string LogCategory = "AuthEndpoints";

    public static IServiceCollection AddModule<TModule>(this IServiceCollection services)
        where TModule : class
    {
        services.TryAddSingleton<AuthEndpointsModule<TModule>>();
        return services;
    }

    public static bool HasModule<TModule>(this IServiceCollection services)
        where TModule : class
    {
        return services.Any(descriptor => descriptor.ServiceType == typeof(AuthEndpointsModule<TModule>));
    }

    public static bool IsRegistered<TModule>(IServiceProvider services)
        where TModule : class
    {
        return services.GetService<AuthEndpointsModule<TModule>>() is not null;
    }

    public static void WarnIfMissing<TModule>(
        IEndpointRouteBuilder endpoints,
        string addMethod,
        string mapMethod)
        where TModule : class
    {
        if (IsRegistered<TModule>(endpoints.ServiceProvider))
        {
            return;
        }

        Log(endpoints, $"{addMethod} was not called before {mapMethod}.");
    }

    public static void Log(IEndpointRouteBuilder endpoints, string message)
    {
        endpoints.ServiceProvider
            .GetService<ILoggerFactory>()
            ?.CreateLogger(LogCategory)
            .LogWarning("{Message}", message);
    }
}

internal static class AuthEndpointsInfrastructure
{
    public static IServiceCollection AddAuthEndpointsAuthorizationAndAntiforgery(this IServiceCollection services)
    {
        services.AddAuthorization();
        services.AddAntiforgery();
        return services;
    }
}
