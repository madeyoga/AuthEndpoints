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
        services.TryAddSingleton(AuthEndpointsFeatures.Resolve);
        return services;
    }

    public static bool HasModule<TModule>(this IServiceCollection services)
        where TModule : class
    {
        return services.Any(descriptor => descriptor.ServiceType == typeof(AuthEndpointsModule<TModule>));
    }

    /// <summary>
    /// Reads one module marker. Only <see cref="AuthEndpointsFeatures.Resolve"/> should call this;
    /// route conditions read <see cref="AuthEndpointsFeatures"/>.
    /// </summary>
    internal static bool IsRegistered<TModule>(IServiceProvider services)
        where TModule : class
    {
        return services.GetService<AuthEndpointsModule<TModule>>() is not null;
    }

    public static void LogNoSignInModule(IEndpointRouteBuilder endpoints)
    {
        Logger(endpoints)?.LogWarning(
            "MapSignInEndpoints mapped no sign-in method. Call AddPasswordSignInEndpoints, AddEmailCodeSignInEndpoints, AddPasskeySignInEndpoints, or AddPasskeySignUpEndpoints before MapSignInEndpoints.");
    }

    public static void LogDuplicateRoute(
        IEndpointRouteBuilder endpoints,
        string existingMap,
        string mapMethod,
        string route)
    {
        Logger(endpoints)?.LogWarning(
            "{ExistingMap} and {MapMethod} both map {Route}.",
            existingMap,
            mapMethod,
            route);
    }

    public static void LogPasskeyConfirmNameTreatedAsEndpoint(IEndpointRouteBuilder endpoints)
    {
        Logger(endpoints)?.LogWarning(
            "MapPasskeySignInEndpoints treated the string argument as the confirm-email endpoint name, not a sign-in completer. Pass AuthEndpointsSession, or pass completer: together with confirmEmailEndpointName.");
    }

    private static ILogger? Logger(IEndpointRouteBuilder endpoints)
    {
        return endpoints.ServiceProvider
            .GetService<ILoggerFactory>()
            ?.CreateLogger(LogCategory);
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
