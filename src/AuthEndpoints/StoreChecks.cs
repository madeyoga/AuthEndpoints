using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints;

/// <summary>
/// Fails at map time, with the fix in the message, when a feature's store is not registered. A resolve also runs the
/// store's own checks, such as an EF Core store's check that its table is mapped.
/// </summary>
internal static class StoreChecks
{
    /// <summary>Throws unless <typeparamref name="TStore"/> is registered.</summary>
    public static void EnsureRegistered<TStore>(IServiceProvider services, string feature)
        where TStore : class
    {
        if (services.GetService<IServiceProviderIsService>() is { } isService && !isService.IsService(typeof(TStore)))
        {
            throw Missing<TStore>(feature);
        }
    }

    /// <summary>Throws unless <typeparamref name="TStore"/> resolves in a new scope.</summary>
    public static void EnsureResolvable<TStore>(IServiceProvider services, string feature)
        where TStore : class
    {
        using var scope = services.CreateScope();
        if (scope.ServiceProvider.GetService<TStore>() is null)
        {
            throw Missing<TStore>(feature);
        }
    }

    /// <summary>
    /// Resolves <typeparamref name="TService"/> in a new scope. If that fails and <typeparamref name="TStore"/> is not
    /// registered, throws the missing-store message instead. A replaced service that needs no store resolves fine.
    /// </summary>
    public static void EnsureResolves<TService, TStore>(IServiceProvider services, string feature)
        where TService : class
        where TStore : class
    {
        using var scope = services.CreateScope();
        try
        {
            _ = scope.ServiceProvider.GetService<TService>();
        }
        catch (InvalidOperationException) when (
            services.GetService<IServiceProviderIsService>() is { } isService && !isService.IsService(typeof(TStore)))
        {
            throw Missing<TStore>(feature);
        }
    }

    private static InvalidOperationException Missing<TStore>(string feature)
    {
        var name = DisplayName(typeof(TStore));
        return new InvalidOperationException(
            $"{feature} needs an {name}. Add the AuthEndpoints.EntityFrameworkCore package and call "
            + "AddEntityFrameworkStores<TContext>() on the AddAuthEndpoints builder (or "
            + "AddAuthEndpointsEntityFrameworkStores<TUser, TContext>() with the Add*Endpoints building blocks), "
            + $"or register your own {name}.");
    }

    private static string DisplayName(Type type)
    {
        if (!type.IsGenericType)
        {
            return type.Name;
        }

        var name = type.Name[..type.Name.IndexOf('`')];
        return $"{name}<{string.Join(", ", type.GetGenericArguments().Select(DisplayName))}>";
    }
}
