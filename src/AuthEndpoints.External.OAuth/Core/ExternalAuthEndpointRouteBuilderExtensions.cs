using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.External;

/// <summary>
/// Endpoint mapping helpers for external OAuth providers.
/// </summary>
public static class ExternalAuthEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps login and callback routes for every registered <see cref="IExternalAuthProvider"/>.
    /// </summary>
    public static IEndpointConventionBuilder MapExternalAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        var group = endpoints.MapGroup("");
        var providers = endpoints.ServiceProvider.GetServices<IExternalAuthProvider>().ToList();

        foreach (var provider in providers)
        {
            MapProviderEndpoints<TUser>(group, provider);
        }

        return group;
    }

    /// <summary>
    /// Maps login and callback routes for a single provider.
    /// </summary>
    public static IEndpointConventionBuilder MapExternalAuthProvider<TUser>(
        this IEndpointRouteBuilder endpoints,
        IExternalAuthProvider provider)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(provider);
        var group = endpoints.MapGroup("");
        MapProviderEndpoints<TUser>(group, provider);
        return group;
    }

    /// <summary>
    /// Maps login and callback routes for the registered provider with the given scheme.
    /// </summary>
    public static IEndpointConventionBuilder MapExternalAuthProvider<TUser>(
        this IEndpointRouteBuilder endpoints,
        string scheme)
        where TUser : class, new()
    {
        ArgumentException.ThrowIfNullOrEmpty(scheme);

        var provider = endpoints.ServiceProvider
            .GetServices<IExternalAuthProvider>()
            .FirstOrDefault(p => string.Equals(p.Scheme, scheme, StringComparison.Ordinal));

        if (provider is null)
        {
            throw new InvalidOperationException(
                $"No IExternalAuthProvider with scheme '{scheme}' is registered. Call Add{{Provider}} on ExternalAuthBuilder first.");
        }

        return endpoints.MapExternalAuthProvider<TUser>(provider);
    }

    private static void MapProviderEndpoints<TUser>(IEndpointRouteBuilder group, IExternalAuthProvider provider)
        where TUser : class, new()
    {
        group.MapGet(provider.LoginPath, (
            string? returnUrl,
            HttpContext context,
            LinkGenerator linkGenerator,
            Microsoft.AspNetCore.Identity.SignInManager<TUser> signInManager) =>
                ExternalAuthEndpoints<TUser>.Login(returnUrl, context, linkGenerator, signInManager, provider))
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy);

        group.MapGet(provider.CallbackPath, ExternalAuthEndpoints<TUser>.Callback)
            .WithName(provider.CallbackEndpointName);
    }
}
