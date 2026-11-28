using AuthEndpoints.Jwt;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthEndpoints.OpenIddict;

public static class OAuthServerEntityFrameworkCoreExtensions
{
    /// <summary>
    /// Stores the OAuth server in <typeparamref name="TContext"/>: OpenIddict's EF Core stores (applications,
    /// authorizations, scopes and tokens), and the AuthEndpoints stores for pending consent requests and developer apps.
    /// </summary>
    /// <remarks>
    /// Call <c>modelBuilder.UseAuthEndpointsOpenIddict&lt;TUser&gt;()</c> in <typeparamref name="TContext"/>'s
    /// <c>OnModelCreating</c>, with the same <c>TUser</c> as <c>AddOAuthServer</c>, then add a migration.
    /// Events raised while <typeparamref name="TContext"/> has a transaction open wait for its commit.
    /// </remarks>
    public static OAuthServerBuilder AddEntityFrameworkStores<TContext>(this OAuthServerBuilder builder)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        var services = builder.Services;
        if (services.Any(service => service.ServiceType == typeof(EntityFrameworkStoresMarker)))
        {
            throw new InvalidOperationException("AddEntityFrameworkStores<TContext>() was already called on this OAuth server.");
        }

        services.AddSingleton<EntityFrameworkStoresMarker>();
        var keyType = TypeHelper.FindKeyType(builder.UserType);

        services.TryAddSingleton<OAuthEventTransactions>();
        services.ConfigureDbContext<TContext>((provider, db) => db.AddInterceptors(provider.GetRequiredService<OAuthEventTransactions>()));
        services.TryAddScoped(
            typeof(IOAuthRequestStore<>).MakeGenericType(keyType),
            typeof(EntityFrameworkOAuthRequestStore<,>).MakeGenericType(typeof(TContext), keyType));
        services.TryAddScoped(
            typeof(IOAuthDeveloperAppStore<>).MakeGenericType(keyType),
            typeof(EntityFrameworkOAuthDeveloperAppStore<,>).MakeGenericType(typeof(TContext), keyType));
        services.TryAddScoped<IOAuthServerQueries, EntityFrameworkOAuthServerQueries<TContext>>();
        services.TryAddScoped<IOAuthServerEventTransactions, EntityFrameworkOAuthServerEventTransactions<TContext>>();
        services.TryAddScoped<IOAuthAuthorizationRefresher, EntityFrameworkOAuthAuthorizationRefresher<TContext>>();
        builder.OpenIddict.AddCore(options => options.UseEntityFrameworkCore().UseDbContext<TContext>());
        return builder;
    }

    private sealed class EntityFrameworkStoresMarker;
}
