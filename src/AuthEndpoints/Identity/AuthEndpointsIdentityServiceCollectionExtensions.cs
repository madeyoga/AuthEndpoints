using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Identity;

public static class AuthEndpointsIdentityServiceCollectionExtensions
{
    /// <summary>
    /// Registers Identity API endpoints, EF stores, default token providers, authorization, and antiforgery.
    /// <see cref="IdentityOptions.SignIn.RequireConfirmedAccount"/> defaults to <see langword="true"/> and
    /// <see cref="IdentityOptions.Stores.SchemaVersion"/> defaults to <see cref="IdentitySchemaVersions.Version3"/>.
    /// The <paramref name="configure"/> callback runs after those defaults.
    /// Safe to call once per <typeparamref name="TUser"/>; a later call is ignored.
    /// </summary>
    public static IdentityBuilder AddAuthEndpointsIdentity<TUser, TContext>(
        this IServiceCollection services,
        Action<IdentityOptions>? configure = null)
        where TUser : class, new()
        where TContext : DbContext
    {
        return AddAuthEndpointsIdentity<TUser, TContext>(services, configure, addRoles: null);
    }

    internal static IdentityBuilder AddAuthEndpointsIdentity<TUser, TContext>(
        this IServiceCollection services,
        Action<IdentityOptions>? configure,
        Func<IdentityBuilder, IdentityBuilder>? addRoles)
        where TUser : class, new()
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.Any(descriptor => descriptor.ServiceType == typeof(AuthEndpointsIdentityMarker<TUser>)))
        {
            return new IdentityBuilder(typeof(TUser), services);
        }

        services.AddSingleton<AuthEndpointsIdentityMarker<TUser>>();

        var identityBuilder = services.AddIdentityApiEndpoints<TUser>(identity =>
        {
            identity.SignIn.RequireConfirmedAccount = true;
            identity.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
            configure?.Invoke(identity);
        });

        if (addRoles is not null)
        {
            identityBuilder = addRoles(identityBuilder);
        }

        identityBuilder = identityBuilder
            .AddEntityFrameworkStores<TContext>()
            .AddDefaultTokenProviders();

        services.AddAuthEndpointsAuthorizationAndAntiforgery();
        return identityBuilder;
    }
}

internal sealed class AuthEndpointsIdentityMarker<TUser>
    where TUser : class;
