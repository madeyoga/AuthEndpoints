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
    /// A later call for the same <typeparamref name="TUser"/> applies <paramref name="configure"/> through
    /// options configuration and does not reset <see cref="IdentityOptions.SignIn.RequireConfirmedAccount"/>.
    /// </summary>
    public static IdentityBuilder AddAuthEndpointsIdentity<TUser, TContext>(
        this IServiceCollection services,
        Action<IdentityOptions>? configure = null)
        where TUser : class, new()
        where TContext : DbContext
    {
        return AddAuthEndpointsIdentity<TUser, TContext>(services, configure, addRoles: null, roleType: null);
    }

    internal static IdentityBuilder AddAuthEndpointsIdentity<TUser, TContext>(
        this IServiceCollection services,
        Action<IdentityOptions>? configure,
        Func<IdentityBuilder, IdentityBuilder>? addRoles,
        Type? roleType)
        where TUser : class, new()
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.Any(descriptor => descriptor.ServiceType == typeof(AuthEndpointsIdentityMarker<TUser>)))
        {
            ApplyLaterIdentityCall<TUser, TContext>(services, configure, addRoles, roleType);
            return roleType is null
                ? new IdentityBuilder(typeof(TUser), services)
                : new IdentityBuilder(typeof(TUser), roleType, services);
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

    private static void ApplyLaterIdentityCall<TUser, TContext>(
        IServiceCollection services,
        Action<IdentityOptions>? configure,
        Func<IdentityBuilder, IdentityBuilder>? addRoles,
        Type? roleType)
        where TUser : class
        where TContext : DbContext
    {
        if (configure is not null)
        {
            services.Configure(configure);
        }

        if (roleType is null)
        {
            return;
        }

        var registered = services
            .Select(descriptor => descriptor.ServiceType)
            .FirstOrDefault(type => type.IsGenericType && type.GetGenericTypeDefinition() == typeof(RoleManager<>));
        if (registered is not null)
        {
            var registeredRole = registered.GetGenericArguments()[0];
            if (registeredRole == roleType)
            {
                return;
            }

            throw new InvalidOperationException(
                $"RoleManager<{registeredRole.Name}> is already registered. A later AddAuthEndpoints call requested RoleManager<{roleType.Name}>.");
        }

        var builder = addRoles is null
            ? new IdentityBuilder(typeof(TUser), roleType, services)
            : addRoles(new IdentityBuilder(typeof(TUser), services));
        builder.AddEntityFrameworkStores<TContext>();
    }
}

internal sealed class AuthEndpointsIdentityMarker<TUser>
    where TUser : class;
