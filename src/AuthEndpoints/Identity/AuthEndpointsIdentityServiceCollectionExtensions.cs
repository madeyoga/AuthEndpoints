using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Identity;

public static class AuthEndpointsIdentityServiceCollectionExtensions
{
    /// <summary>
    /// Registers Identity API endpoints, default token providers, authorization, and antiforgery. It registers no stores:
    /// add them to the returned builder, for example Identity's <c>AddEntityFrameworkStores&lt;TContext&gt;()</c>, or
    /// register your own <c>IUserStore&lt;TUser&gt;</c>.
    /// <see cref="SignInOptions.RequireConfirmedAccount"/> defaults to <see langword="true"/> and
    /// <see cref="StoreOptions.SchemaVersion"/> defaults to <see cref="IdentitySchemaVersions.Version3"/>.
    /// The <paramref name="configure"/> callback runs after those defaults.
    /// A later call for the same <typeparamref name="TUser"/> applies <paramref name="configure"/> through
    /// options configuration and does not reset <see cref="SignInOptions.RequireConfirmedAccount"/>.
    /// </summary>
    public static IdentityBuilder AddAuthEndpointsIdentity<TUser>(
        this IServiceCollection services,
        Action<IdentityOptions>? configure = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.Any(descriptor => descriptor.ServiceType == typeof(AuthEndpointsIdentityMarker<TUser>)))
        {
            if (configure is not null)
            {
                services.Configure(configure);
            }

            var roleType = services
                .Select(descriptor => descriptor.ServiceType)
                .FirstOrDefault(type => type.IsGenericType && type.GetGenericTypeDefinition() == typeof(RoleManager<>))
                ?.GetGenericArguments()[0];
            return roleType is null
                ? new IdentityBuilder(typeof(TUser), services)
                : new IdentityBuilder(typeof(TUser), roleType, services);
        }

        services.AddSingleton<AuthEndpointsIdentityMarker<TUser>>();
        SignInCompleterRegistry.AddIdentityCompleters(services);

        var identityBuilder = services.AddIdentityApiEndpoints<TUser>(identity =>
        {
            identity.SignIn.RequireConfirmedAccount = true;
            identity.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
            configure?.Invoke(identity);
        });

        identityBuilder.AddDefaultTokenProviders();
        services.AddAuthEndpointsAuthorizationAndAntiforgery();
        return identityBuilder;
    }
}

internal sealed class AuthEndpointsIdentityMarker<TUser>
    where TUser : class;
