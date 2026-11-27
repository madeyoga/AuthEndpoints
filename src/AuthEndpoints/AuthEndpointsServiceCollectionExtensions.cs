using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AuthEndpoints;

/// <summary>Registered by <c>AddAuthEndpoints</c> so <c>MapAuthEndpoints</c> can check it ran.</summary>
internal sealed class AuthEndpointsRegistration;

public static class AuthEndpointsServiceCollectionExtensions
{
    /// <summary>
    /// Registers Identity with EF stores, the cookie session, and account management, and returns a builder
    /// that adds sign-in methods: <see cref="AuthEndpointsBuilder{TUser, TContext}.AddPassword"/>,
    /// <see cref="AuthEndpointsBuilder{TUser, TContext}.AddPasskeys"/>, and
    /// <see cref="AuthEndpointsBuilder{TUser, TContext}.AddEmailCode"/>.
    /// <c>MapAuthEndpoints</c> maps exactly what was added.
    /// Hosts must also call <c>UseAuthEndpoints</c>, and in Production register a real <c>IEmailSender&lt;TUser&gt;</c>.
    /// </summary>
    /// <remarks>
    /// The builder is a shortcut over the <c>Add*Endpoints</c> building blocks. A host can mix the two:
    /// <c>MapAuthEndpoints</c> maps whatever is registered, whichever way it was added.
    /// For roles, call <see cref="AddAuthEndpoints{TUser, TRole, TContext}(IServiceCollection, Action{AuthEndpointsOptions}?)"/>
    /// so <c>AddRoles</c> runs before <c>AddEntityFrameworkStores</c>.
    /// </remarks>
    public static AuthEndpointsBuilder<TUser, TContext> AddAuthEndpoints<TUser, TContext>(
        this IServiceCollection services,
        Action<AuthEndpointsOptions>? configure = null)
        where TUser : class, new()
        where TContext : DbContext
    {
        return AddCore<TUser, TContext>(services, configure, addRoles: null, roleType: null);
    }

    /// <summary>
    /// Same as <see cref="AddAuthEndpoints{TUser, TContext}(IServiceCollection, Action{AuthEndpointsOptions}?)"/>,
    /// and registers Identity roles (<typeparamref name="TRole"/>) before EF stores so <c>IRoleStore</c> is available
    /// and sign-in includes role claims.
    /// </summary>
    public static AuthEndpointsBuilder<TUser, TContext> AddAuthEndpoints<TUser, TRole, TContext>(
        this IServiceCollection services,
        Action<AuthEndpointsOptions>? configure = null)
        where TUser : class, new()
        where TRole : class
        where TContext : DbContext
    {
        return AddCore<TUser, TContext>(services, configure, builder => builder.AddRoles<TRole>(), typeof(TRole));
    }

    private static AuthEndpointsBuilder<TUser, TContext> AddCore<TUser, TContext>(
        IServiceCollection services,
        Action<AuthEndpointsOptions>? configure,
        Func<IdentityBuilder, IdentityBuilder>? addRoles,
        Type? roleType)
        where TUser : class, new()
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<AuthEndpointsRegistration>();
        var options = services.AddOptions<AuthEndpointsOptions>().ValidateOnStart();
        if (configure is not null)
        {
            options.Configure(configure);
        }

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<AuthEndpointsOptions>, AuthEndpointsOptionsValidator>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<AuthEndpointsOptions>, AuthEndpointsEmailSenderValidator<TUser>>());

        // Roles must be configured before AddEntityFrameworkStores so IRoleStore is registered.
        var identity = services.AddAuthEndpointsIdentity<TUser, TContext>(configure: null, addRoles, roleType);
        services.AddCookieSessionEndpoints();
        services.AddAccountManagementEndpoints();

        return new AuthEndpointsBuilder<TUser, TContext>(services, identity);
    }
}
