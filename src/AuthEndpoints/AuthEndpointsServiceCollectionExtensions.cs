using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AuthEndpoints;

/// <summary>Registered by <c>AddAuthEndpoints</c> so <c>MapAuthEndpoints</c> can check it ran.</summary>
internal sealed class AuthEndpointsRegistration;

public static class AuthEndpointsServiceCollectionExtensions
{
    /// <summary>
    /// Registers Identity, the cookie session, and account management, and returns a builder that adds storage and
    /// sign-in methods: <see cref="AuthEndpointsBuilder.AddPassword"/>, <see cref="AuthEndpointsBuilder.AddPasskeys"/>,
    /// and <see cref="AuthEndpointsBuilder.AddEmailCode"/>.
    /// <c>MapAuthEndpoints</c> maps exactly what was added.
    /// Hosts must also call <c>UseAuthEndpoints</c>, and in Production register a real <c>IEmailSender&lt;TUser&gt;</c>.
    /// </summary>
    /// <remarks>
    /// Add storage with a store package, for example <c>AddEntityFrameworkStores&lt;TContext&gt;()</c> from
    /// AuthEndpoints.EntityFrameworkCore. For roles, call <see cref="AuthEndpointsBuilder.AddRoles{TRole}"/> before it.
    /// The builder is a shortcut over the <c>Add*Endpoints</c> building blocks. A host can mix the two:
    /// <c>MapAuthEndpoints</c> maps whatever is registered, whichever way it was added.
    /// </remarks>
    public static AuthEndpointsBuilder AddAuthEndpoints<TUser>(
        this IServiceCollection services,
        Action<AuthEndpointsOptions>? configure = null)
        where TUser : class, new()
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

        var identity = services.AddAuthEndpointsIdentity<TUser>();
        services.AddCookieSessionEndpoints();
        services.AddAccountManagementEndpoints();

        return new AuthEndpointsBuilder<TUser>(services, identity);
    }
}
