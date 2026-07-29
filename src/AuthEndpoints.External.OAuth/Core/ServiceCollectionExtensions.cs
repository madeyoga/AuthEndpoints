using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthEndpoints.External;

/// <summary>
/// DI registration for external OAuth endpoints (shared Core).
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers external auth core services and returns a builder for provider modules.
    /// </summary>
    public static ExternalAuthBuilder AddExternalAuthEndpoints<TUser>(
        this IServiceCollection services,
        Action<ExternalAuthOptions>? configure = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(services);

        var optionsBuilder = services.AddOptions<ExternalAuthOptions>();
        if (configure is not null)
        {
            optionsBuilder.Configure(configure);
        }

        services.TryAddScoped<ExternalLoginService<TUser>>();
        services.TryAddScoped<IExternalLoginCompleter<TUser>, CookieExternalLoginCompleter<TUser>>();

        // Ensure authentication services exist; provider modules add schemes.
        services.AddAuthentication();

        return new ExternalAuthBuilder(typeof(TUser), services);
    }
}
