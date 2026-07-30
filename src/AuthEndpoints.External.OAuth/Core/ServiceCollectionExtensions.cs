using AuthEndpoints.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth;

/// <summary>
/// DI registration for external OAuth endpoints (shared Core).
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers external auth core services and returns a builder for provider modules.
    /// Also registers the login rate-limit policy used by OAuth login endpoints.
    /// </summary>
    public static ExternalAuthBuilder AddExternalAuthEndpoints<TUser>(
        this IServiceCollection services,
        Action<ExternalAuthOptions>? configure = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<ExternalAuthOptions>()
            .Configure(o => configure?.Invoke(o))
            .ValidateOnStart();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<ExternalAuthOptions>, ExternalAuthOptionsValidator>());

        services.TryAddScoped<ExternalLoginService<TUser>>();
        services.TryAddScoped<IExternalLoginCompleter<TUser>, CookieExternalLoginCompleter<TUser>>();

        services.AddLoginRateLimiting();

        // Ensure authentication services exist; provider modules add schemes.
        services.AddAuthentication();

        return new ExternalAuthBuilder(typeof(TUser), services);
    }
}
