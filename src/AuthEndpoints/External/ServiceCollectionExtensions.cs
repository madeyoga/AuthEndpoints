using AuthEndpoints.Identity;
using AuthEndpoints.ReAuth;
using AuthEndpoints.SignIn;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth;

internal sealed class ExternalAuthEndpointsModule;

/// <summary>
/// DI registration for external OAuth endpoints.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers external auth core services and returns a builder for provider modules.
    /// Also registers login, account-abuse, and confirm-identity rate limits, the ReAuth scheme,
    /// and the cookie and Identity bearer sign-in completers.
    /// </summary>
    public static ExternalAuthBuilder AddExternalAuthEndpoints<TUser>(
        this IServiceCollection services,
        Action<ExternalAuthOptions>? configure = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddModule<ExternalAuthEndpointsModule>();
        services.AddOptions<ExternalAuthOptions>()
            .Configure(o => configure?.Invoke(o))
            .ValidateOnStart();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<ExternalAuthOptions>, ExternalAuthOptionsValidator>());

        services.TryAddScoped<ExternalLoginService<TUser>>();
        services.TryAddScoped<IExternalLoginCompleter<TUser>, CookieExternalLoginCompleter<TUser>>();
        SignInCompleterRegistry.AddIdentityCompleters(services);

        services.AddLoginRateLimiting();
        services.AddAccountAbuseRateLimiting();
        services.AddConfirmIdentityRateLimiting();
        services.AddReAuthScheme();

        // Ensure authentication services exist; provider modules add schemes.
        services.AddAuthentication();

        return new ExternalAuthBuilder(typeof(TUser), services);
    }
}
