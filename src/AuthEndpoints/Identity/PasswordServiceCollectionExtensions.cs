using AuthEndpoints.SignIn;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Identity;

public static class PasswordServiceCollectionExtensions
{
    /// <summary>
    /// Registers the login and account-abuse rate-limit policies, authorization, and antiforgery
    /// used by password sign-up and sign-in routes.
    /// Safe to call more than once. Hosts must call <c>UseRateLimiter()</c> for the policies to apply.
    /// </summary>
    public static IServiceCollection AddPasswordEndpoints(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.HasModule<PasswordEndpointsModule>())
        {
            return services;
        }

        services.AddModule<PasswordEndpointsModule>();
        SignInCompleterRegistry.AddIdentityCompleters(services);
        services.AddLoginRateLimiting();
        services.AddAccountAbuseRateLimiting();
        services.AddAuthEndpointsAuthorizationAndAntiforgery();
        return services;
    }
}
