using AuthEndpoints.ReAuth;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Identity;

public static class AccountManagementServiceCollectionExtensions
{
    /// <summary>
    /// Registers ReAuth schemes, the account-abuse and confirm-identity rate-limit policies,
    /// authorization, and antiforgery used by account management.
    /// Safe to call more than once. Hosts must call <c>UseRateLimiter()</c> for the policies to apply.
    /// </summary>
    public static IServiceCollection AddAccountManagementEndpoints(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.HasModule<AccountManagementEndpointsModule>())
        {
            return services;
        }

        services.AddModule<AccountManagementEndpointsModule>();
        services.AddReAuthScheme();
        services.AddAccountAbuseRateLimiting();
        services.AddConfirmIdentityRateLimiting();
        services.AddAuthEndpointsAuthorizationAndAntiforgery();
        return services;
    }
}
