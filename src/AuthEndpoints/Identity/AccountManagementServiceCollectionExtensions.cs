using AuthEndpoints.ReAuth;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Identity;

public static class AccountManagementServiceCollectionExtensions
{
    /// <summary>
    /// Registers ReAuth schemes, the account-abuse, confirm-identity, and email-code confirm
    /// rate-limit policies, authorization, and antiforgery used by account management.
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
        services.AddConfirmIdentityEmailCodeRateLimiting();
        services.AddAuthEndpointsAuthorizationAndAntiforgery();
        return services;
    }
}
