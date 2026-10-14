using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

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
        services.TryAddScoped(typeof(IAccountSecurityEmailSender<>), typeof(LoggingAccountSecurityEmailSender<>));
        ReplaceDefaultAuthorizationResultHandler(services);
        return services;
    }

    private static void ReplaceDefaultAuthorizationResultHandler(IServiceCollection services)
    {
        var existing = services
            .Where(descriptor => descriptor.ServiceType == typeof(IAuthorizationMiddlewareResultHandler))
            .ToArray();
        if (existing.Any(descriptor => descriptor.ImplementationType != typeof(AuthorizationMiddlewareResultHandler)))
        {
            return;
        }

        foreach (var descriptor in existing)
        {
            services.Remove(descriptor);
        }

        services.AddSingleton<IAuthorizationMiddlewareResultHandler, SetPasswordAvailabilityResultHandler>();
    }
}
