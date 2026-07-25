using System.Threading.RateLimiting;
using AuthEndpoints.Identity;
using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Passkey;

internal sealed class PasskeyRateLimitMarker;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers ReAuth, Identity rate limiting, and passkey rate-limit policies.
    /// Hosts must call <c>UseRateLimiter()</c>, serve over HTTPS, and configure
    /// <c>IdentityPasskeyOptions</c> (<c>ServerDomain</c>, allowed origins, etc.).
    /// </summary>
    public static IServiceCollection AddPasskeyEndpoints(this IServiceCollection services)
    {
        services.AddReAuthScheme();
        services.AddIdentityEndpointRateLimiting();

        if (services.Any(d => d.ServiceType == typeof(PasskeyRateLimitMarker)))
        {
            return services;
        }

        services.AddSingleton<PasskeyRateLimitMarker>();

        services.AddRateLimiter(options =>
        {
            options.AddPolicy(AuthEndpointsConstants.PasskeyObtainOptionsPolicy, context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 5,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0
                    }));

            options.AddPolicy(AuthEndpointsConstants.PasskeyRegisterPolicy, context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 3,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0
                    }));
        });

        return services;
    }
}
