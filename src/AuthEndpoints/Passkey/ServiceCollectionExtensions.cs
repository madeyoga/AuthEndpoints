using System.Threading.RateLimiting;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Passkey;

internal sealed class PasskeyRateLimitMarker;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers ReAuth, login rate limiting, and passkey rate-limit policies.
    /// Hosts should also configure <c>IdentityPasskeyOptions</c> (ServerDomain, origins, etc.).
    /// </summary>
    public static IServiceCollection AddPasskeyEndpoints(this IServiceCollection services)
    {
        services.AddReAuthScheme();
        services.AddLoginRateLimiting();

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
