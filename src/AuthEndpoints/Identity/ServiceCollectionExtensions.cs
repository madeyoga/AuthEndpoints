using System.Threading.RateLimiting;
using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Identity;

internal sealed class LoginRateLimitMarker;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the ReAuth cookie scheme and login rate limiting used by cookie Identity endpoints.
    /// For passkeys, also call <c>AddPasskeyEndpoints</c> (or call only that if you need both).
    /// </summary>
    public static IServiceCollection AddCookieAuthEndpoints(this IServiceCollection services)
    {
        services.AddReAuthScheme();
        services.AddLoginRateLimiting();
        return services;
    }

    internal static IServiceCollection AddLoginRateLimiting(this IServiceCollection services)
    {
        if (services.Any(d => d.ServiceType == typeof(LoginRateLimitMarker)))
        {
            return services;
        }

        services.AddSingleton<LoginRateLimitMarker>();

        services.AddRateLimiter(options =>
        {
            options.AddPolicy(AuthEndpointsConstants.LoginPolicy, context =>
            {
                var key = context.Connection.RemoteIpAddress?.ToString() ?? "anon";

                return RateLimitPartition.GetTokenBucketLimiter(key, _ => new TokenBucketRateLimiterOptions
                {
                    TokenLimit = 10,
                    TokensPerPeriod = 2,
                    ReplenishmentPeriod = TimeSpan.FromSeconds(10),
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
            });
        });

        return services;
    }
}
