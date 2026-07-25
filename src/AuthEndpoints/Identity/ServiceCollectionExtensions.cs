using System.Threading.RateLimiting;
using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Identity;

internal sealed class LoginRateLimitMarker;
internal sealed class AccountAbuseRateLimitMarker;
internal sealed class ConfirmIdentityRateLimitMarker;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the ReAuth schemes and rate-limit policies used by cookie Identity endpoints.
    /// Hosts must also call <c>UseRateLimiter()</c> in the pipeline for policies to take effect.
    /// For passkeys, also call <c>AddPasskeyEndpoints</c> (or call only that if you need both).
    /// </summary>
    public static IServiceCollection AddCookieAuthEndpoints(this IServiceCollection services)
    {
        services.AddReAuthScheme();
        services.AddIdentityEndpointRateLimiting();
        return services;
    }

    /// <summary>
    /// Registers the ReAuth schemes and rate-limit policies used by bearer Identity endpoints.
    /// Hosts must also call <c>UseRateLimiter()</c> in the pipeline for policies to take effect.
    /// </summary>
    public static IServiceCollection AddBearerAuthEndpoints(this IServiceCollection services)
    {
        services.AddReAuthScheme();
        services.AddIdentityEndpointRateLimiting();
        return services;
    }

    internal static IServiceCollection AddIdentityEndpointRateLimiting(this IServiceCollection services)
    {
        services.AddLoginRateLimiting();
        services.AddAccountAbuseRateLimiting();
        services.AddConfirmIdentityRateLimiting();
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

            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        });

        return services;
    }

    internal static IServiceCollection AddAccountAbuseRateLimiting(this IServiceCollection services)
    {
        if (services.Any(d => d.ServiceType == typeof(AccountAbuseRateLimitMarker)))
        {
            return services;
        }

        services.AddSingleton<AccountAbuseRateLimitMarker>();

        services.AddRateLimiter(options =>
        {
            options.AddPolicy(AuthEndpointsConstants.AccountAbusePolicy, context =>
            {
                var key = context.Connection.RemoteIpAddress?.ToString() ?? "anon";

                return RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 10,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0
                });
            });

            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        });

        return services;
    }

    internal static IServiceCollection AddConfirmIdentityRateLimiting(this IServiceCollection services)
    {
        if (services.Any(d => d.ServiceType == typeof(ConfirmIdentityRateLimitMarker)))
        {
            return services;
        }

        services.AddSingleton<ConfirmIdentityRateLimitMarker>();

        services.AddRateLimiter(options =>
        {
            options.AddPolicy(AuthEndpointsConstants.ConfirmIdentityPolicy, context =>
            {
                var key = context.Connection.RemoteIpAddress?.ToString() ?? "anon";

                return RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 20,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0
                });
            });

            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        });

        return services;
    }
}
