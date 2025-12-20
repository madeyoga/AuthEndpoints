using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Identity;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCookieAuthEndpoints(this IServiceCollection services)
    {
        services.AddReAuthScheme();

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

            options.AddPolicy(AuthEndpointsConstants.LoginPolicy, context =>
            {
                var key = context.Connection.RemoteIpAddress?.ToString() ?? "anon";

                return RateLimitPartition.GetTokenBucketLimiter(key, _ => new TokenBucketRateLimiterOptions {
                    TokenLimit = 10,
                    TokensPerPeriod = 2,           // Refill 2 tokens every 10 seconds
                    ReplenishmentPeriod = TimeSpan.FromSeconds(10), 
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
            });
        });
        
        return services;
    }

    public static IServiceCollection AddReAuthScheme(this IServiceCollection services)
    {
        services.AddAuthentication()
            .AddCookie(AuthEndpointsConstants.ReAuthScheme, options =>
            {
                options.Cookie.Name = AuthEndpointsConstants.ReAuthScheme;
                options.Cookie.HttpOnly = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                options.SlidingExpiration = false;

                options.Events.OnRedirectToLogin = context =>
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                };

                options.Events.OnRedirectToAccessDenied = context =>
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return Task.CompletedTask;
                };

                options.Events.OnRedirectToLogout = context =>
                {
                    context.Response.StatusCode = StatusCodes.Status204NoContent;
                    return Task.CompletedTask;
                };
            });

        services.AddAuthorizationBuilder()
            .AddPolicy("ReAuthPolicy", policy =>
            {
                policy.AddAuthenticationSchemes(AuthEndpointsConstants.ReAuthScheme);
                policy.RequireAuthenticatedUser();
            });

        return services;
    }

    public static TBuilder RequireReauth<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        return builder.RequireAuthorization("ReAuthPolicy");
    }
}
