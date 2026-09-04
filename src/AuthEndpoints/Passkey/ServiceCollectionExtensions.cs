using System.Threading.RateLimiting;
using AuthEndpoints.Identity;
using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthEndpoints.Passkey;

internal sealed class PasskeyRateLimitMarker;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers ReAuth, Identity rate limiting, and passkey rate-limit policies.
    /// Hosts must call <c>UseRateLimiter()</c>, serve over HTTPS, and configure
    /// <c>IdentityPasskeyOptions</c> (<c>ServerDomain</c>, allowed origins, etc.).
    /// Does not register <see cref="IPasskeySignInCompleter{TUser}"/> — prefer
    /// <see cref="AddPasskeyEndpoints{TUser}"/> for compose hosts.
    /// </summary>
    public static IServiceCollection AddPasskeyEndpoints(this IServiceCollection services)
    {
        services.AddReAuthScheme();
        services.AddIdentityEndpointRateLimiting();
        services.TryAddSingleton<IPasskeyUserIdFactory, DefaultPasskeyUserIdFactory>();

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

    /// <summary>
    /// Registers passkey infrastructure and the default
    /// <see cref="IdentityPasskeySignInCompleter{TUser}"/>.
    /// </summary>
    public static IServiceCollection AddPasskeyEndpoints<TUser>(this IServiceCollection services)
        where TUser : class
    {
        services.AddPasskeyEndpoints();
        services.TryAddScoped<IPasskeySignInCompleter<TUser>, IdentityPasskeySignInCompleter<TUser>>();
        return services;
    }

    /// <summary>
    /// Replaces the default <see cref="IPasskeySignInCompleter{TUser}"/> (e.g. with
    /// <c>JwtPasskeySignInCompleter&lt;TUser&gt;</c>).
    /// </summary>
    public static IServiceCollection AddPasskeySignInCompleter<TUser, TCompleter>(this IServiceCollection services)
        where TUser : class
        where TCompleter : class, IPasskeySignInCompleter<TUser>
    {
        services.AddScoped<IPasskeySignInCompleter<TUser>, TCompleter>();
        return services;
    }

    /// <summary>
    /// Replaces the default <see cref="IPasskeyUserIdFactory"/> used when minting
    /// a user id during passwordless passkey registration.
    /// </summary>
    public static IServiceCollection AddPasskeyUserIdFactory<TFactory>(this IServiceCollection services)
        where TFactory : class, IPasskeyUserIdFactory
    {
        services.AddSingleton<IPasskeyUserIdFactory, TFactory>();
        return services;
    }

    /// <summary>
    /// Registers a callback as the <see cref="IPasskeyUserIdFactory"/> used when minting
    /// a user id during passwordless passkey registration.
    /// </summary>
    public static IServiceCollection AddPasskeyUserIdFactory(this IServiceCollection services, Func<string> createUserId)
    {
        ArgumentNullException.ThrowIfNull(createUserId);
        services.AddSingleton<IPasskeyUserIdFactory>(new DelegatePasskeyUserIdFactory(createUserId));
        return services;
    }

    private sealed class DelegatePasskeyUserIdFactory(Func<string> createUserId) : IPasskeyUserIdFactory
    {
        public string CreateUserId() => createUserId();
    }
}
