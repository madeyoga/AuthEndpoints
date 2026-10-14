using System.Threading.RateLimiting;
using AuthEndpoints.Identity;
using AuthEndpoints.ReAuth;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthEndpoints.Passkey;

internal sealed class PasskeyRateLimitMarker;

internal sealed class PasskeyEndpointsModule;

internal sealed class PasskeySignUpEndpointsModule;

internal sealed class PasskeySignInEndpointsModule;

internal sealed class PasskeyRegisterOptionsEndpointsModule;

internal sealed class PasskeyManagementEndpointsModule;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers ReAuth, Identity rate limiting, and passkey rate-limit policies.
    /// Also registers the password, cookie-session, and account-management modules
    /// so a host that calls only this method can map <c>MapIdentityManagementApi</c>
    /// and <c>MapCookieAuthEndpoints</c>.
    /// Hosts must call <c>UseRateLimiter()</c>, serve over HTTPS, and configure
    /// <c>IdentityPasskeyOptions</c> (<c>ServerDomain</c>, allowed origins, etc.).
    /// Does not register <see cref="IPasskeySignInCompleter{TUser}"/> — prefer
    /// <see cref="AddPasskeyEndpoints{TUser}"/> for compose hosts.
    /// </summary>
    public static IServiceCollection AddPasskeyEndpoints(this IServiceCollection services)
    {
        services.AddModule<PasskeyEndpointsModule>();
        services.AddPasswordEndpoints();
        services.AddCookieSessionEndpoints();
        services.AddAccountManagementEndpoints();
        services.AddReAuthScheme();
        services.AddIdentityEndpointRateLimiting();
        services.TryAddSingleton<IPasskeyUserIdFactory, DefaultPasskeyUserIdFactory>();
        services.AddPasskeySignUpEndpoints();
        services.AddPasskeySignInEndpoints();
        services.AddPasskeyRegisterOptionsEndpoints();
        services.AddPasskeyManagementEndpoints();
        return services;
    }

    /// <summary>
    /// Registers passkey rate limits and the user-id factory used by <c>POST /passkeys/register</c>.
    /// Safe to call more than once. Does not register <see cref="IPasskeySignInCompleter{TUser}"/> —
    /// use <see cref="AddPasskeySignUpEndpoints{TUser}"/> when register should be able to sign in.
    /// </summary>
    public static IServiceCollection AddPasskeySignUpEndpoints(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.HasModule<PasskeySignUpEndpointsModule>())
        {
            return services;
        }

        services.AddModule<PasskeySignUpEndpointsModule>();
        services.TryAddSingleton<IPasskeyUserIdFactory, DefaultPasskeyUserIdFactory>();
        AddPasskeyRateLimiting(services);
        return services;
    }

    /// <summary>
    /// Registers passkey infrastructure and the default
    /// <see cref="IdentityPasskeySignInCompleter{TUser}"/> for <c>POST /passkeys/register</c>.
    /// </summary>
    public static IServiceCollection AddPasskeySignUpEndpoints<TUser>(this IServiceCollection services)
        where TUser : class
    {
        services.AddPasskeySignUpEndpoints();
        services.TryAddScoped<IPasskeySignInCompleter<TUser>, IdentityPasskeySignInCompleter<TUser>>();
        SignInCompleterRegistry.AddIdentityCompleters(services);
        return services;
    }

    /// <summary>
    /// Registers passkey rate limits, the login and account-abuse rate-limit policies, and the user-id factory
    /// used by passkey request options, login, and the confirm-email route that
    /// <c>MapPasskeySignInEndpoints</c> ensures.
    /// Safe to call more than once. Does not register <see cref="IPasskeySignInCompleter{TUser}"/> —
    /// use <see cref="AddPasskeySignInEndpoints{TUser}"/> when login should be able to sign in.
    /// </summary>
    public static IServiceCollection AddPasskeySignInEndpoints(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.HasModule<PasskeySignInEndpointsModule>())
        {
            return services;
        }

        services.AddModule<PasskeySignInEndpointsModule>();
        services.TryAddSingleton<IPasskeyUserIdFactory, DefaultPasskeyUserIdFactory>();
        services.AddLoginRateLimiting();
        services.AddAccountAbuseRateLimiting();
        AddPasskeyRateLimiting(services);
        return services;
    }

    /// <summary>
    /// Registers passkey sign-in services and the default
    /// <see cref="IdentityPasskeySignInCompleter{TUser}"/> for passkey login.
    /// </summary>
    public static IServiceCollection AddPasskeySignInEndpoints<TUser>(this IServiceCollection services)
        where TUser : class
    {
        services.AddPasskeySignInEndpoints();
        services.TryAddScoped<IPasskeySignInCompleter<TUser>, IdentityPasskeySignInCompleter<TUser>>();
        SignInCompleterRegistry.AddIdentityCompleters(services);
        return services;
    }

    /// <summary>
    /// Registers the passkey rate limits used by <c>POST /passkeys/register/options</c>.
    /// Safe to call more than once.
    /// </summary>
    public static IServiceCollection AddPasskeyRegisterOptionsEndpoints(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.HasModule<PasskeyRegisterOptionsEndpointsModule>())
        {
            return services;
        }

        services.AddModule<PasskeyRegisterOptionsEndpointsModule>();
        AddPasskeyRateLimiting(services);
        return services;
    }

    /// <summary>
    /// Registers passkey rate limits and the ReAuth scheme used by passkey credential management.
    /// Safe to call more than once.
    /// </summary>
    public static IServiceCollection AddPasskeyManagementEndpoints(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.HasModule<PasskeyManagementEndpointsModule>())
        {
            return services;
        }

        services.AddModule<PasskeyManagementEndpointsModule>();
        AddPasskeyRateLimiting(services);
        services.AddReAuthScheme();
        return services;
    }

    private static void AddPasskeyRateLimiting(IServiceCollection services)
    {
        if (services.Any(d => d.ServiceType == typeof(PasskeyRateLimitMarker)))
        {
            return;
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
    }

    /// <summary>
    /// Registers passkey infrastructure and the default
    /// <see cref="IdentityPasskeySignInCompleter{TUser}"/>.
    /// </summary>
    public static IServiceCollection AddPasskeyEndpoints<TUser>(this IServiceCollection services)
        where TUser : class
    {
        services.AddPasskeyEndpoints();
        services.AddPasskeySignUpEndpoints<TUser>();
        services.AddPasskeySignInEndpoints<TUser>();
        return services;
    }

    /// <summary>
    /// Replaces the default <see cref="IPasskeySignInCompleter{TUser}"/> (e.g. with
    /// <c>JwtPasskeySignInCompleter&lt;TUser&gt;</c>).
    /// </summary>
    [Obsolete(LegacyCompleterMessages.Obsolete)]
    public static IServiceCollection AddPasskeySignInCompleter<TUser, TCompleter>(this IServiceCollection services)
        where TUser : class
        where TCompleter : class, IPasskeySignInCompleter<TUser>
    {
        services.AddScoped<IPasskeySignInCompleter<TUser>, TCompleter>();
        LegacySignInCompleters.MarkPasskey<TUser>(services);
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
