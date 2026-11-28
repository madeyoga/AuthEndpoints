using System.Threading.RateLimiting;
using AuthEndpoints.Identity;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.EmailCode;

internal sealed class EmailCodeSendRateLimitMarker;

internal sealed class EmailCodeInfrastructureModule;

internal sealed class EmailCodeSendEndpointsModule;

internal sealed class EmailCodeSignInEndpointsModule;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the email-code service, Identity sign-in completer, send rate-limit policy,
    /// and options validation. In Development, registers <see cref="DevelopmentEmailCodeSender{TUser}"/>
    /// when no <see cref="IEmailCodeSender{TUser}"/> is already registered.
    /// </summary>
    public static IServiceCollection AddEmailCodeEndpoints<TUser>(
        this IServiceCollection services,
        Action<EmailCodeOptions>? configure = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddEmailCodeSendEndpoints<TUser>(configure);
        services.AddEmailCodeSignInEndpoints<TUser>();
        return services;
    }

    /// <summary>
    /// Registers the email-code service, sender, and send rate-limit policy used by <c>POST /emailCode/send</c>.
    /// Safe to call more than once. In Development, registers <see cref="DevelopmentEmailCodeSender{TUser}"/>
    /// when no <see cref="IEmailCodeSender{TUser}"/> is already registered.
    /// </summary>
    public static IServiceCollection AddEmailCodeSendEndpoints<TUser>(
        this IServiceCollection services,
        Action<EmailCodeOptions>? configure = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.HasModule<EmailCodeSendEndpointsModule>())
        {
            return services;
        }

        services.AddModule<EmailCodeSendEndpointsModule>();
        AddEmailCodeInfrastructure<TUser>(services, configure);
        AddEmailCodeSendRateLimiting(services);
        services.AddConfirmIdentityEmailCodeRateLimiting();
        return services;
    }

    /// <summary>
    /// Registers the email-code service, Identity sign-in completer, and login rate-limit policy
    /// used by <c>POST /emailCode/verify</c>.
    /// Safe to call more than once.
    /// </summary>
    public static IServiceCollection AddEmailCodeSignInEndpoints<TUser>(
        this IServiceCollection services,
        Action<EmailCodeOptions>? configure = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.HasModule<EmailCodeSignInEndpointsModule>())
        {
            return services;
        }

        services.AddModule<EmailCodeSignInEndpointsModule>();
        AddEmailCodeInfrastructure<TUser>(services, configure);
        services.AddLoginRateLimiting();
        SignInCompleterRegistry.AddIdentityCompleters(services);
        return services;
    }

    private static void AddEmailCodeInfrastructure<TUser>(
        IServiceCollection services,
        Action<EmailCodeOptions>? configure)
        where TUser : class, new()
    {
        if (!services.HasModule<EmailCodeInfrastructureModule>())
        {
            services.AddModule<EmailCodeInfrastructureModule>();
            services.AddOptions<EmailCodeOptions>().ValidateOnStart();
            services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IValidateOptions<EmailCodeOptions>, EmailCodeOptionsValidator>());
            services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IValidateOptions<EmailCodeOptions>, EmailCodeSenderValidator<TUser>>());
            services.TryAddSingleton(TimeProvider.System);
            services.TryAddSingleton<ILookupNormalizer, UpperInvariantLookupNormalizer>();
            services.TryAddScoped<EmailCodeService>();
            services.TryAddScoped<IEmailCodeSender<TUser>>(sp =>
            {
                var environment = sp.GetRequiredService<IHostEnvironment>();
                if (environment.IsDevelopment())
                {
                    return ActivatorUtilities.CreateInstance<DevelopmentEmailCodeSender<TUser>>(sp);
                }

                return new MissingEmailCodeSender<TUser>();
            });
        }

        if (configure is not null)
        {
            services.AddOptions<EmailCodeOptions>().Configure(configure);
        }
    }

    private static void AddEmailCodeSendRateLimiting(IServiceCollection services)
    {
        if (services.Any(descriptor => descriptor.ServiceType == typeof(EmailCodeSendRateLimitMarker)))
        {
            return;
        }

        services.AddSingleton<EmailCodeSendRateLimitMarker>();
        services.AddRateLimiter(options =>
        {
            options.AddPolicy(AuthEndpointsConstants.EmailCodeSendPolicy, httpContext =>
            {
                var limit = httpContext.RequestServices
                    .GetRequiredService<IOptionsMonitor<EmailCodeOptions>>()
                    .CurrentValue
                    .SendsPerIpPerMinute;
                var key = httpContext.Connection.RemoteIpAddress?.ToString() ?? "anon";
                return RateLimitPartition.GetFixedWindowLimiter(
                    key,
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = limit,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0
                    });
            });

            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        });
    }
}
