using System.Threading.RateLimiting;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.EmailCode;

internal sealed class EmailCodeSendRateLimitMarker;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the email-code store, Identity sign-in completer, send rate-limit policy,
    /// and options validation. In Development, registers <see cref="DevelopmentEmailCodeSender{TUser}"/>
    /// when no <see cref="IEmailCodeSender{TUser}"/> is already registered.
    /// </summary>
    public static IServiceCollection AddEmailCodeEndpoints<TUser, TContext>(
        this IServiceCollection services,
        Action<EmailCodeOptions>? configure = null)
        where TUser : class, new()
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<EmailCodeOptions>()
            .Configure(options => configure?.Invoke(options))
            .ValidateOnStart();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<EmailCodeOptions>, EmailCodeOptionsValidator>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<EmailCodeOptions>, EmailCodeSenderValidator<TUser>>());

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ILookupNormalizer, UpperInvariantLookupNormalizer>();
        services.AddLoginRateLimiting();
        AddEmailCodeSendRateLimiting(services);

        services.TryAddSingleton<IEmailCodeModelCheck, EmailCodeModelCheck<TContext>>();
        services.TryAddScoped<IEmailCodeStore>(sp => new EmailCodeStore<TContext>(
            sp.GetRequiredService<TContext>(),
            sp.GetRequiredService<TimeProvider>(),
            sp.GetRequiredService<IOptions<EmailCodeOptions>>().Value,
            sp.GetRequiredService<ILookupNormalizer>()));
        services.TryAddScoped<IEmailCodeSignInCompleter<TUser>, IdentityEmailCodeSignInCompleter<TUser>>();
        services.TryAddScoped<IEmailCodeSender<TUser>>(sp =>
        {
            var environment = sp.GetRequiredService<IHostEnvironment>();
            if (environment.IsDevelopment())
            {
                return ActivatorUtilities.CreateInstance<DevelopmentEmailCodeSender<TUser>>(sp);
            }

            return new MissingEmailCodeSender<TUser>();
        });

        return services;
    }

    /// <summary>
    /// Replaces the default <see cref="IEmailCodeSignInCompleter{TUser}"/>
    /// (for example with <c>JwtEmailCodeSignInCompleter&lt;TUser&gt;</c>).
    /// </summary>
    public static IServiceCollection AddEmailCodeSignInCompleter<TUser, TCompleter>(this IServiceCollection services)
        where TUser : class
        where TCompleter : class, IEmailCodeSignInCompleter<TUser>
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddScoped<IEmailCodeSignInCompleter<TUser>, TCompleter>();
        return services;
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
