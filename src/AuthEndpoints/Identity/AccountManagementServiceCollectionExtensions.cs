using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AuthEndpoints.Identity;

public static class AccountManagementServiceCollectionExtensions
{
    /// <summary>
    /// Registers ReAuth schemes, the account-abuse and confirm-identity rate-limit policies,
    /// authorization, antiforgery, and the logging account-security email sender used by account management.
    /// Safe to call more than once. Hosts must call <c>UseRateLimiter()</c> for the policies to apply.
    /// Startup logs a warning while <see cref="LoggingAccountSecurityEmailSender{TUser}"/> is the registered sender.
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
        services.AddAccountSecurityEmailSender();
        WrapAuthorizationResultHandler(services);
        return services;
    }

    /// <summary>
    /// Registers <see cref="LoggingAccountSecurityEmailSender{TUser}"/> when no sender is registered.
    /// </summary>
    internal static void AddAccountSecurityEmailSender(this IServiceCollection services)
    {
        services.TryAddScoped(typeof(IAccountSecurityEmailSender<>), typeof(LoggingAccountSecurityEmailSender<>));
        if (services.Any(descriptor => descriptor.ServiceType == typeof(AccountSecurityEmailSenderStartupMarker)))
        {
            return;
        }

        services.AddSingleton<AccountSecurityEmailSenderStartupMarker>();
        services.AddSingleton<IHostedService>(sp =>
            new AccountSecurityEmailSenderStartup(services, sp.GetRequiredService<ILoggerFactory>()));
    }

    private static void WrapAuthorizationResultHandler(IServiceCollection services)
    {
        var existing = services
            .Where(descriptor => descriptor.ServiceType == typeof(IAuthorizationMiddlewareResultHandler))
            .ToArray();
        var innerDescriptor = existing.LastOrDefault();
        foreach (var descriptor in existing)
        {
            services.Remove(descriptor);
        }

        var lifetime = innerDescriptor?.Lifetime ?? ServiceLifetime.Singleton;
        services.Add(ServiceDescriptor.Describe(
            typeof(IAuthorizationMiddlewareResultHandler),
            sp => new SetPasswordAvailabilityResultHandler(CreateInnerHandler(sp, innerDescriptor)),
            lifetime));
    }

    private static IAuthorizationMiddlewareResultHandler CreateInnerHandler(
        IServiceProvider services,
        ServiceDescriptor? existing)
    {
        if (existing?.ImplementationInstance is IAuthorizationMiddlewareResultHandler instance)
        {
            return instance;
        }

        if (existing?.ImplementationFactory is not null)
        {
            return (IAuthorizationMiddlewareResultHandler)existing.ImplementationFactory(services);
        }

        if (existing?.ImplementationType is not null)
        {
            return (IAuthorizationMiddlewareResultHandler)ActivatorUtilities.CreateInstance(services, existing.ImplementationType);
        }

        return new AuthorizationMiddlewareResultHandler();
    }
}

internal sealed class AccountSecurityEmailSenderStartupMarker;

internal sealed class AccountSecurityEmailSenderStartup : IHostedService
{
    private readonly IServiceCollection _services;
    private readonly ILogger _logger;

    public AccountSecurityEmailSenderStartup(IServiceCollection services, ILoggerFactory loggerFactory)
    {
        _services = services;
        _logger = loggerFactory.CreateLogger(AuthEndpointsModules.LogCategory);
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (HasCustomSender(_services))
        {
            return Task.CompletedTask;
        }

        _logger.LogWarning(
            "IAccountSecurityEmailSender is LoggingAccountSecurityEmailSender, which logs password-set notices and does not send mail. Register an implementation to deliver them.");
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    internal static bool HasCustomSender(IServiceCollection services)
    {
        return services.Any(descriptor => IsSender(descriptor) && !IsLoggingSender(descriptor));
    }

    private static bool IsSender(ServiceDescriptor descriptor)
    {
        return descriptor.ServiceType.IsGenericType
            && descriptor.ServiceType.GetGenericTypeDefinition() == typeof(IAccountSecurityEmailSender<>);
    }

    private static bool IsLoggingSender(ServiceDescriptor descriptor)
    {
        var type = descriptor.ImplementationType;
        if (type is null)
        {
            return false;
        }

        if (type == typeof(LoggingAccountSecurityEmailSender<>))
        {
            return true;
        }

        return type.IsGenericType
            && type.GetGenericTypeDefinition() == typeof(LoggingAccountSecurityEmailSender<>);
    }
}
