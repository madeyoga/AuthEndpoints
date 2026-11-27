using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AuthEndpoints.Identity;

/// <summary>Raises account security events. The only place that finds the address and the notifier.</summary>
internal static class AccountSecurityNotifications
{
    /// <summary>
    /// Raises <paramref name="kind"/> for <paramref name="user"/>, with the account's email or null when it has none.
    /// </summary>
    public static async Task NotifyAsync<TUser>(
        IServiceProvider services,
        UserManager<TUser> userManager,
        TUser user,
        AccountSecurityEventKind kind,
        CancellationToken cancellationToken)
        where TUser : class
    {
        var email = userManager.SupportsUserEmail ? await userManager.GetEmailAsync(user) : null;
        await NotifyAsync(services, new AccountSecurityEvent<TUser>(kind, user, string.IsNullOrEmpty(email) ? null : email), cancellationToken);
    }

    public static Task NotifyAsync<TUser>(
        IServiceProvider services,
        AccountSecurityEvent<TUser> securityEvent,
        CancellationToken cancellationToken)
        where TUser : class
    {
        var notifier = services.GetService<IAccountSecurityNotifier<TUser>>() ?? CreateLoggingNotifier<TUser>(services);
        return notifier.NotifyAsync(securityEvent, cancellationToken);
    }

    private static LoggingAccountSecurityNotifier<TUser> CreateLoggingNotifier<TUser>(IServiceProvider services)
        where TUser : class
    {
        var loggerFactory = services.GetRequiredService<ILoggerFactory>();
        loggerFactory.CreateLogger(AuthEndpointsModules.LogCategory).LogWarning(
            "IAccountSecurityNotifier<{User}> is not registered. Account security events are logged and no notice is sent. Register an implementation to deliver them.",
            typeof(TUser).Name);
        return ActivatorUtilities.CreateInstance<LoggingAccountSecurityNotifier<TUser>>(services);
    }
}
