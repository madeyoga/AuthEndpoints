using Microsoft.Extensions.Logging;

namespace AuthEndpoints.Identity;

/// <summary>
/// Default <see cref="IAccountSecurityNotifier{TUser}"/>. Logs the event kind and sends nothing.
/// The log line holds no address or user id. Register another implementation to deliver the notice.
/// </summary>
public sealed partial class LoggingAccountSecurityNotifier<TUser> : IAccountSecurityNotifier<TUser>
    where TUser : class
{
    private readonly ILogger<LoggingAccountSecurityNotifier<TUser>> _logger;

    public LoggingAccountSecurityNotifier(ILogger<LoggingAccountSecurityNotifier<TUser>> logger)
    {
        _logger = logger;
    }

    public Task NotifyAsync(AccountSecurityEvent<TUser> securityEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        EventLogged(_logger, securityEvent.Kind);
        return Task.CompletedTask;
    }

    [LoggerMessage(
        EventId = 1101,
        EventName = "AccountSecurityEventLogged",
        Level = LogLevel.Information,
        Message = "Account security event {Kind}. LoggingAccountSecurityNotifier logs it and sends no notice.")]
    private static partial void EventLogged(ILogger logger, AccountSecurityEventKind kind);
}
