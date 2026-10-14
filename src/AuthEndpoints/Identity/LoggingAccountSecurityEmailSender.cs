using Microsoft.Extensions.Logging;

namespace AuthEndpoints.Identity;

/// <summary>
/// Default <see cref="IAccountSecurityEmailSender{TUser}"/>. Logs that a password was set
/// and does not send mail. Register another implementation to deliver the notice.
/// </summary>
public sealed class LoggingAccountSecurityEmailSender<TUser> : IAccountSecurityEmailSender<TUser>
    where TUser : class
{
    private readonly ILogger<LoggingAccountSecurityEmailSender<TUser>> _logger;

    public LoggingAccountSecurityEmailSender(ILogger<LoggingAccountSecurityEmailSender<TUser>> logger)
    {
        _logger = logger;
    }

    public Task SendPasswordSetAsync(TUser user, string email, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(email);
        _logger.LogInformation("A password was added to an account.");
        return Task.CompletedTask;
    }
}
