using Microsoft.Extensions.Logging;

namespace AuthEndpoints.EmailCode;

/// <summary>
/// Development-only sender that logs the raw code. Do not register this in Production.
/// </summary>
public sealed class DevelopmentEmailCodeSender<TUser> : IEmailCodeSender<TUser>
    where TUser : class
{
    private readonly ILogger<DevelopmentEmailCodeSender<TUser>> _logger;

    public DevelopmentEmailCodeSender(ILogger<DevelopmentEmailCodeSender<TUser>> logger)
    {
        _logger = logger;
    }

    public Task SendSignInCodeAsync(EmailCodeMessage<TUser> message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        _logger.LogWarning("DEV ONLY email sign-in code {Code}.", message.Code);
        return Task.CompletedTask;
    }
}
