using Microsoft.Extensions.Logging;

namespace AuthEndpoints.EmailCode;

internal enum EmailCodeVerifyFailure
{
    NotFound,
    UserMissing,
    EmailMismatch,
    StampMismatch,
    UnknownEmail,
    LockedOut,
    CodeMismatch,
    TwoFactorMismatch,
    ConsumeLost,
    AttemptCap,
    NotAllowed,
    UnconfirmedRejected,
    ConfirmFailed,
    CredentialResetFailed
}

internal static partial class EmailCodeLog
{
    public const string Category = "AuthEndpoints.EmailCode";

    [LoggerMessage(
        EventId = 1,
        EventName = "CodeIssued",
        Level = LogLevel.Information,
        Message = "Email code issued for user {UserId} hash {EmailHashPrefix}.")]
    public static partial void CodeIssued(ILogger logger, string? userId, string emailHashPrefix);

    [LoggerMessage(
        EventId = 2,
        EventName = "SendSuppressed",
        Level = LogLevel.Information,
        Message = "Email code send suppressed for user {UserId} hash {EmailHashPrefix} reason {Reason}.")]
    public static partial void SendSuppressed(ILogger logger, string? userId, string emailHashPrefix, string reason);

    [LoggerMessage(
        EventId = 3,
        EventName = "SenderFailed",
        Level = LogLevel.Error,
        Message = "Email code sender failed for user {UserId} hash {EmailHashPrefix}.")]
    public static partial void SenderFailed(ILogger logger, Exception exception, string? userId, string emailHashPrefix);

    [LoggerMessage(
        EventId = 4,
        EventName = "VerifyFailed",
        Level = LogLevel.Information,
        Message = "Email code verify failed for user {UserId} hash {EmailHashPrefix} reason {Reason}.")]
    public static partial void VerifyFailed(ILogger logger, string? userId, string emailHashPrefix, EmailCodeVerifyFailure reason);

    [LoggerMessage(
        EventId = 5,
        EventName = "VerifyRequiresTwoFactor",
        Level = LogLevel.Information,
        Message = "Email code verify requires two-factor for user {UserId} hash {EmailHashPrefix}.")]
    public static partial void VerifyRequiresTwoFactor(ILogger logger, string? userId, string emailHashPrefix);

    [LoggerMessage(
        EventId = 6,
        EventName = "SignedIn",
        Level = LogLevel.Information,
        Message = "Email code sign-in completed for user {UserId} hash {EmailHashPrefix}.")]
    public static partial void SignedIn(ILogger logger, string? userId, string emailHashPrefix);

    [LoggerMessage(
        EventId = 7,
        EventName = "SignedUp",
        Level = LogLevel.Information,
        Message = "Email code sign-up completed for user {UserId} hash {EmailHashPrefix}.")]
    public static partial void SignedUp(ILogger logger, string? userId, string emailHashPrefix);

    [LoggerMessage(
        EventId = 8,
        EventName = "CredentialsResetOnConfirm",
        Level = LogLevel.Information,
        Message = "Email code confirmation reset credentials for user {UserId} hash {EmailHashPrefix}.")]
    public static partial void CredentialsResetOnConfirm(ILogger logger, string? userId, string emailHashPrefix);
}
