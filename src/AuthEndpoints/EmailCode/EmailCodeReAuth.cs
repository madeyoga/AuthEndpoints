using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.EmailCode;

internal enum EmailCodeReAuthVerifyStatus
{
    Valid,
    Invalid,
    Unavailable
}

internal static class EmailCodeReAuthGate
{
    public static async Task<bool> IsAvailableAsync<TUser>(
        UserManager<TUser> userManager,
        TUser user,
        EmailCodeOptions options)
        where TUser : class
    {
        if (options.ReAuth is not { Enabled: true })
        {
            return false;
        }

        if (!await userManager.IsEmailConfirmedAsync(user))
        {
            return false;
        }

        var email = await userManager.GetEmailAsync(user);
        if (string.IsNullOrWhiteSpace(email) || !EmailCodeAddress.IsValid(email))
        {
            return false;
        }

        if (userManager.SupportsUserPassword && await userManager.HasPasswordAsync(user))
        {
            return false;
        }

        if (userManager.SupportsUserTwoFactor && await userManager.GetTwoFactorEnabledAsync(user))
        {
            return false;
        }

        if (userManager.SupportsUserPasskey && (await userManager.GetPasskeysAsync(user)).Count > 0)
        {
            return false;
        }

        return true;
    }
}

internal static class EmailCodeReAuthEndpoints<TUser>
    where TUser : class, new()
{
    internal const string UnavailableTitle = "EmailCodeProofUnavailable";

    public static async Task<Results<Ok<EmailCodeSendResponse>, UnauthorizedHttpResult, ProblemHttpResult>> Send(
        HttpContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var services = context.RequestServices;
        var userManager = services.GetRequiredService<UserManager<TUser>>();
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return TypedResults.Unauthorized();
        }

        var options = services.GetRequiredService<IOptions<EmailCodeOptions>>().Value;
        var store = services.GetService<IEmailCodeStore>();
        if (store is null || !await EmailCodeReAuthGate.IsAvailableAsync(userManager, user, options))
        {
            return Unavailable();
        }

        var email = (await userManager.GetEmailAsync(user))!.Trim();
        var userId = await userManager.GetUserIdAsync(user);
        var stamp = userManager.SupportsUserSecurityStamp
            ? await userManager.GetSecurityStampAsync(user)
            : null;
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(stamp))
        {
            return Unavailable();
        }

        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger(EmailCodeLog.Category);
        var response = new EmailCodeSendResponse(
            (int)options.ReAuth.CodeLifetime.TotalSeconds,
            (int)options.ResendCooldown.TotalSeconds);
        var hashPrefix = HashPrefix(userManager, email);
        if (await store.HasReachedSendCapAsync(email, EmailCodeRowPurpose.ReAuth, cancellationToken))
        {
            EmailCodeLog.SendSuppressed(logger, userId, hashPrefix, "cap");
            return TypedResults.Ok(response);
        }

        EmailCodeIssueResult issued;
        try
        {
            issued = await store.IssueAsync(
                email,
                userId,
                stamp,
                EmailCodeRowPurpose.ReAuth,
                rememberSignupEmail: false,
                cancellationToken);
        }
        catch (Exception ex) when (IsTransientTransactionConflict(ex, cancellationToken))
        {
            EmailCodeLog.SendSuppressed(logger, userId, hashPrefix, "conflict");
            return TypedResults.Ok(response);
        }

        if (issued.Suppressed)
        {
            EmailCodeLog.SendSuppressed(logger, userId, hashPrefix, issued.SuppressedReason ?? "cooldown");
            return TypedResults.Ok(response);
        }

        try
        {
            var sender = services.GetRequiredService<IEmailCodeSender<TUser>>();
            await sender.SendSignInCodeAsync(new EmailCodeMessage<TUser>
            {
                Email = email,
                User = user,
                Code = issued.Code,
                LinkUrl = null,
                ExpiresAt = new DateTimeOffset(DateTime.SpecifyKind(issued.ExpiresAt, DateTimeKind.Utc)),
                Lifetime = options.ReAuth.CodeLifetime,
                Purpose = EmailCodePurpose.ReAuth
            }, cancellationToken);
            EmailCodeLog.CodeIssued(logger, userId, EmailCodeHasher.HashPrefix(issued.EmailHash));
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            EmailCodeLog.SenderFailed(logger, ex, userId, EmailCodeHasher.HashPrefix(issued.EmailHash));
        }

        return TypedResults.Ok(response);
    }

    public static async Task<EmailCodeReAuthVerifyStatus> Verify(
        HttpContext context,
        UserManager<TUser> userManager,
        TUser user,
        string code,
        CancellationToken cancellationToken)
    {
        var services = context.RequestServices;
        var options = services.GetService<IOptions<EmailCodeOptions>>()?.Value;
        var store = services.GetService<IEmailCodeStore>();
        // Sign-in shares the store. Send owns the step-up proof.
        if (!AuthEndpointsModules.IsRegistered<EmailCodeSendEndpointsModule>(services)
            || options is null
            || store is null
            || !await EmailCodeReAuthGate.IsAvailableAsync(userManager, user, options))
        {
            return EmailCodeReAuthVerifyStatus.Unavailable;
        }

        var email = await userManager.GetEmailAsync(user);
        var userId = await userManager.GetUserIdAsync(user);
        var stamp = userManager.SupportsUserSecurityStamp
            ? await userManager.GetSecurityStampAsync(user)
            : null;
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(stamp))
        {
            return EmailCodeReAuthVerifyStatus.Unavailable;
        }

        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger(EmailCodeLog.Category);
        var row = await store.FindLiveByEmailAsync(email, EmailCodeRowPurpose.ReAuth, userId, cancellationToken);
        var hashPrefix = row is null ? HashPrefix(userManager, email) : EmailCodeHasher.HashPrefix(row.EmailHash);
        if (row is null
            || !string.Equals(row.UserId, userId, StringComparison.Ordinal)
            || !string.Equals(row.SecurityStamp, stamp, StringComparison.Ordinal))
        {
            EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.NotFound);
            return EmailCodeReAuthVerifyStatus.Invalid;
        }

        if (await userManager.IsLockedOutAsync(user))
        {
            EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.LockedOut);
            return EmailCodeReAuthVerifyStatus.Invalid;
        }

        if (!await store.TryReserveAttemptAsync(row, cancellationToken))
        {
            EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.AttemptCap);
            return EmailCodeReAuthVerifyStatus.Invalid;
        }

        if (!store.CodeMatches(row, code))
        {
            if (options.CountFailuresTowardLockout)
            {
                await userManager.AccessFailedAsync(user);
            }

            EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.CodeMismatch);
            return EmailCodeReAuthVerifyStatus.Invalid;
        }

        if (!await store.TryConsumeReservedAsync(row, cancellationToken))
        {
            EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.ConsumeLost);
            return EmailCodeReAuthVerifyStatus.Invalid;
        }

        return EmailCodeReAuthVerifyStatus.Valid;
    }

    public static ProblemHttpResult Unavailable()
    {
        return TypedResults.Problem(
            title: UnavailableTitle,
            detail: "Email code step-up is unavailable for this account.",
            statusCode: StatusCodes.Status400BadRequest);
    }

    private static string HashPrefix(UserManager<TUser> userManager, string email)
    {
        var normalized = userManager.NormalizeEmail(email.Trim());
        if (string.IsNullOrEmpty(normalized))
        {
            return "";
        }

        return EmailCodeHasher.HashPrefix(EmailCodeHasher.HashEmail(normalized));
    }

    private static bool IsTransientTransactionConflict(Exception exception, CancellationToken cancellationToken)
    {
        return !cancellationToken.IsCancellationRequested
            && EmailCodeTransactionFailures.IsDeadlockOrSerializationFailure(exception);
    }
}
