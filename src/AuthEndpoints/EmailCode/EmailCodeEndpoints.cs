using System.ComponentModel.DataAnnotations;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.EmailCode;

public static class EmailCodeEndpoints<TUser>
    where TUser : class, new()
{
    private const string RecoveryCodeLoginProvider = "[AspNetUserStore]";
    private const string RecoveryCodeTokenName = "RecoveryCodes";

    private static readonly EmailAddressAttribute EmailAddress = new();

    public static async Task<Results<Ok<EmailCodeSendResponse>, ValidationProblem>> Send(
        [FromBody] EmailCodeSendRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var services = httpContext.RequestServices;
        var userManager = services.GetRequiredService<UserManager<TUser>>();
        var options = services.GetRequiredService<IOptions<EmailCodeOptions>>().Value;
        var store = services.GetRequiredService<IEmailCodeStore>();
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger(EmailCodeLog.Category);
        var response = new EmailCodeSendResponse(
            (int)options.CodeLifetime.TotalSeconds,
            (int)options.ResendCooldown.TotalSeconds);

        var email = request?.Email?.Trim();
        if (string.IsNullOrEmpty(email) || !EmailAddress.IsValid(email))
        {
            return CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(email ?? "")));
        }

        var hashPrefix = HashPrefix(userManager, email);
        if (await store.HasReachedSendCapAsync(email, cancellationToken))
        {
            EmailCodeLog.SendSuppressed(logger, null, hashPrefix, "cap");
            return TypedResults.Ok(response);
        }

        var user = await userManager.FindByEmailAsync(email);
        string? userId = null;
        string? stamp = null;
        var eligible = false;
        if (user is not null)
        {
            userId = await userManager.GetUserIdAsync(user);
            eligible = !await IsSendIneligibleAsync(userManager, user, options);
            if (eligible)
            {
                stamp = await userManager.GetSecurityStampAsync(user);
            }
        }

        var issued = await store.IssueAsync(
            email,
            eligible ? userId : null,
            eligible ? stamp : null,
            cancellationToken);
        if (issued.Suppressed)
        {
            EmailCodeLog.SendSuppressed(logger, userId, hashPrefix, "cooldown");
            return TypedResults.Ok(response);
        }

        if (!eligible)
        {
            EmailCodeLog.SendSuppressed(logger, userId, EmailCodeHasher.HashPrefix(issued.EmailHash), "ineligible");
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
                Lifetime = options.CodeLifetime,
                Purpose = EmailCodePurpose.SignIn
            }, cancellationToken);
            EmailCodeLog.CodeIssued(logger, userId, EmailCodeHasher.HashPrefix(issued.EmailHash));
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            EmailCodeLog.SenderFailed(logger, ex, userId, EmailCodeHasher.HashPrefix(issued.EmailHash));
        }

        return TypedResults.Ok(response);
    }

    public static async Task<IResult> Verify(
        [FromBody] EmailCodeVerifyRequest request,
        [FromQuery] bool? useCookies,
        [FromQuery] bool? useSessionCookies,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var services = httpContext.RequestServices;
        var userManager = services.GetRequiredService<UserManager<TUser>>();
        var signInManager = services.GetRequiredService<SignInManager<TUser>>();
        var options = services.GetRequiredService<IOptions<EmailCodeOptions>>().Value;
        var store = services.GetRequiredService<IEmailCodeStore>();
        var completer = services.GetRequiredService<IEmailCodeSignInCompleter<TUser>>();
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger(EmailCodeLog.Category);

        if (!TryGetCode(request, options.CodeLength, out var email, out var code))
        {
            return InvalidRequest();
        }

        var row = await store.FindLiveByEmailAsync(email, cancellationToken);
        if (row is null)
        {
            EmailCodeLog.VerifyFailed(logger, null, HashPrefix(userManager, email), EmailCodeVerifyFailure.NotFound);
            return InvalidCode();
        }

        var hashPrefix = EmailCodeHasher.HashPrefix(row.EmailHash);
        var user = row.UserId is null ? null : await userManager.FindByIdAsync(row.UserId);
        if (user is null)
        {
            if (row.UserId is null)
            {
                if (!await store.TryReserveAttemptAsync(row, cancellationToken))
                {
                    EmailCodeLog.VerifyFailed(logger, null, hashPrefix, EmailCodeVerifyFailure.AttemptCap);
                    return InvalidCode();
                }

                _ = store.CodeMatches(row, code);
                EmailCodeLog.VerifyFailed(logger, null, hashPrefix, EmailCodeVerifyFailure.UnknownEmail);
            }
            else
            {
                _ = store.CodeMatches(row, code);
                await store.TryConsumeAsync(row, cancellationToken);
                EmailCodeLog.VerifyFailed(logger, row.UserId, hashPrefix, EmailCodeVerifyFailure.UserMissing);
            }

            return InvalidCode();
        }

        var userId = await userManager.GetUserIdAsync(user);
        var currentEmail = await userManager.GetEmailAsync(user);
        var emailMismatch = currentEmail is null
            || !string.Equals(EmailHash(userManager, currentEmail), row.EmailHash, StringComparison.Ordinal);
        var currentStamp = await userManager.GetSecurityStampAsync(user);
        var stampMismatch = !string.Equals(currentStamp, row.SecurityStamp, StringComparison.Ordinal);
        if (emailMismatch || stampMismatch)
        {
            await store.TryConsumeAsync(row, cancellationToken);
            EmailCodeLog.VerifyFailed(
                logger,
                userId,
                hashPrefix,
                emailMismatch ? EmailCodeVerifyFailure.EmailMismatch : EmailCodeVerifyFailure.StampMismatch);
            return InvalidCode();
        }

        if (await userManager.IsLockedOutAsync(user))
        {
            EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.LockedOut);
            return InvalidCode();
        }

        if (!await store.TryReserveAttemptAsync(row, cancellationToken))
        {
            EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.AttemptCap);
            return InvalidCode();
        }

        if (!store.CodeMatches(row, code))
        {
            if (options.CountFailuresTowardLockout)
            {
                await userManager.AccessFailedAsync(user);
            }

            EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.CodeMismatch);
            return InvalidCode();
        }

        var redeemRecoveryCode = false;
        if (options.RequireTwoFactor && await userManager.GetTwoFactorEnabledAsync(user))
        {
            if (string.IsNullOrEmpty(request.TwoFactorCode) && string.IsNullOrEmpty(request.TwoFactorRecoveryCode))
            {
                await store.TryReleaseAttemptAsync(row, cancellationToken);
                EmailCodeLog.VerifyRequiresTwoFactor(logger, userId, hashPrefix);
                return TypedResults.Problem(
                    title: "RequiresTwoFactor",
                    detail: "Two-factor authentication is required.",
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            var proofOk = false;
            if (!string.IsNullOrEmpty(request.TwoFactorCode))
            {
                proofOk = await userManager.VerifyTwoFactorTokenAsync(
                    user,
                    userManager.Options.Tokens.AuthenticatorTokenProvider,
                    request.TwoFactorCode);
            }
            else
            {
                proofOk = await HasRecoveryCodeAsync(userManager, user, request.TwoFactorRecoveryCode!);
                redeemRecoveryCode = proofOk;
            }

            if (!proofOk)
            {
                if (options.CountFailuresTowardLockout)
                {
                    await userManager.AccessFailedAsync(user);
                }

                EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.TwoFactorMismatch);
                return InvalidCode();
            }
        }

        if (!await store.TryConsumeReservedAsync(row, cancellationToken))
        {
            EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.ConsumeLost);
            return InvalidCode();
        }

        if (redeemRecoveryCode)
        {
            var redeemed = await userManager.RedeemTwoFactorRecoveryCodeAsync(user, request!.TwoFactorRecoveryCode!);
            if (!redeemed.Succeeded)
            {
                await store.TryUnconsumeAsync(row, cancellationToken);
                EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.TwoFactorMismatch);
                return InvalidCode();
            }
        }

        if (!await userManager.IsEmailConfirmedAsync(user))
        {
            var hasCredentials = await HasCredentialsAsync(userManager, user);
            if (hasCredentials && options.UnconfirmedAccounts == EmailCodeUnconfirmedAccounts.Reject)
            {
                EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.UnconfirmedRejected);
                return InvalidCode();
            }

            if (hasCredentials
                && options.UnconfirmedAccounts == EmailCodeUnconfirmedAccounts.ConfirmAndResetCredentials)
            {
                if (!await ResetCredentialsAsync(userManager, user))
                {
                    EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.CredentialResetFailed);
                    return InvalidCode();
                }

                EmailCodeLog.CredentialsResetOnConfirm(logger, userId, hashPrefix);
            }

            var confirmToken = await userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirm = await userManager.ConfirmEmailAsync(user, confirmToken);
            if (!confirm.Succeeded)
            {
                EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.ConfirmFailed);
                return InvalidCode();
            }
        }

        if (!await signInManager.CanSignInAsync(user))
        {
            EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.NotAllowed);
            return InvalidCode();
        }

        await userManager.ResetAccessFailedCountAsync(user);
        var result = await completer.CompleteAsync(
            httpContext,
            user,
            new EmailCodeSignInContext
            {
                UseCookies = useCookies,
                UseSessionCookies = useSessionCookies,
                IsNewUser = false
            },
            cancellationToken);
        EmailCodeLog.SignedIn(logger, userId, hashPrefix);
        return result;
    }

    private static async Task<bool> HasRecoveryCodeAsync(UserManager<TUser> userManager, TUser user, string code)
    {
        var merged = await userManager.GetAuthenticationTokenAsync(user, RecoveryCodeLoginProvider, RecoveryCodeTokenName);
        if (string.IsNullOrEmpty(merged))
        {
            return false;
        }

        foreach (var candidate in merged.Split(';'))
        {
            if (string.Equals(candidate, code, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static async Task<bool> IsSendIneligibleAsync(
        UserManager<TUser> userManager,
        TUser user,
        EmailCodeOptions options)
    {
        if (await userManager.IsLockedOutAsync(user))
        {
            return true;
        }

        return options.UnconfirmedAccounts == EmailCodeUnconfirmedAccounts.Reject
            && !await userManager.IsEmailConfirmedAsync(user)
            && await HasCredentialsAsync(userManager, user);
    }

    private static async Task<bool> HasCredentialsAsync(UserManager<TUser> userManager, TUser user)
    {
        if (userManager.SupportsUserPassword && await userManager.HasPasswordAsync(user))
        {
            return true;
        }

        if (userManager.SupportsUserLogin && (await userManager.GetLoginsAsync(user)).Count > 0)
        {
            return true;
        }

        return userManager.SupportsUserPasskey && (await userManager.GetPasskeysAsync(user)).Count > 0;
    }

    private static async Task<bool> ResetCredentialsAsync(UserManager<TUser> userManager, TUser user)
    {
        if (userManager.SupportsUserPassword && await userManager.HasPasswordAsync(user))
        {
            var password = await userManager.RemovePasswordAsync(user);
            if (!password.Succeeded)
            {
                return false;
            }
        }

        if (userManager.SupportsUserLogin)
        {
            foreach (var login in await userManager.GetLoginsAsync(user))
            {
                var result = await userManager.RemoveLoginAsync(user, login.LoginProvider, login.ProviderKey);
                if (!result.Succeeded)
                {
                    return false;
                }
            }
        }

        if (userManager.SupportsUserPasskey)
        {
            foreach (var passkey in await userManager.GetPasskeysAsync(user))
            {
                var result = await userManager.RemovePasskeyAsync(user, passkey.CredentialId);
                if (!result.Succeeded)
                {
                    return false;
                }
            }
        }

        var stamp = await userManager.UpdateSecurityStampAsync(user);
        return stamp.Succeeded;
    }

    private static string HashPrefix(UserManager<TUser> userManager, string email)
    {
        return EmailCodeHasher.HashPrefix(EmailHash(userManager, email));
    }

    private static string EmailHash(UserManager<TUser> userManager, string email)
    {
        var normalized = userManager.NormalizeEmail(email.Trim());
        if (string.IsNullOrEmpty(normalized))
        {
            throw new InvalidOperationException("UserManager.NormalizeEmail returned no value.");
        }

        return EmailCodeHasher.HashEmail(normalized);
    }

    private static bool TryGetCode(EmailCodeVerifyRequest? request, int codeLength, out string email, out string code)
    {
        email = "";
        code = "";
        if (request is null || !string.IsNullOrWhiteSpace(request.Token))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrEmpty(request.Code))
        {
            return false;
        }

        if (request.Code.Length != codeLength)
        {
            return false;
        }

        foreach (var ch in request.Code)
        {
            if (ch is < '0' or > '9')
            {
                return false;
            }
        }

        email = request.Email.Trim();
        code = request.Code;
        return email.Length > 0;
    }

    private static ProblemHttpResult InvalidCode()
    {
        return TypedResults.Problem(
            title: "Unauthorized",
            detail: "Invalid or expired code.",
            statusCode: StatusCodes.Status401Unauthorized);
    }

    private static ValidationProblem InvalidRequest()
    {
        return TypedResults.ValidationProblem(new Dictionary<string, string[]>
        {
            ["InvalidEmailCodeRequest"] = ["Provide an email and a numeric code."]
        });
    }

    private static ValidationProblem CreateValidationProblem(IdentityResult result)
    {
        var errors = new Dictionary<string, string[]>(1);
        foreach (var error in result.Errors)
        {
            if (errors.TryGetValue(error.Code, out var descriptions))
            {
                var next = new string[descriptions.Length + 1];
                Array.Copy(descriptions, next, descriptions.Length);
                next[descriptions.Length] = error.Description;
                errors[error.Code] = next;
            }
            else
            {
                errors[error.Code] = [error.Description];
            }
        }

        return TypedResults.ValidationProblem(errors);
    }
}
