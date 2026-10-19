using System.ComponentModel.DataAnnotations;
using AuthEndpoints.SignIn;
using System.Reflection;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.EmailCode;

public static class EmailCodeEndpoints<TUser>
    where TUser : class, new()
{
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
        if (string.IsNullOrEmpty(email) || !EmailCodeAddress.IsValid(email))
        {
            return CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(email ?? "")));
        }

        var hashPrefix = HashPrefix(userManager, email);
        if (await store.HasReachedSendCapAsync(email, EmailCodeRowPurpose.SignIn, cancellationToken))
        {
            EmailCodeLog.SendSuppressed(logger, null, hashPrefix, "cap");
            return TypedResults.Ok(response);
        }

        var user = await userManager.FindByEmailAsync(email);
        string? userId = null;
        string? stamp = null;
        var eligible = false;
        var purpose = EmailCodePurpose.SignIn;
        var rememberSignupEmail = false;
        if (user is null)
        {
            if (options.AllowSignUp)
            {
                eligible = true;
                purpose = EmailCodePurpose.SignUp;
                rememberSignupEmail = true;
            }
        }
        else
        {
            userId = await userManager.GetUserIdAsync(user);
            eligible = !await IsSendIneligibleAsync(userManager, user, options);
            if (eligible)
            {
                stamp = await userManager.GetSecurityStampAsync(user);
            }
        }

        EmailCodeIssueResult issued;
        try
        {
            issued = await store.IssueAsync(
                email,
                eligible ? userId : null,
                eligible ? stamp : null,
                EmailCodeRowPurpose.SignIn,
                rememberSignupEmail,
                cancellationToken);
        }
        catch (Exception ex) when (IsTransientTransactionConflict(ex, cancellationToken))
        {
            try
            {
                issued = await store.IssueAsync(
                    email,
                    eligible ? userId : null,
                    eligible ? stamp : null,
                    EmailCodeRowPurpose.SignIn,
                    rememberSignupEmail,
                    cancellationToken);
            }
            catch (Exception retryEx) when (IsTransientTransactionConflict(retryEx, cancellationToken))
            {
                EmailCodeLog.SendSuppressed(logger, userId, hashPrefix, "conflict");
                return TypedResults.Ok(response);
            }
        }

        if (issued.Suppressed)
        {
            EmailCodeLog.SendSuppressed(logger, userId, hashPrefix, issued.SuppressedReason ?? "cooldown");
            return TypedResults.Ok(response);
        }

        if (!eligible)
        {
            // Unknown and ineligible addresses skip the sender. Protect the address so this branch
            // still does the same class of work as a send.
            var dataProtection = services.GetService<IDataProtectionProvider>();
            if (dataProtection is not null)
            {
                EnumerationPadding.Protect(dataProtection, email);
            }

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
                LinkUrl = EmailCodeLinks.CreateUrl(options.MagicLink, issued.LinkToken),
                ExpiresAt = new DateTimeOffset(DateTime.SpecifyKind(issued.ExpiresAt, DateTimeKind.Utc)),
                Lifetime = options.CodeLifetime,
                Purpose = purpose
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

        if (!TryReadProof(request, options, out var proof))
        {
            return InvalidRequest();
        }

        var row = proof.IsToken
            ? await store.FindLiveByLinkTokenAsync(proof.Token, cancellationToken)
            : await store.FindLiveByEmailAsync(
                proof.Email,
                EmailCodeRowPurpose.SignIn,
                cancellationToken: cancellationToken);
        if (row is null)
        {
            EmailCodeLog.VerifyFailed(logger, null, ProofHashPrefix(userManager, proof), EmailCodeVerifyFailure.NotFound);
            return InvalidCode();
        }

        var hashPrefix = EmailCodeHasher.HashPrefix(row.EmailHash);
        var resolved = await ResolveUserAsync(userManager, store, options, row, proof, logger, hashPrefix, cancellationToken);
        if (resolved.Error is not null)
        {
            return resolved.Error;
        }

        var user = resolved.User;
        var userId = user is null ? null : await userManager.GetUserIdAsync(user);
        if (user is not null && await userManager.IsLockedOutAsync(user))
        {
            EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.LockedOut);
            return InvalidCode();
        }

        if (!await store.TryReserveAttemptAsync(row, cancellationToken))
        {
            EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.AttemptCap);
            return InvalidCode();
        }

        if (!proof.IsToken && !store.CodeMatches(row, proof.Code))
        {
            if (user is not null && options.CountFailuresTowardLockout)
            {
                await userManager.AccessFailedAsync(user);
            }

            EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.CodeMismatch);
            return InvalidCode();
        }

        var redeemRecovery = false;
        if (user is not null)
        {
            var factor = await EvaluateSecondFactorAsync(userManager, options, user, request!);
            if (factor.Outcome == SecondFactor.Missing)
            {
                await store.TryReleaseAttemptAsync(row, cancellationToken);
                EmailCodeLog.VerifyRequiresTwoFactor(logger, userId, hashPrefix);
                return TwoFactorRequired();
            }

            if (factor.Outcome == SecondFactor.Failed)
            {
                if (options.CountFailuresTowardLockout)
                {
                    await userManager.AccessFailedAsync(user);
                }

                EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.TwoFactorMismatch);
                return InvalidCode();
            }

            redeemRecovery = factor.RedeemRecovery;
        }

        if (!await store.TryConsumeReservedAsync(row, cancellationToken))
        {
            EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.ConsumeLost);
            return InvalidCode();
        }

        if (redeemRecovery)
        {
            var redeemed = await userManager.RedeemTwoFactorRecoveryCodeAsync(user!, request!.TwoFactorRecoveryCode!);
            if (!redeemed.Succeeded)
            {
                await store.TryUnconsumeAsync(row, cancellationToken);
                if (options.CountFailuresTowardLockout)
                {
                    await userManager.AccessFailedAsync(user!);
                }

                EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.TwoFactorMismatch);
                return InvalidCode();
            }
        }

        var isNewUser = false;
        if (user is null)
        {
            var created = await CreateSignupUserAsync(services, userManager, resolved.SignupEmail!, cancellationToken);
            if (created.Status == SignupCreateStatus.Failed || created.User is null)
            {
                EmailCodeLog.VerifyFailed(logger, null, hashPrefix, EmailCodeVerifyFailure.SignupFailed);
                return InvalidCode();
            }

            user = created.User;
            userId = await userManager.GetUserIdAsync(user);
            isNewUser = created.Status == SignupCreateStatus.Created;
            if (!isNewUser)
            {
                if (await userManager.IsLockedOutAsync(user))
                {
                    EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.LockedOut);
                    return InvalidCode();
                }

                var raced = await EvaluateSecondFactorAsync(userManager, options, user, request!);
                if (raced.Outcome == SecondFactor.Missing)
                {
                    await ReleaseConsumedReservationAsync(store, row, cancellationToken);
                    EmailCodeLog.VerifyRequiresTwoFactor(logger, userId, hashPrefix);
                    return TwoFactorRequired();
                }

                if (raced.Outcome == SecondFactor.Failed)
                {
                    await store.TryUnconsumeAsync(row, cancellationToken);
                    if (options.CountFailuresTowardLockout)
                    {
                        await userManager.AccessFailedAsync(user);
                    }

                    EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.TwoFactorMismatch);
                    return InvalidCode();
                }

                if (raced.RedeemRecovery)
                {
                    var redeemed = await userManager.RedeemTwoFactorRecoveryCodeAsync(user, request!.TwoFactorRecoveryCode!);
                    if (!redeemed.Succeeded)
                    {
                        await store.TryUnconsumeAsync(row, cancellationToken);
                        if (options.CountFailuresTowardLockout)
                        {
                            await userManager.AccessFailedAsync(user);
                        }

                        EmailCodeLog.VerifyFailed(logger, userId, hashPrefix, EmailCodeVerifyFailure.TwoFactorMismatch);
                        return InvalidCode();
                    }
                }
            }
        }

        return await FinishSignInAsync(
            httpContext,
            userManager,
            signInManager,
            completer,
            logger,
            options,
            user!,
            hashPrefix,
            isNewUser,
            useCookies,
            useSessionCookies,
            cancellationToken);
    }

    private static async Task<ResolvedUser> ResolveUserAsync(
        UserManager<TUser> userManager,
        IEmailCodeStore store,
        EmailCodeOptions options,
        EmailCodeEntry row,
        EmailCodeProof proof,
        ILogger logger,
        string hashPrefix,
        CancellationToken cancellationToken)
    {
        if (row.UserId is not null)
        {
            var bound = await userManager.FindByIdAsync(row.UserId);
            if (bound is null)
            {
                if (!proof.IsToken)
                {
                    _ = store.CodeMatches(row, proof.Code);
                }

                await store.TryConsumeAsync(row, cancellationToken);
                EmailCodeLog.VerifyFailed(logger, row.UserId, hashPrefix, EmailCodeVerifyFailure.UserMissing);
                return ResolvedUser.Fail(InvalidCode());
            }

            if (!await EmailHashMatchesAsync(userManager, bound, row.EmailHash))
            {
                await store.TryConsumeAsync(row, cancellationToken);
                EmailCodeLog.VerifyFailed(logger, row.UserId, hashPrefix, EmailCodeVerifyFailure.EmailMismatch);
                return ResolvedUser.Fail(InvalidCode());
            }

            var stamp = await userManager.GetSecurityStampAsync(bound);
            if (!string.Equals(stamp, row.SecurityStamp, StringComparison.Ordinal))
            {
                await store.TryConsumeAsync(row, cancellationToken);
                EmailCodeLog.VerifyFailed(logger, row.UserId, hashPrefix, EmailCodeVerifyFailure.StampMismatch);
                return ResolvedUser.Fail(InvalidCode());
            }

            return ResolvedUser.Found(bound);
        }

        var signupEmail = proof.IsToken ? row.SignupEmail?.Trim() : proof.Email;
        if (!options.AllowSignUp || !SignupEmailMatches(userManager, signupEmail, row.EmailHash))
        {
            return await RejectUnknownAsync(store, row, proof, logger, hashPrefix, cancellationToken);
        }

        var existing = await userManager.FindByEmailAsync(signupEmail!);
        if (existing is null)
        {
            return ResolvedUser.Signup(signupEmail!);
        }

        if (!await EmailHashMatchesAsync(userManager, existing, row.EmailHash))
        {
            await store.TryConsumeAsync(row, cancellationToken);
            EmailCodeLog.VerifyFailed(
                logger,
                await userManager.GetUserIdAsync(existing),
                hashPrefix,
                EmailCodeVerifyFailure.EmailMismatch);
            return ResolvedUser.Fail(InvalidCode());
        }

        return ResolvedUser.Found(existing);
    }

    private static async Task<ResolvedUser> RejectUnknownAsync(
        IEmailCodeStore store,
        EmailCodeEntry row,
        EmailCodeProof proof,
        ILogger logger,
        string hashPrefix,
        CancellationToken cancellationToken)
    {
        if (!await store.TryReserveAttemptAsync(row, cancellationToken))
        {
            EmailCodeLog.VerifyFailed(logger, null, hashPrefix, EmailCodeVerifyFailure.AttemptCap);
            return ResolvedUser.Fail(InvalidCode());
        }

        if (!proof.IsToken)
        {
            _ = store.CodeMatches(row, proof.Code);
        }

        EmailCodeLog.VerifyFailed(logger, null, hashPrefix, EmailCodeVerifyFailure.UnknownEmail);
        return ResolvedUser.Fail(InvalidCode());
    }

    private static async Task<FactorDecision> EvaluateSecondFactorAsync(
        UserManager<TUser> userManager,
        EmailCodeOptions options,
        TUser user,
        EmailCodeVerifyRequest request)
    {
        if (!options.RequireTwoFactor || !await userManager.GetTwoFactorEnabledAsync(user))
        {
            return new FactorDecision(SecondFactor.NotRequired, false);
        }

        if (string.IsNullOrEmpty(request.TwoFactorCode) && string.IsNullOrEmpty(request.TwoFactorRecoveryCode))
        {
            return new FactorDecision(SecondFactor.Missing, false);
        }

        if (!string.IsNullOrEmpty(request.TwoFactorCode))
        {
            var ok = await userManager.VerifyTwoFactorTokenAsync(
                user,
                userManager.Options.Tokens.AuthenticatorTokenProvider,
                request.TwoFactorCode);
            return new FactorDecision(ok ? SecondFactor.Passed : SecondFactor.Failed, false);
        }

        return new FactorDecision(SecondFactor.Passed, true);
    }

    private static async Task<SignupCreateResult> CreateSignupUserAsync(
        IServiceProvider services,
        UserManager<TUser> userManager,
        string email,
        CancellationToken cancellationToken)
    {
        var userStore = services.GetRequiredService<IUserStore<TUser>>();
        if (userStore is not IUserEmailStore<TUser> emailStore)
        {
            return SignupCreateResult.Fail();
        }

        var user = new TUser();
        await userStore.SetUserNameAsync(user, email, cancellationToken);
        await emailStore.SetEmailAsync(user, email, cancellationToken);
        await emailStore.SetEmailConfirmedAsync(user, true, cancellationToken);

        try
        {
            var created = await userManager.CreateAsync(user);
            if (created.Succeeded)
            {
                return SignupCreateResult.Created(user);
            }

            if (created.Errors.Any(error => error.Code is "DuplicateUserName" or "DuplicateEmail"))
            {
                return await DuplicateOrFailAsync(userManager, userStore, user, email);
            }

            return SignupCreateResult.Fail();
        }
        catch (DbUpdateException)
        {
            return await DuplicateOrFailAsync(userManager, userStore, user, email);
        }
    }

    private static async Task<SignupCreateResult> DuplicateOrFailAsync(
        UserManager<TUser> userManager,
        IUserStore<TUser> userStore,
        TUser user,
        string email)
    {
        DetachTrackedUser(userStore, user);
        var existing = await userManager.FindByEmailAsync(email);
        if (existing is null || ReferenceEquals(existing, user))
        {
            return SignupCreateResult.Fail();
        }

        return SignupCreateResult.Duplicate(existing);
    }

    private static void DetachTrackedUser(IUserStore<TUser> userStore, TUser user)
    {
        PropertyInfo? contextProperty = userStore.GetType().GetProperty("Context");
        if (contextProperty?.GetValue(userStore) is not DbContext context)
        {
            return;
        }

        var entry = context.Entry(user);
        if (entry.State != EntityState.Detached)
        {
            entry.State = EntityState.Detached;
        }
    }

    private static async Task ReleaseConsumedReservationAsync(
        IEmailCodeStore store,
        EmailCodeEntry row,
        CancellationToken cancellationToken)
    {
        if (await store.TryUnconsumeAsync(row, cancellationToken))
        {
            await store.TryReleaseAttemptAsync(row, cancellationToken);
        }
    }

    private static async Task<IResult> FinishSignInAsync(
        HttpContext httpContext,
        UserManager<TUser> userManager,
        SignInManager<TUser> signInManager,
        IEmailCodeSignInCompleter<TUser> completer,
        ILogger logger,
        EmailCodeOptions options,
        TUser user,
        string hashPrefix,
        bool isNewUser,
        bool? useCookies,
        bool? useSessionCookies,
        CancellationToken cancellationToken)
    {
        var userId = await userManager.GetUserIdAsync(user);
        if (!isNewUser && !await userManager.IsEmailConfirmedAsync(user))
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
        var result = await SignInCompletion.CompleteEmailCodeAsync(
            httpContext,
            user,
            completer,
            isNewUser,
            useCookies,
            useSessionCookies,
            cancellationToken);
        if (isNewUser)
        {
            EmailCodeLog.SignedUp(logger, userId, hashPrefix);
        }

        EmailCodeLog.SignedIn(logger, userId, hashPrefix);
        return result;
    }

    private static async Task<bool> EmailHashMatchesAsync(UserManager<TUser> userManager, TUser user, string emailHash)
    {
        var current = await userManager.GetEmailAsync(user);
        return current is not null
            && string.Equals(EmailHash(userManager, current), emailHash, StringComparison.Ordinal);
    }

    private static bool SignupEmailMatches(UserManager<TUser> userManager, string? email, string emailHash)
    {
        return !string.IsNullOrEmpty(email)
            && string.Equals(EmailHash(userManager, email), emailHash, StringComparison.Ordinal);
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

    private static bool IsTransientTransactionConflict(Exception exception, CancellationToken cancellationToken)
    {
        return !cancellationToken.IsCancellationRequested
            && EmailCodeTransactionFailures.IsDeadlockOrSerializationFailure(exception);
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

    private readonly struct EmailCodeProof
    {
        public bool IsToken { get; init; }

        public string Email { get; init; }

        public string Code { get; init; }

        public string Token { get; init; }
    }

    private static bool TryReadProof(EmailCodeVerifyRequest? request, EmailCodeOptions options, out EmailCodeProof proof)
    {
        proof = default;
        if (request is null)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(request.Token))
        {
            if (!options.MagicLink.Enabled
                || !string.IsNullOrWhiteSpace(request.Email)
                || !string.IsNullOrEmpty(request.Code))
            {
                return false;
            }

            proof = new EmailCodeProof
            {
                IsToken = true,
                Email = "",
                Code = "",
                Token = request.Token
            };
            return true;
        }

        if (string.IsNullOrWhiteSpace(request.Email)
            || string.IsNullOrEmpty(request.Code)
            || request.Code.Length != options.CodeLength
            || !request.Code.All(static ch => ch is >= '0' and <= '9'))
        {
            return false;
        }

        var email = request.Email.Trim();
        if (email.Length == 0)
        {
            return false;
        }

        proof = new EmailCodeProof
        {
            IsToken = false,
            Email = email,
            Code = request.Code,
            Token = ""
        };
        return true;
    }

    private static string ProofHashPrefix(UserManager<TUser> userManager, EmailCodeProof proof)
    {
        var hash = proof.IsToken
            ? EmailCodeHasher.HashLinkToken(proof.Token)
            : EmailHash(userManager, proof.Email);
        return EmailCodeHasher.HashPrefix(hash);
    }

    private static ProblemHttpResult TwoFactorRequired()
    {
        return TypedResults.Problem(
            title: "RequiresTwoFactor",
            detail: "Two-factor authentication is required.",
            statusCode: StatusCodes.Status401Unauthorized);
    }

    private sealed class ResolvedUser
    {
        public TUser? User { get; private init; }

        public string? SignupEmail { get; private init; }

        public IResult? Error { get; private init; }

        public static ResolvedUser Found(TUser user) => new() { User = user };

        public static ResolvedUser Signup(string email) => new() { SignupEmail = email };

        public static ResolvedUser Fail(IResult error) => new() { Error = error };
    }

    private enum SignupCreateStatus
    {
        Created,
        Duplicate,
        Failed
    }

    private sealed class SignupCreateResult
    {
        public SignupCreateStatus Status { get; private init; }

        public TUser? User { get; private init; }

        public static SignupCreateResult Created(TUser user) => new() { Status = SignupCreateStatus.Created, User = user };

        public static SignupCreateResult Duplicate(TUser user) => new() { Status = SignupCreateStatus.Duplicate, User = user };

        public static SignupCreateResult Fail() => new() { Status = SignupCreateStatus.Failed };
    }

    private enum SecondFactor
    {
        NotRequired,
        Missing,
        Failed,
        Passed
    }

    private readonly record struct FactorDecision(SecondFactor Outcome, bool RedeemRecovery);

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

internal static class EmailCodeAddress
{
    private static readonly EmailAddressAttribute Attribute = new();

    public static bool IsValid(string email)
    {
        return Attribute.IsValid(email);
    }
}
