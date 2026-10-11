namespace AuthEndpoints.EmailCode;

internal interface IEmailCodeStore
{
    Task<EmailCodeIssueResult> IssueAsync(
        string email,
        string? userId,
        string? securityStamp,
        bool rememberSignupEmail = false,
        CancellationToken cancellationToken = default);

    Task<EmailCodeEntry?> FindLiveByEmailAsync(string email, CancellationToken cancellationToken = default);

    Task<EmailCodeEntry?> FindLiveByLinkTokenAsync(string token, CancellationToken cancellationToken = default);

    bool CodeMatches(EmailCodeEntry row, string submittedCode);

    Task<bool> TryReserveAttemptAsync(EmailCodeEntry row, CancellationToken cancellationToken = default);

    Task<bool> TryReleaseAttemptAsync(EmailCodeEntry row, CancellationToken cancellationToken = default);

    Task<bool> TryConsumeAsync(EmailCodeEntry row, CancellationToken cancellationToken = default);

    Task<bool> TryConsumeReservedAsync(EmailCodeEntry row, CancellationToken cancellationToken = default);

    Task<bool> TryUnconsumeAsync(EmailCodeEntry row, CancellationToken cancellationToken = default);

    Task<bool> IsWithinResendCooldownAsync(string email, CancellationToken cancellationToken = default);

    Task<bool> HasReachedSendCapAsync(string email, CancellationToken cancellationToken = default);
}
