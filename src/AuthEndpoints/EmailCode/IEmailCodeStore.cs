namespace AuthEndpoints.EmailCode;

internal interface IEmailCodeStore
{
    Task<EmailCodeIssueResult> IssueAsync(
        string email,
        string? userId,
        string? securityStamp,
        CancellationToken cancellationToken = default);

    Task<EmailCode?> FindLiveByEmailAsync(string email, CancellationToken cancellationToken = default);

    bool CodeMatches(EmailCode row, string submittedCode);

    Task<bool> TryIncrementAttemptsAsync(EmailCode row, CancellationToken cancellationToken = default);

    Task<bool> TryConsumeAsync(EmailCode row, CancellationToken cancellationToken = default);

    Task<bool> IsWithinResendCooldownAsync(string email, CancellationToken cancellationToken = default);

    Task<bool> HasReachedSendCapAsync(string email, CancellationToken cancellationToken = default);
}
