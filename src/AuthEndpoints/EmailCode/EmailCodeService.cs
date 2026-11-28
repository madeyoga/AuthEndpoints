using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.EmailCode;

internal sealed class EmailCodeIssueResult
{
    public bool Suppressed { get; init; }

    public string? SuppressedReason { get; init; }

    public required string Id { get; init; }

    public required string Code { get; init; }

    public string? LinkToken { get; init; }

    public required string EmailHash { get; init; }

    public required DateTime ExpiresAt { get; init; }
}

internal static class EmailCodeRetention
{
    public static readonly TimeSpan ExpiredRowRetention = TimeSpan.FromHours(24);
}

/// <summary>
/// The email-code rules over an <see cref="IEmailCodeStore"/>: code and link generation, hashing, lifetimes,
/// the resend cooldown, the send cap, and the attempt limit.
/// </summary>
internal class EmailCodeService
{
    private readonly IEmailCodeStore _store;
    private readonly TimeProvider _time;
    private readonly EmailCodeOptions _options;
    private readonly ILookupNormalizer _normalizer;

    public EmailCodeService(
        IEmailCodeStore store,
        TimeProvider time,
        IOptions<EmailCodeOptions> options,
        ILookupNormalizer normalizer)
    {
        _store = store;
        _time = time;
        _options = options.Value;
        _normalizer = normalizer;
    }

    public async Task<EmailCodeIssueResult> IssueAsync(
        string email,
        string? userId,
        string? securityStamp,
        EmailCodeRowPurpose purpose,
        bool rememberSignupEmail = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);

        string emailHash = HashEmail(email);
        DateTime now = UtcNow();
        string id = Guid.NewGuid().ToString();
        string code = EmailCodeGenerator.CreateCode(_options.CodeLength);
        var reAuth = purpose == EmailCodeRowPurpose.ReAuth;
        string? linkToken = null;
        string? linkTokenHash = null;
        if (!reAuth && _options.MagicLink.Enabled)
        {
            linkToken = EmailCodeGenerator.CreateLinkToken();
            linkTokenHash = EmailCodeHasher.HashLinkToken(linkToken);
        }

        TimeSpan lifetime = reAuth ? _options.ReAuth.CodeLifetime : _options.CodeLifetime;
        var entry = new EmailCodeEntry
        {
            Id = id,
            EmailHash = emailHash,
            Purpose = purpose,
            UserId = userId,
            CodeHash = EmailCodeHasher.HashCode(id, code),
            LinkTokenHash = linkTokenHash,
            SecurityStamp = securityStamp,
            SignupEmail = reAuth || !rememberSignupEmail ? null : email.Trim(),
            CreatedAt = now,
            ExpiresAt = now.Add(lifetime),
            Attempts = 0
        };
        var rules = new EmailCodeIssueRules
        {
            Liveness = new EmailCodeLiveness(now, _options.MaxAttempts),
            CooldownSince = _options.ResendCooldown > TimeSpan.Zero ? now - _options.ResendCooldown : null,
            DeleteExpiredBefore = now - EmailCodeRetention.ExpiredRowRetention
        };

        var status = await _store.IssueAsync(entry, rules, cancellationToken);
        return status switch
        {
            EmailCodeIssueStatus.Issued => new EmailCodeIssueResult
            {
                Id = entry.Id,
                Code = code,
                LinkToken = linkToken,
                EmailHash = emailHash,
                ExpiresAt = entry.ExpiresAt
            },
            EmailCodeIssueStatus.Cooldown => Suppressed(emailHash, "cooldown"),
            _ => Suppressed(emailHash, "conflict"),
        };
    }

    public Task<EmailCodeEntry?> FindLiveByEmailAsync(
        string email,
        EmailCodeRowPurpose purpose,
        string? userId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);
        return _store.FindLiveByEmailAsync(HashEmail(email), purpose, userId, Liveness(), cancellationToken);
    }

    public Task<EmailCodeEntry?> FindLiveByLinkTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        return _store.FindLiveByLinkTokenAsync(EmailCodeHasher.HashLinkToken(token), Liveness(), cancellationToken);
    }

    /// <summary>Constant-time compare of a submitted code with the row's hash. Virtual so tests can count compares.</summary>
    public virtual bool CodeMatches(EmailCodeEntry row, string submittedCode)
    {
        return EmailCodeHasher.CodeMatches(row.Id, submittedCode, row.CodeHash);
    }

    public Task<bool> TryReserveAttemptAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
    {
        return _store.TryReserveAttemptAsync(row.Id, Liveness(), cancellationToken);
    }

    public Task<bool> TryReleaseAttemptAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
    {
        return _store.TryReleaseAttemptAsync(row.Id, cancellationToken);
    }

    public Task<bool> TryConsumeAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
    {
        return ConsumeAsync(row, attemptReserved: false, cancellationToken);
    }

    public Task<bool> TryConsumeReservedAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
    {
        return ConsumeAsync(row, attemptReserved: true, cancellationToken);
    }

    public async Task<bool> TryUnconsumeAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
    {
        if (row.ConsumedAt is null || !await _store.TryUnconsumeAsync(row.Id, cancellationToken))
        {
            return false;
        }

        row.ConsumedAt = null;
        return true;
    }

    public async Task<bool> HasReachedSendCapAsync(
        string email,
        EmailCodeRowPurpose purpose,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);
        DateTime since = UtcNow() - _options.SendWindow;
        int count = await _store.CountIssuedSinceAsync(HashEmail(email), purpose, since, cancellationToken);
        return count >= _options.MaxSendsPerEmail;
    }

    private async Task<bool> ConsumeAsync(EmailCodeEntry row, bool attemptReserved, CancellationToken cancellationToken)
    {
        var liveness = Liveness();
        if (!await _store.TryConsumeAsync(row.Id, liveness, attemptReserved, cancellationToken))
        {
            return false;
        }

        row.ConsumedAt = liveness.Now;
        return true;
    }

    private string HashEmail(string email)
    {
        string? normalized = _normalizer.NormalizeEmail(email.Trim());
        if (string.IsNullOrEmpty(normalized))
        {
            throw new InvalidOperationException("ILookupNormalizer.NormalizeEmail returned no value.");
        }

        return EmailCodeHasher.HashEmail(normalized);
    }

    private static EmailCodeIssueResult Suppressed(string emailHash, string reason)
    {
        return new EmailCodeIssueResult
        {
            Suppressed = true,
            SuppressedReason = reason,
            Id = "",
            Code = "",
            EmailHash = emailHash,
            ExpiresAt = default
        };
    }

    private EmailCodeLiveness Liveness() => new(UtcNow(), _options.MaxAttempts);

    private DateTime UtcNow() => _time.GetUtcNow().UtcDateTime;
}
