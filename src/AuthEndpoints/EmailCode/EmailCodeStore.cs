using System.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

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

internal sealed class EmailCodeStore<TContext> : IEmailCodeStore
    where TContext : DbContext
{
    private readonly TContext _db;
    private readonly TimeProvider _time;
    private readonly EmailCodeOptions _options;
    private readonly ILookupNormalizer _normalizer;

    public EmailCodeStore(TContext db, TimeProvider time, EmailCodeOptions options, ILookupNormalizer normalizer)
    {
        _db = db;
        _time = time;
        _options = options;
        _normalizer = normalizer;
    }

    public async Task<EmailCodeIssueResult> IssueAsync(
        string email,
        string? userId,
        string? securityStamp,
        bool rememberSignupEmail = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);

        string emailHash = HashEmail(email);
        try
        {
            return await IssueOnceAsync(email, emailHash, userId, securityStamp, rememberSignupEmail, cancellationToken);
        }
        catch (Exception ex) when (IsTransientTransactionConflict(ex, cancellationToken))
        {
            try
            {
                return await IssueOnceAsync(email, emailHash, userId, securityStamp, rememberSignupEmail, cancellationToken);
            }
            catch (Exception retryEx) when (IsTransientTransactionConflict(retryEx, cancellationToken))
            {
                return Suppressed(emailHash, "conflict");
            }
        }
    }

    private async Task<EmailCodeIssueResult> IssueOnceAsync(
        string email,
        string emailHash,
        string? userId,
        string? securityStamp,
        bool rememberSignupEmail,
        CancellationToken cancellationToken)
    {
        IExecutionStrategy strategy = _db.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(
            async ct =>
            {
                DateTime now = UtcNow();
                string id = Guid.NewGuid().ToString();
                string code = EmailCodeGenerator.CreateCode(_options.CodeLength);
                string? linkToken = null;
                string? linkTokenHash = null;
                if (_options.MagicLink.Enabled)
                {
                    linkToken = EmailCodeGenerator.CreateLinkToken();
                    linkTokenHash = EmailCodeHasher.HashLinkToken(linkToken);
                }

                await using var transaction = await _db.Database.BeginTransactionAsync(IsolationLevel.Serializable, ct);
                EmailCodeEntry? row = null;
                try
                {
                    DetachEmail(emailHash);
                    if (await IsWithinResendCooldownAsync(email, ct))
                    {
                        return Suppressed(emailHash);
                    }

                    DateTime deleteBefore = now - EmailCodeRetention.ExpiredRowRetention;
                    await _db.Set<EmailCodeEntry>()
                        .Where(e => e.EmailHash == emailHash && e.ExpiresAt < deleteBefore)
                        .ExecuteDeleteAsync(ct);

                    await _db.Set<EmailCodeEntry>()
                        .Where(e => e.EmailHash == emailHash
                            && e.ConsumedAt == null
                            && e.SupersededAt == null
                            && e.Attempts < _options.MaxAttempts
                            && e.ExpiresAt > now)
                        .ExecuteUpdateAsync(
                            setters => setters.SetProperty(e => e.SupersededAt, now),
                            ct);

                    row = new EmailCodeEntry
                    {
                        Id = id,
                        EmailHash = emailHash,
                        UserId = userId,
                        CodeHash = EmailCodeHasher.HashCode(id, code),
                        LinkTokenHash = linkTokenHash,
                        SecurityStamp = securityStamp,
                        SignupEmail = rememberSignupEmail ? email.Trim() : null,
                        CreatedAt = now,
                        ExpiresAt = now.Add(_options.CodeLifetime),
                        Attempts = 0
                    };
                    _db.Add(row);
                    await _db.SaveChangesAsync(ct);
                    await transaction.CommitAsync(ct);
                    return new EmailCodeIssueResult
                    {
                        Id = row.Id,
                        Code = code,
                        LinkToken = linkToken,
                        EmailHash = emailHash,
                        ExpiresAt = row.ExpiresAt
                    };
                }
                catch
                {
                    if (row is not null)
                    {
                        Detach(row);
                    }

                    throw;
                }
            },
            cancellationToken);
    }

    private static bool IsTransientTransactionConflict(Exception exception, CancellationToken cancellationToken)
    {
        return !cancellationToken.IsCancellationRequested
            && EmailCodeTransactionFailures.IsDeadlockOrSerializationFailure(exception);
    }

    public Task<EmailCodeEntry?> FindLiveByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);

        string emailHash = HashEmail(email);
        DateTime now = UtcNow();
        return _db.Set<EmailCodeEntry>()
            .AsNoTracking()
            .Where(e => e.EmailHash == emailHash
                && e.ConsumedAt == null
                && e.SupersededAt == null
                && e.Attempts < _options.MaxAttempts
                && e.ExpiresAt > now)
            .OrderByDescending(e => e.CreatedAt)
            .ThenByDescending(e => e.Id)
            .FirstOrDefaultAsync(cancellationToken);
    }

    public Task<EmailCodeEntry?> FindLiveByLinkTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);

        string tokenHash = EmailCodeHasher.HashLinkToken(token);
        DateTime now = UtcNow();
        return _db.Set<EmailCodeEntry>()
            .AsNoTracking()
            .Where(e => e.LinkTokenHash == tokenHash
                && e.ConsumedAt == null
                && e.SupersededAt == null
                && e.Attempts < _options.MaxAttempts
                && e.ExpiresAt > now)
            .FirstOrDefaultAsync(cancellationToken);
    }

    public bool CodeMatches(EmailCodeEntry row, string submittedCode)
    {
        return EmailCodeHasher.CodeMatches(row.Id, submittedCode, row.CodeHash);
    }

    public async Task<bool> TryReserveAttemptAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
    {
        DateTime now = UtcNow();
        int affected = await _db.Set<EmailCodeEntry>()
            .Where(e => e.Id == row.Id
                && e.ConsumedAt == null
                && e.SupersededAt == null
                && e.Attempts < _options.MaxAttempts
                && e.ExpiresAt > now)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(e => e.Attempts, e => e.Attempts + 1),
                cancellationToken);

        Detach(row);
        return affected == 1;
    }

    public async Task<bool> TryReleaseAttemptAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
    {
        int affected = await _db.Set<EmailCodeEntry>()
            .Where(e => e.Id == row.Id && e.ConsumedAt == null && e.Attempts > 0)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(e => e.Attempts, e => e.Attempts - 1),
                cancellationToken);

        Detach(row);
        return affected == 1;
    }

    public Task<bool> TryConsumeAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
    {
        return ConsumeAsync(row, allowReservedAttempt: false, cancellationToken);
    }

    public Task<bool> TryConsumeReservedAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
    {
        return ConsumeAsync(row, allowReservedAttempt: true, cancellationToken);
    }

    public async Task<bool> TryUnconsumeAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
    {
        if (row.ConsumedAt is null)
        {
            return false;
        }

        DateTime consumedAt = row.ConsumedAt.Value;
        int affected = await _db.Set<EmailCodeEntry>()
            .Where(e => e.Id == row.Id && e.ConsumedAt == consumedAt)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(e => e.ConsumedAt, (DateTime?)null),
                cancellationToken);

        if (affected == 0)
        {
            return false;
        }

        row.ConsumedAt = null;
        Detach(row);
        return true;
    }

    public async Task<bool> IsWithinResendCooldownAsync(string email, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);
        if (_options.ResendCooldown <= TimeSpan.Zero)
        {
            return false;
        }

        string emailHash = HashEmail(email);
        DateTime since = UtcNow() - _options.ResendCooldown;
        return await _db.Set<EmailCodeEntry>()
            .AnyAsync(e => e.EmailHash == emailHash && e.CreatedAt > since, cancellationToken);
    }

    public async Task<bool> HasReachedSendCapAsync(string email, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);
        string emailHash = HashEmail(email);
        DateTime since = UtcNow() - _options.SendWindow;
        int count = await _db.Set<EmailCodeEntry>()
            .CountAsync(e => e.EmailHash == emailHash && e.CreatedAt >= since, cancellationToken);
        return count >= _options.MaxSendsPerEmail;
    }

    private async Task<bool> ConsumeAsync(
        EmailCodeEntry row,
        bool allowReservedAttempt,
        CancellationToken cancellationToken)
    {
        DateTime now = UtcNow();
        int maxAttempts = _options.MaxAttempts;
        var query = _db.Set<EmailCodeEntry>().Where(e => e.Id == row.Id
            && e.ConsumedAt == null
            && e.SupersededAt == null
            && e.ExpiresAt > now);
        query = allowReservedAttempt
            ? query.Where(e => e.Attempts <= maxAttempts)
            : query.Where(e => e.Attempts < maxAttempts);

        int affected = await query.ExecuteUpdateAsync(
            setters => setters.SetProperty(e => e.ConsumedAt, now),
            cancellationToken);

        if (affected == 0)
        {
            return false;
        }

        row.ConsumedAt = now;
        Detach(row);
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

    private static EmailCodeIssueResult Suppressed(string emailHash, string reason = "cooldown")
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

    private DateTime UtcNow()
    {
        return _time.GetUtcNow().UtcDateTime;
    }

    private void DetachEmail(string emailHash)
    {
        foreach (var entry in _db.ChangeTracker.Entries<EmailCodeEntry>().ToList())
        {
            if (entry.Entity.EmailHash == emailHash)
            {
                entry.State = EntityState.Detached;
            }
        }
    }

    private void Detach(EmailCodeEntry row)
    {
        var entry = _db.Entry(row);
        if (entry.State != EntityState.Detached)
        {
            entry.State = EntityState.Detached;
        }
    }
}
