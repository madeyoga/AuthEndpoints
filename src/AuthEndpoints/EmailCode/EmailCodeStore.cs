using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.EmailCode;

internal sealed class EmailCodeIssueResult
{
    public required string Id { get; init; }

    public required string Code { get; init; }

    public string? LinkToken { get; init; }

    public required string EmailHash { get; init; }

    public required DateTime ExpiresAt { get; init; }
}

internal sealed class EmailCodeStore<TContext> : IEmailCodeStore
    where TContext : DbContext
{
    internal static readonly TimeSpan ExpiredRowRetention = TimeSpan.FromHours(24);

    private readonly TContext _db;
    private readonly TimeProvider _time;
    private readonly EmailCodeOptions _options;

    public EmailCodeStore(TContext db, TimeProvider time, EmailCodeOptions options)
    {
        _db = db;
        _time = time;
        _options = options;
    }

    public async Task<EmailCodeIssueResult> IssueAsync(
        string email,
        string? userId,
        string? securityStamp,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);

        string normalized = EmailCodeHasher.NormalizeEmail(email);
        string emailHash = EmailCodeHasher.HashEmail(normalized);
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

        var row = new EmailCode
        {
            Id = id,
            EmailHash = emailHash,
            UserId = userId,
            CodeHash = EmailCodeHasher.HashCode(id, code),
            LinkTokenHash = linkTokenHash,
            SecurityStamp = securityStamp,
            CreatedAt = now,
            ExpiresAt = now.Add(_options.CodeLifetime),
            Attempts = 0
        };

        await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            DetachEmail(emailHash);

            DateTime deleteBefore = now - ExpiredRowRetention;
            await _db.Set<EmailCode>()
                .Where(e => e.EmailHash == emailHash && e.ExpiresAt < deleteBefore)
                .ExecuteDeleteAsync(cancellationToken);

            await _db.Set<EmailCode>()
                .Where(e => e.EmailHash == emailHash
                    && e.ConsumedAt == null
                    && e.SupersededAt == null
                    && e.Attempts < _options.MaxAttempts
                    && e.ExpiresAt > now)
                .ExecuteUpdateAsync(
                    setters => setters.SetProperty(e => e.SupersededAt, now),
                    cancellationToken);

            _db.Add(row);
            await _db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            Detach(row);
            throw;
        }

        return new EmailCodeIssueResult
        {
            Id = row.Id,
            Code = code,
            LinkToken = linkToken,
            EmailHash = emailHash,
            ExpiresAt = row.ExpiresAt
        };
    }

    public Task<EmailCode?> FindLiveByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);

        string emailHash = EmailCodeHasher.HashEmail(EmailCodeHasher.NormalizeEmail(email));
        DateTime now = UtcNow();
        return _db.Set<EmailCode>()
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

    public bool CodeMatches(EmailCode row, string submittedCode)
    {
        return EmailCodeHasher.CodeMatches(row.Id, submittedCode, row.CodeHash);
    }

    public async Task<bool> TryIncrementAttemptsAsync(EmailCode row, CancellationToken cancellationToken = default)
    {
        int affected = await _db.Set<EmailCode>()
            .Where(e => e.Id == row.Id && e.ConsumedAt == null && e.Attempts < _options.MaxAttempts)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(e => e.Attempts, e => e.Attempts + 1),
                cancellationToken);

        Detach(row);
        return affected == 1;
    }

    public async Task<bool> TryConsumeAsync(EmailCode row, CancellationToken cancellationToken = default)
    {
        DateTime now = UtcNow();
        int affected = await _db.Set<EmailCode>()
            .Where(e => e.Id == row.Id
                && e.ConsumedAt == null
                && e.SupersededAt == null
                && e.Attempts < _options.MaxAttempts
                && e.ExpiresAt > now)
            .ExecuteUpdateAsync(
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

    public async Task<bool> IsWithinResendCooldownAsync(string email, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);
        if (_options.ResendCooldown <= TimeSpan.Zero)
        {
            return false;
        }

        string emailHash = EmailCodeHasher.HashEmail(EmailCodeHasher.NormalizeEmail(email));
        DateTime since = UtcNow() - _options.ResendCooldown;
        return await _db.Set<EmailCode>()
            .AnyAsync(e => e.EmailHash == emailHash && e.CreatedAt > since, cancellationToken);
    }

    public async Task<bool> HasReachedSendCapAsync(string email, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);
        string emailHash = EmailCodeHasher.HashEmail(EmailCodeHasher.NormalizeEmail(email));
        DateTime since = UtcNow() - _options.SendWindow;
        int count = await _db.Set<EmailCode>()
            .CountAsync(e => e.EmailHash == emailHash && e.CreatedAt >= since, cancellationToken);
        return count >= _options.MaxSendsPerEmail;
    }

    private DateTime UtcNow()
    {
        return _time.GetUtcNow().UtcDateTime;
    }

    private void DetachEmail(string emailHash)
    {
        foreach (var entry in _db.ChangeTracker.Entries<EmailCode>().ToList())
        {
            if (entry.Entity.EmailHash == emailHash)
            {
                entry.State = EntityState.Detached;
            }
        }
    }

    private void Detach(EmailCode row)
    {
        var entry = _db.Entry(row);
        if (entry.State != EntityState.Detached)
        {
            entry.State = EntityState.Detached;
        }
    }
}
