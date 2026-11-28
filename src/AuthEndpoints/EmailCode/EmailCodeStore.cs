using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace AuthEndpoints.EmailCode;

/// <summary>
/// EF Core <see cref="IEmailCodeStore"/>. Issuing runs in a <see cref="IsolationLevel.Serializable"/> transaction
/// through the context's execution strategy, and is tried once more after a deadlock or serialization failure.
/// Every other method is one conditional statement. Rows are read untracked, and nothing stays tracked after a call,
/// so a later <c>SaveChanges</c> on the shared context cannot write a stale row back.
/// </summary>
internal sealed class EmailCodeStore<TContext> : IEmailCodeStore
    where TContext : DbContext
{
    private readonly TContext _db;

    public EmailCodeStore(TContext db)
    {
        _db = db;
    }

    public async Task<EmailCodeIssueStatus> IssueAsync(
        EmailCodeEntry entry,
        EmailCodeIssueRules rules,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(rules);

        try
        {
            return await IssueOnceAsync(entry, rules, cancellationToken);
        }
        catch (Exception ex) when (IsTransientTransactionConflict(ex, cancellationToken))
        {
            try
            {
                return await IssueOnceAsync(entry, rules, cancellationToken);
            }
            catch (Exception retryEx) when (IsTransientTransactionConflict(retryEx, cancellationToken))
            {
                return EmailCodeIssueStatus.Conflict;
            }
        }
    }

    private async Task<EmailCodeIssueStatus> IssueOnceAsync(
        EmailCodeEntry entry,
        EmailCodeIssueRules rules,
        CancellationToken cancellationToken)
    {
        IExecutionStrategy strategy = _db.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(
            async ct =>
            {
                string emailHash = entry.EmailHash;
                EmailCodeRowPurpose purpose = entry.Purpose;
                DateTime now = rules.Liveness.Now;
                int maxAttempts = rules.Liveness.MaxAttempts;

                await using var transaction = await _db.Database.BeginTransactionAsync(IsolationLevel.Serializable, ct);
                try
                {
                    DetachEmail(emailHash);
                    if (rules.CooldownSince is { } since
                        && await _db.Set<EmailCodeEntry>().AnyAsync(
                            e => e.EmailHash == emailHash && e.Purpose == purpose && e.CreatedAt > since,
                            ct))
                    {
                        return EmailCodeIssueStatus.Cooldown;
                    }

                    DateTime deleteBefore = rules.DeleteExpiredBefore;
                    await _db.Set<EmailCodeEntry>()
                        .Where(e => e.EmailHash == emailHash && e.Purpose == purpose && e.ExpiresAt < deleteBefore)
                        .ExecuteDeleteAsync(ct);

                    await _db.Set<EmailCodeEntry>()
                        .Where(e => e.EmailHash == emailHash
                            && e.Purpose == purpose
                            && e.ConsumedAt == null
                            && e.SupersededAt == null
                            && e.Attempts < maxAttempts
                            && e.ExpiresAt > now)
                        .ExecuteUpdateAsync(
                            setters => setters.SetProperty(e => e.SupersededAt, now),
                            ct);

                    _db.Add(entry);
                    await _db.SaveChangesAsync(ct);
                    await transaction.CommitAsync(ct);
                    return EmailCodeIssueStatus.Issued;
                }
                finally
                {
                    Detach(entry);
                }
            },
            cancellationToken);
    }

    private static bool IsTransientTransactionConflict(Exception exception, CancellationToken cancellationToken)
    {
        return !cancellationToken.IsCancellationRequested
            && EmailCodeTransactionFailures.IsDeadlockOrSerializationFailure(exception);
    }

    public Task<EmailCodeEntry?> FindLiveByEmailAsync(
        string emailHash,
        EmailCodeRowPurpose purpose,
        string? userId,
        EmailCodeLiveness liveness,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(emailHash);

        DateTime now = liveness.Now;
        int maxAttempts = liveness.MaxAttempts;
        var query = _db.Set<EmailCodeEntry>()
            .AsNoTracking()
            .Where(e => e.EmailHash == emailHash
                && e.Purpose == purpose
                && e.ConsumedAt == null
                && e.SupersededAt == null
                && e.Attempts < maxAttempts
                && e.ExpiresAt > now);
        if (userId is not null)
        {
            query = query.Where(e => e.UserId == userId);
        }

        return query
            .OrderByDescending(e => e.CreatedAt)
            .ThenByDescending(e => e.Id)
            .FirstOrDefaultAsync(cancellationToken);
    }

    public Task<EmailCodeEntry?> FindLiveByLinkTokenAsync(
        string linkTokenHash,
        EmailCodeLiveness liveness,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(linkTokenHash);

        DateTime now = liveness.Now;
        int maxAttempts = liveness.MaxAttempts;
        return _db.Set<EmailCodeEntry>()
            .AsNoTracking()
            .Where(e => e.LinkTokenHash == linkTokenHash
                && e.Purpose == EmailCodeRowPurpose.SignIn
                && e.ConsumedAt == null
                && e.SupersededAt == null
                && e.Attempts < maxAttempts
                && e.ExpiresAt > now)
            .FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<bool> TryReserveAttemptAsync(string id, EmailCodeLiveness liveness, CancellationToken cancellationToken)
    {
        DetachId(id);
        DateTime now = liveness.Now;
        int maxAttempts = liveness.MaxAttempts;
        int affected = await _db.Set<EmailCodeEntry>()
            .Where(e => e.Id == id
                && e.ConsumedAt == null
                && e.SupersededAt == null
                && e.Attempts < maxAttempts
                && e.ExpiresAt > now)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(e => e.Attempts, e => e.Attempts + 1),
                cancellationToken);
        return affected == 1;
    }

    public async Task<bool> TryReleaseAttemptAsync(string id, CancellationToken cancellationToken)
    {
        DetachId(id);
        int affected = await _db.Set<EmailCodeEntry>()
            .Where(e => e.Id == id && e.ConsumedAt == null && e.Attempts > 0)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(e => e.Attempts, e => e.Attempts - 1),
                cancellationToken);
        return affected == 1;
    }

    public async Task<bool> TryConsumeAsync(
        string id,
        EmailCodeLiveness liveness,
        bool attemptReserved,
        CancellationToken cancellationToken)
    {
        DetachId(id);
        DateTime now = liveness.Now;
        int maxAttempts = liveness.MaxAttempts;
        var query = _db.Set<EmailCodeEntry>().Where(e => e.Id == id
            && e.ConsumedAt == null
            && e.SupersededAt == null
            && e.ExpiresAt > now);
        query = attemptReserved
            ? query.Where(e => e.Attempts <= maxAttempts)
            : query.Where(e => e.Attempts < maxAttempts);

        int affected = await query.ExecuteUpdateAsync(
            setters => setters.SetProperty(e => e.ConsumedAt, now),
            cancellationToken);
        return affected == 1;
    }

    public async Task<bool> TryUnconsumeAsync(string id, CancellationToken cancellationToken)
    {
        DetachId(id);
        int affected = await _db.Set<EmailCodeEntry>()
            .Where(e => e.Id == id && e.ConsumedAt != null)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(e => e.ConsumedAt, (DateTime?)null),
                cancellationToken);
        return affected == 1;
    }

    public Task<int> CountIssuedSinceAsync(
        string emailHash,
        EmailCodeRowPurpose purpose,
        DateTime since,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(emailHash);
        return _db.Set<EmailCodeEntry>()
            .CountAsync(
                e => e.EmailHash == emailHash && e.Purpose == purpose && e.CreatedAt >= since,
                cancellationToken);
    }

    private void DetachEmail(string emailHash)
    {
        foreach (var tracked in _db.ChangeTracker.Entries<EmailCodeEntry>().ToList())
        {
            if (tracked.Entity.EmailHash == emailHash)
            {
                tracked.State = EntityState.Detached;
            }
        }
    }

    // The conditional updates bypass the change tracker. Detach a copy of the row that a caller attached to this
    // context, so a later query or SaveChanges does not see or write back its old values.
    private void DetachId(string id)
    {
        foreach (var tracked in _db.ChangeTracker.Entries<EmailCodeEntry>().ToList())
        {
            if (tracked.Entity.Id == id)
            {
                tracked.State = EntityState.Detached;
            }
        }
    }

    private void Detach(EmailCodeEntry row)
    {
        var tracked = _db.Entry(row);
        if (tracked.State != EntityState.Detached)
        {
            tracked.State = EntityState.Detached;
        }
    }
}
